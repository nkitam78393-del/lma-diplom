# -*- coding: utf-8 -*-
"""Перекрёстная проверка артефактов (Cross-View Validation) и анализ истории bash.

Главное отличие от LMA 1.x — уточнённый критерий сокрытия процесса.
Наивное сравнение множеств PID (psscan \\ pslist), реализованное в курсовом
проекте, даёт ложные срабатывания по двум системным причинам:

  1) linux.pslist по умолчанию перечисляет только лидеров групп потоков
     (TID == PID), а linux.psscan сканирует ВСЕ структуры task_struct, включая
     потоки. Каждый поток легитимного многопоточного процесса попадал в
     «скрытые»;
  2) в psscan остаются завершённые задачи (EXIT_STATE = EXIT_ZOMBIE / EXIT_DEAD /
     EXIT_TRACE), которых уже нет в списке живых задач.

Уточнённый критерий: кандидат считается скрытым, только если он является
лидером группы (TID == PID), находится в состоянии TASK_RUNNING и отсутствует
в pslist. Дополнительно поддерживается режим сравнения с pslist --threads.

Второе отличие — контекстное подавление ложных срабатываний эвристик bash:
легитимные административные команды (загрузка пакетов из доверенных
репозиториев, chmod +x в каталоге сборки) не выбрасываются молча, а помечаются
как подавленные с указанием причины — для аудита и для расчёта точности.
"""
from __future__ import annotations

import re

# id, регулярное выражение, причина, критичность, техника MITRE ATT&CK
SUSPICIOUS_PATTERNS = [
    ("BASH_RShell_Netcat", r"\bnc\b[^\n]*\s-e\s*(/bin/)?(ba)?sh",
     "обратная оболочка через netcat -e", "critical", "T1059.004"),
    ("BASH_RShell_DevTcp", r"/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+",
     "обратная оболочка через /dev/tcp", "critical", "T1059.004"),
    ("BASH_RShell_Interactive", r"bash\s+-i\s+>&",
     "интерактивная обратная оболочка", "critical", "T1059.004"),
    ("BASH_Download_Exec", r"(wget|curl)\b[^\n]*\|\s*(sudo\s+)?(ba)?sh",
     "загрузка и немедленное исполнение кода из сети", "high", "T1105"),
    ("BASH_Deobfuscate", r"base64\s+(-d|--decode)\b[^\n]*\|\s*(ba)?sh",
     "деобфускация и исполнение полезной нагрузки", "high", "T1140"),
    ("BASH_Base64", r"base64\s+(-d|--decode)\b",
     "декодирование данных base64", "medium", "T1140"),
    ("BASH_Download", r"\b(wget|curl)\s+",
     "загрузка файла из сети", "medium", "T1105"),
    ("BASH_ChmodExec", r"chmod\s+\+x\b",
     "выдача прав на исполнение", "low", "T1222.002"),
    ("BASH_Module_Load", r"\b(insmod|modprobe)\s+",
     "загрузка модуля ядра", "high", "T1547.006"),
    ("BASH_AntiForensics", r"history\s+-c\b|unset\s+HISTFILE|shred\s+.*bash_history",
     "сокрытие следов активности (очистка истории)", "high", "T1070.003"),
    ("BASH_Persistence", r"(crontab\s+-|>>\s*/etc/cron|systemctl\s+enable\s+)",
     "закрепление в системе (автозапуск)", "medium", "T1053.003"),
]

# доверенные источники загрузки пакетов и обновлений
TRUSTED_HOSTS = (
    "archive.ubuntu.com", "security.ubuntu.com", "ddebs.ubuntu.com",
    "ppa.launchpad.net", "deb.debian.org", "pypi.org", "files.pythonhosted.org",
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
)
BUILD_CONTEXT = re.compile(r"(\./|/build/|/src/|configure|Makefile|\.sh\b|venv|node_modules)")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ------------------------------------------------------------ процессы
def detect_hidden_naive(pslist_pids, psscan_pids) -> list:
    """Критерий курсового проекта: разность множеств PID (для сравнения)."""
    return sorted({p for p in psscan_pids if p is not None}
                  - {p for p in pslist_pids if p is not None})


def detect_hidden_processes(pslist: list[dict], psscan: list[dict],
                            threads_listed: bool = False) -> dict:
    """Уточнённый критерий DKOM-сокрытия с разбором причин отбраковки.

    Возвращает {"hidden": [...], "rejected": {...}, "stats": {...}}.
    """
    live_pids = {p["pid"] for p in pslist if p.get("pid") is not None}
    live_tids = {(p["pid"], p.get("tid", p["pid"])) for p in pslist}
    hidden, rejected = [], {"thread": [], "exited": [], "known": 0}

    for row in psscan:
        pid, tid = row.get("pid"), row.get("tid", row.get("pid"))
        if pid is None:
            continue
        present = (pid, tid) in live_tids if threads_listed else pid in live_pids
        if present and tid == pid:
            rejected["known"] += 1
            continue
        if tid != pid and not threads_listed:
            rejected["thread"].append(row)
            continue
        if str(row.get("exit_state", "TASK_RUNNING")) != "TASK_RUNNING":
            rejected["exited"].append(row)
            continue
        if present:
            rejected["known"] += 1
            continue
        hidden.append(row)

    hidden.sort(key=lambda r: (r.get("pid") or 0))
    return {
        "hidden": hidden,
        "rejected": rejected,
        "stats": {
            "pslist_tasks": len(pslist),
            "psscan_tasks": len(psscan),
            "hidden": len(hidden),
            "rejected_threads": len(rejected["thread"]),
            "rejected_exited": len(rejected["exited"]),
        },
    }


# ------------------------------------------------------------ история bash
def _suppression_reason(cmd: str, rule_id: str) -> str | None:
    """Контекстное подавление заведомо легитимных административных действий."""
    low = cmd.lower()
    if rule_id in ("BASH_Download", "BASH_Download_Exec"):
        hosts = re.findall(r"https?://([^/\s]+)", low)
        if hosts and all(any(h == t or h.endswith("." + t) for t in TRUSTED_HOSTS) for h in hosts):
            if rule_id == "BASH_Download":
                return "загрузка из доверенного репозитория (" + ", ".join(hosts) + ")"
    if rule_id == "BASH_ChmodExec" and BUILD_CONTEXT.search(cmd):
        return "выдача прав в контексте сборки/скрипта проекта"
    if rule_id == "BASH_Module_Load" and re.search(r"\bmodprobe\s+(-r|--remove)\b", low):
        return "выгрузка модуля, а не загрузка"
    return None


def analyze_bash_history(commands: list[dict], suppress: bool = True) -> dict:
    """Эвристический разбор истории команд.

    Возвращает {"iocs": [...], "suppressed": [...], "stats": {...}}.
    """
    iocs, suppressed = [], []
    for cmd in commands:
        text = cmd.get("command") or ""
        if not text.strip():
            continue
        matched = []
        for rule_id, pattern, reason, severity, mitre in SUSPICIOUS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matched.append((rule_id, reason, severity, mitre))
        if not matched:
            continue
        # наиболее значимое срабатывание определяет итоговую оценку команды
        matched.sort(key=lambda m: SEV_ORDER[m[2]])
        rule_id, reason, severity, mitre = matched[0]
        record = {**cmd, "rule": rule_id, "reason": reason, "severity": severity,
                  "mitre": mitre, "all_rules": [m[0] for m in matched]}
        why = _suppression_reason(text, rule_id) if suppress else None
        if why:
            suppressed.append({**record, "suppressed_because": why})
        else:
            iocs.append(record)
    iocs.sort(key=lambda r: (SEV_ORDER.get(r["severity"], 9), str(r.get("timestamp"))))
    return {"iocs": iocs, "suppressed": suppressed,
            "stats": {"commands": len(commands), "iocs": len(iocs),
                      "suppressed": len(suppressed)}}


def correlate_with_processes(iocs: list[dict], processes: list[dict]) -> list[dict]:
    """Связывает команду с живым процессом — признак сохраняющейся активности."""
    running: dict[str, int] = {}
    for p in processes:
        if p.get("name"):
            running.setdefault(p["name"], p["pid"])
    for ioc in iocs:
        for token in re.findall(r"[A-Za-z0-9_.\-]{3,}", ioc.get("command", "")):
            base = token.rsplit("/", 1)[-1]
            if base in running and base not in ("sh", "bash", "sudo"):
                ioc["running_pid"] = running[base]
                ioc["running_name"] = base
                break
    return iocs


def summarize(hidden: dict, bash: dict) -> dict:
    return {
        "hidden_processes": hidden["stats"]["hidden"],
        "rejected_threads": hidden["stats"]["rejected_threads"],
        "rejected_exited": hidden["stats"]["rejected_exited"],
        "suspicious_commands": bash["stats"]["iocs"],
        "suppressed_commands": bash["stats"]["suppressed"],
        "critical": sum(1 for i in bash["iocs"] if i["severity"] == "critical"),
    }
