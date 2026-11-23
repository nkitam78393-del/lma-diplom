# -*- coding: utf-8 -*-
"""Хронология инцидента (timeline) — новая функциональность дипломной версии.

Курсовая версия выдавала артефакты разрозненными списками без привязки ко
времени. Для расследования инцидента важно, КОГДА появился процесс, какие
команды выполнялись ДО срабатывания сигнатур и как события связаны между
собой. Модуль объединяет источники конвейера в единую упорядоченную
последовательность событий:

  process_start    — создание процесса (linux.pslist, CREATION TIME);
  command          — команда из истории bash (linux.bash, CommandTime);
  hidden_process   — скрытый процесс, выявленный Cross-View Validation (DKOM);
  yara_detection   — срабатывание сигнатуры YARA;
  injected_region  — область памяти с признаками инъекции (malfind + энтропия);
  reputation       — вердикт репутационной проверки по хешу области.

События артефактов имеют собственное время из образа (time_source =
"artifact"). У обнаружений собственного времени в дампе нет, поэтому они
привязываются ко времени создания процесса-владельца (time_source =
"anchored_to_process"); события без известного владельца сортируются в конец
хронологии. Порядок сортировки: время -> тип события -> критичность.
"""
from __future__ import annotations

from datetime import datetime

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

TYPE_RU = {
    "process_start": "создание процесса",
    "command": "команда bash",
    "hidden_process": "скрытый процесс (DKOM)",
    "yara_detection": "срабатывание YARA",
    "injected_region": "инъекция в память",
    "reputation": "репутация хеша",
}


def _parse_ts(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _created_map(processes: list[dict]) -> dict:
    out = {}
    for p in processes or []:
        ts = _parse_ts(p.get("created"))
        if ts is not None and p.get("pid") is not None:
            out[p["pid"]] = ts
    return out


def build_timeline(processes: list[dict], bash_hist: list[dict],
                   hidden: dict, iocs: list[dict], yara_findings: list[dict],
                   regions: list[dict], reputation: dict | None = None) -> dict:
    """Сборка единой хронологии инцидента из результатов этапов конвейера."""
    events: list[dict] = []
    created = _created_map(processes)
    hidden_pids = {h.get("pid") for h in (hidden or {}).get("hidden", [])}
    ioc_by_cmd = {(i.get("pid"), i.get("command")): i for i in iocs or []}

    for p in processes or []:
        ts = created.get(p.get("pid"))
        if ts is None:
            continue
        pid = p.get("pid")
        is_hidden = pid in hidden_pids
        events.append({
            "timestamp": ts.isoformat(), "time_source": "artifact",
            "type": "process_start", "severity": "critical" if is_hidden else "info",
            "pid": pid, "process": p.get("name"),
            "detail": f"PPID {p.get('ppid')}, UID {p.get('uid')}"
                      + (" — процесс скрыт из списка задач (DKOM)" if is_hidden else ""),
        })

    for r in bash_hist or []:
        ts = _parse_ts(r.get("timestamp"))
        if ts is None:
            continue
        cmd = r.get("command", "")
        ioc = ioc_by_cmd.get((r.get("pid"), cmd))
        events.append({
            "timestamp": ts.isoformat(), "time_source": "artifact",
            "type": "command", "severity": (ioc or {}).get("severity", "info"),
            "pid": r.get("pid"), "process": r.get("process"),
            "detail": ("подозрительная команда: " + (ioc or {}).get("reason", "")
                       if ioc else "команда из истории bash"),
            "command": cmd,
        })

    for h in (hidden or {}).get("hidden", []):
        ts = created.get(h.get("pid"))
        events.append({
            "timestamp": ts.isoformat() if ts else None,
            "time_source": "anchored_to_process" if ts else "none",
            "type": "hidden_process", "severity": "critical",
            "pid": h.get("pid"), "process": h.get("name"),
            "detail": f"TID {h.get('tid')} == PID, EXIT_STATE {h.get('exit_state')}, "
                      f"задача отсутствует в pslist, task_struct {_hex(h.get('offset'))}",
        })

    for f in yara_findings or []:
        ts = created.get(f.get("pid"))
        events.append({
            "timestamp": ts.isoformat() if ts else None,
            "time_source": "anchored_to_process" if ts else "none",
            "type": "yara_detection", "severity": f.get("severity", "medium"),
            "pid": f.get("pid"), "process": f.get("process"),
            "detail": f"{f['rule']} (MITRE {f.get('mitre', '-')}), "
                      f"смещение {_hex(f.get('offset'))}",
        })

    for r in regions or []:
        if r.get("verdict") not in ("packed_or_encrypted", "probable_injected_code"):
            continue
        ts = created.get(r.get("pid"))
        events.append({
            "timestamp": ts.isoformat() if ts else None,
            "time_source": "anchored_to_process" if ts else "none",
            "type": "injected_region",
            "severity": r.get("severity", "critical"),
            "pid": r.get("pid"), "process": r.get("process"),
            "detail": f"{r.get('verdict')}: {r.get('why')}",
        })

    for res in (reputation or {}).get("results", []):
        reg = next((r for r in regions or [] if r.get("sha256") == res.get("sha256")), None)
        pid = reg.get("pid") if reg else None
        ts = created.get(pid)
        if res.get("verdict") in ("unknown", "clean") and not res.get("signature"):
            continue
        events.append({
            "timestamp": ts.isoformat() if ts else None,
            "time_source": "anchored_to_process" if ts else "none",
            "type": "reputation", "severity": "critical" if res.get("verdict") == "malicious" else "high",
            "pid": pid, "process": (reg or {}).get("process"),
            "detail": f"хеш {str(res.get('sha256'))[:16]}… — {res.get('verdict')} "
                      f"({res.get('signature') or 'без подписи'}, {res.get('provider')})",
        })

    events.sort(key=lambda e: (
        e.get("timestamp") is None,
        e.get("timestamp") or "",
        SEV_ORDER.get(e.get("severity"), 9),
        TYPE_RU.get(e.get("type"), ""),
    ))

    stamps = sorted(e["timestamp"] for e in events if e.get("timestamp"))
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for e in events:
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1
        by_severity[e["severity"]] = by_severity.get(e["severity"], 0) + 1
    return {
        "events": events,
        "stats": {
            "total": len(events),
            "by_type": by_type,
            "by_severity": by_severity,
            "window_first": stamps[0] if stamps else None,
            "window_last": stamps[-1] if stamps else None,
        },
    }


def _hex(value) -> str:
    return hex(value) if isinstance(value, int) else str(value or "-")
