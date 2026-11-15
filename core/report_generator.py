# -*- coding: utf-8 -*-
"""Формирование отчёта: текст (для консоли/приложения), JSON (для SIEM), HTML.

Отличие от курсового проекта: отчёт агрегируется по секциям с оценкой
критичности и привязкой к MITRE ATT&CK, содержит протокол этапов и метрики,
а не только сырой вывод плагинов. Секретный материал в отчёт не попадает.
"""
from __future__ import annotations

import html
import json
import os
import time

SEV_RU = {"critical": "КРИТ", "high": "ВЫС", "medium": "СРЕД", "low": "НИЗ", "info": "ИНФО"}
SEV_COLOR = {"critical": "#ff5555", "high": "#ffb86c", "medium": "#f1fa8c",
             "low": "#8be9fd", "info": "#6272a4"}
TYPE_RU = {
    "process_start": "создание процесса",
    "command": "команда bash",
    "hidden_process": "скрытый процесс (DKOM)",
    "yara_detection": "срабатывание YARA",
    "injected_region": "инъекция в память",
    "reputation": "репутация хеша",
}


def _fmt_off(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, int):
        return hex(value)
    return str(value)


class ReportGenerator:
    def __init__(self, title: str = "LMA 2.1 — отчёт анализа образа памяти"):
        self.title = title
        self.sections: dict = {}
        self.created = time.strftime("%Y-%m-%d %H:%M:%S")

    def add_section(self, name: str, payload):
        self.sections[name] = payload

    # ------------------------------------------------------------ текст
    def generate(self) -> str:
        s = self.sections
        L: list[str] = []
        add = L.append
        add("=" * 78)
        add(self.title)
        add(f"Сформирован: {self.created}")
        env = s.get("ENVIRONMENT", {})
        add(f"Образ: {s.get('IMAGE', {}).get('path', '-')} "
            f"({s.get('IMAGE', {}).get('size_human', '-')})")
        add(f"Окружение: Python {env.get('python', '-')}, "
            f"Volatility 3 {env.get('volatility3') or 'не установлен'}, "
            f"YARA {env.get('yara') or 'не установлен'}")
        add("=" * 78)

        k = s.get("KERNEL") or {}
        add("\n[1] ИДЕНТИФИКАЦИЯ ЯДРА (без инициализации фреймворка)")
        add("-" * 78)
        if k:
            add(f"Версия ядра      : {k.get('version')}")
            add(f"Баннер           : {k.get('banner', '')[:150]}")
            add(f"Смещение баннера : {_fmt_off(k.get('offset'))}")
            add(f"Найдено баннеров : {k.get('occurrences')} "
                f"(всего кандидатов: {len(k.get('candidates', []))})")
            add(f"Достоверность    : {k.get('confidence')}")
            add(f"Компилятор       : {k.get('compiler') or '-'}")
        else:
            add("не определена")

        p = s.get("PROFILE") or {}
        add("\n[2] ТАБЛИЦА СИМВОЛОВ ISF")
        add("-" * 78)
        add(f"Источник : {p.get('source', '-')}   Время: {p.get('seconds', '-')} с")
        add(f"Путь     : {p.get('path') or '-'}")
        add(f"Проверка : {p.get('detail', '-')}")

        procs = s.get("PROCESSES") or []
        add(f"\n[3] ПРОЦЕСсы (linux.pslist): {len(procs)}")
        add("-" * 78)
        add(f"{'PID':>7} {'PPID':>7} {'TID':>7}  {'COMM':<24} UID")
        for r in procs[:25]:
            add(f"{str(r.get('pid')):>7} {str(r.get('ppid')):>7} {str(r.get('tid')):>7}  "
                f"{str(r.get('name'))[:24]:<24} {r.get('uid')}")
        if len(procs) > 25:
            add(f"... ещё {len(procs) - 25} записей")

        cv = s.get("CROSS_VIEW") or {}
        add("\n[4] ПЕРЕКРЁСТНАЯ ПРОВЕРКА (Cross-View Validation)")
        add("-" * 78)
        st = cv.get("stats", {})
        add(f"pslist задач: {st.get('pslist_tasks')}   psscan задач: {st.get('psscan_tasks')}")
        add(f"Отбраковано как потоки (TID != PID)      : {st.get('rejected_threads')}")
        add(f"Отбраковано как завершённые (EXIT_STATE) : {st.get('rejected_exited')}")
        hidden = cv.get("hidden", [])
        add(f"Скрытых процессов (уточнённый критерий)  : {len(hidden)}")
        for h in hidden:
            add(f"  PID {h.get('pid')} TID {h.get('tid')} COMM {h.get('name')} "
                f"PPID {h.get('ppid')} EXIT_STATE {h.get('exit_state')} "
                f"offset {_fmt_off(h.get('offset'))}")
        naive = cv.get("naive_hidden", [])
        add(f"Наивный критерий курсовой (разность PID) : {len(naive)} срабатываний "
            f"→ ложных: {len(set(naive) - {h.get('pid') for h in hidden})}")

        bash = s.get("BASH") or {}
        add(f"\n[5] ИСТОРИЯ КОМАНД (linux.bash): {bash.get('stats', {}).get('commands', 0)} команд")
        add("-" * 78)
        for ioc in bash.get("iocs", []):
            run = f"  [ЖИВ, PID {ioc['running_pid']}]" if ioc.get("running_pid") else ""
            add(f"  [{SEV_RU.get(ioc['severity'], ioc['severity'])}] {ioc.get('timestamp', '')}")
            add(f"      $ {ioc.get('command')}")
            add(f"      → {ioc.get('reason')} | {ioc.get('rule')} | MITRE {ioc.get('mitre')}{run}")
        for sup in bash.get("suppressed", []):
            add(f"  [подавлено] {sup.get('command')}")
            add(f"      причина: {sup.get('suppressed_because')}")

        mal = s.get("INJECTIONS") or {}
        add("\n[6] ОБЛАСТИ ПАМЯТИ С ПРИЗНАКАМИ ИНЪЕКЦИИ (malfind + энтропия)")
        add("-" * 78)
        add(f"{'PID':>6} {'START':>12} {'SIZE':>9} {'H(bit/B)':>9} {'PRINT':>6}  ВЕРДИКТ")
        for r in mal.get("regions", []):
            add(f"{str(r.get('pid')):>6} {_fmt_off(r.get('start')):>12} {r.get('size'):>9} "
                f"{r.get('entropy'):>9} {r.get('printable'):>6}  {r.get('verdict')}")
            add(f"       {r.get('why')}")
            for hit in r.get("yara") or []:
                add(f"       YARA: {hit['rule']} [{SEV_RU.get(hit['severity'])}] MITRE {hit['mitre']}")
        for r in mal.get("dropped", []):
            add(f"  [отсеяно] PID {r.get('pid')} {_fmt_off(r.get('start'))} "
                f"H={r.get('entropy')} — {r.get('why')}")
        ms = mal.get("stats", {})
        if ms:
            add(f"Предфильтрация: областей {ms.get('regions_total')}, "
                f"сканировано {ms.get('regions_scanned')}, "
                f"отсеяно {ms.get('regions_dropped')}; "
                f"сокращение объёма сканирования {round(100 * ms.get('prefilter_ratio', 0), 1)} %")

        ya = s.get("YARA") or {}
        add("\n[7] СИГНАТУРНЫЕ НАХОДКИ YARA")
        add("-" * 78)
        add(f"Режим: {ya.get('mode')}   Время: {ya.get('seconds')} с   "
            f"Объём: {ya.get('bytes', 0)} Б   "
            f"Скорость: {ya.get('throughput_mibs', '-')} МиБ/с")
        for f in ya.get("findings", []):
            add(f"  [{SEV_RU.get(f['severity'])}] {f['rule']}  ({f['category']}, MITRE {f['mitre']})")
            add(f"      PID {f.get('pid', '-')}  область {f.get('region')}  "
                f"смещение {_fmt_off(f.get('offset'))}")
            add(f"      фрагмент: {f.get('snippet')}")

        rep = s.get("REPUTATION") or {}
        if rep:
            add("\n[8] РЕПУТАЦИОННАЯ ПРОВЕРКА ХЕШЕЙ")
            add("-" * 78)
            add(f"Провайдер: {rep.get('stats', {}).get('provider')}   "
                f"записей в кеше: {rep.get('stats', {}).get('cache_entries')}   "
                f"попаданий в кеш: {rep.get('stats', {}).get('cache_hits')}   "
                f"сетевых запросов: {rep.get('stats', {}).get('network_queries')}")
            for r in rep.get("results", []):
                add(f"  {r['sha256'][:32]}…  {r['verdict']:<12} "
                    f"{r.get('signature') or ''}  [{r.get('provider')}/{r.get('source')}]")

        met = s.get("METRICS") or {}
        if met:
            add("\n[9] КАЧЕСТВО ДЕТЕКТИРОВАНИЯ (сверка с эталонной разметкой стенда)")
            add("-" * 78)
            add(f"{'Детектор':<34}{'TP':>4}{'FP':>4}{'FN':>4}{'Precision':>11}{'Recall':>9}{'F1':>7}")
            for name, m in met.get("per_detector", {}).items():
                add(f"{name:<34}{m['tp']:>4}{m['fp']:>4}{m['fn']:>4}"
                    f"{m['precision']:>11}{m['recall']:>9}{m['f1']:>7}")
            o = met.get("overall", {})
            add(f"{'ИТОГО (микроусреднение)':<34}{o.get('tp', 0):>4}{o.get('fp', 0):>4}"
                f"{o.get('fn', 0):>4}{o.get('precision', 0):>11}{o.get('recall', 0):>9}{o.get('f1', 0):>7}")
            bc = met.get("benign_controls", {})
            add(f"Контрольные «чистые» двойники: {bc.get('total')}, "
                f"ложно помечено: {bc.get('flagged')} (доля {bc.get('fp_rate')})")

        tl = s.get("TIMELINE") or {}
        if tl.get("events"):
            add("\n[10] ХРОНОЛОГИЯ ИНЦИДЕНТА (timeline)")
            add("-" * 78)
            tst = tl.get("stats", {})
            add(f"Событий: {tst.get('total')}   "
                f"окно наблюдения: {tst.get('window_first') or '-'} … {tst.get('window_last') or '-'}")
            add("  " + "  ".join(f"{TYPE_RU.get(k, k)}: {v}" for k, v in tst.get("by_type", {}).items()))
            for ev in tl["events"]:
                stamp = ev.get("timestamp") or "—"
                mark = "" if ev.get("time_source") == "artifact" else "*"
                add(f"  [{SEV_RU.get(ev['severity'], ev['severity']):<5}] {stamp}{mark} "
                    f"{TYPE_RU.get(ev['type'], ev['type']):<24} "
                    f"PID {ev.get('pid', '-')} {ev.get('process') or '-'}")
                add(f"        {ev.get('detail')}")
                if ev.get("command"):
                    add(f"        $ {ev['command']}")
            add("  (* событие привязано ко времени создания процесса-владельца)")

        tim = s.get("TIMINGS") or []
        if tim:
            add("\n[11] ВРЕМЯ ВЫПОЛНЕНИЯ ЭТАПОВ (измерено)")
            add("-" * 78)
            for t in tim:
                extra = "  ".join(f"{k}={v}" for k, v in t.items() if k not in ("stage", "seconds"))
                add(f"  {t['stage']:<44}{t['seconds']:>8} с  {extra}")
            add(f"  {'ИТОГО':<44}{sum(t['seconds'] for t in tim):>8.3f} с")

        eff = s.get("EFFORT") or {}
        if eff:
            add("\n[12] ТРУДОЗАТРАТЫ ОПЕРАТОРА")
            add("-" * 78)
            add(f"Ручной режим  : {eff.get('manual_steps')} этапов, "
                f"{eff.get('manual_operator_actions')} действий оператора, "
                f"≈{eff.get('manual_minutes_estimate')} мин (оценочная модель)")
            add(f"Конвейер LMA  : 1 команда, {eff.get('pipeline_minutes_measured')} мин (измерено)")
            add(f"Сокращение времени: ×{eff.get('speedup_estimate')} (оценка)")
            add(f"Примечание: {eff.get('disclaimer')}")

        sm = s.get("SUMMARY") or {}
        add("\n" + "=" * 78)
        add("СВОДКА")
        add("-" * 78)
        for k2, v in sm.items():
            add(f"  {k2:<40}{v}")
        add("=" * 78)
        return "\n".join(L) + "\n"

    # ------------------------------------------------------------ JSON
    def to_json(self) -> str:
        return json.dumps({"title": self.title, "created": self.created,
                           "sections": self.sections}, ensure_ascii=False, indent=2, default=str)

    # ------------------------------------------------------------ HTML
    def to_html(self) -> str:
        s = self.sections
        e = html.escape

        def table(headers, rows):
            th = "".join(f"<th>{e(str(h))}</th>" for h in headers)
            trs = []
            for r in rows:
                tds = "".join(f"<td>{c}</td>" for c in r)
                trs.append(f"<tr>{tds}</tr>")
            return f"<table><thead><tr>{th}</tr></thead><tbody>{''.join(trs)}</tbody></table>"

        def badge(sev):
            return (f'<span class="b" style="background:{SEV_COLOR.get(sev, "#6272a4")}">'
                    f'{SEV_RU.get(sev, sev)}</span>')

        parts = [f"""<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">
<title>{e(self.title)}</title><style>
body{{background:#1a1b26;color:#c0caf5;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px}}
h1{{font-size:20px;margin:0 0 4px}} h2{{font-size:15px;margin:26px 0 8px;color:#7aa2f7;
border-bottom:1px solid #2f3549;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%;font-size:13px;margin:6px 0}}
th,td{{border:1px solid #2f3549;padding:5px 8px;text-align:left;vertical-align:top}}
th{{background:#24283b;color:#a9b1d6;font-weight:600}}
tr:nth-child(even) td{{background:#1f2335}}
code,.mono{{font-family:DejaVu Sans Mono,Consolas,monospace;font-size:12px}}
.b{{color:#1a1b26;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:700}}
.meta{{color:#7f849c;font-size:12px}} .k{{color:#9ece6a}} .warn{{color:#e0af68}}
.card{{background:#24283b;border:1px solid #2f3549;border-radius:6px;padding:10px 14px;margin:8px 0}}
</style></head><body>
<h1>{e(self.title)}</h1>
<div class="meta">Сформирован: {self.created} · образ: <span class="mono">{e(str(s.get('IMAGE', {}).get('path', '-')))}</span>
 · {e(str(s.get('IMAGE', {}).get('size_human', '')))}</div>"""]

        k = s.get("KERNEL") or {}
        parts.append("<h2>1. Идентификация ядра</h2>")
        parts.append(f'<div class="card">Версия: <b class="k">{e(str(k.get("version")))}</b> · '
                     f'достоверность {k.get("confidence")} · баннеров найдено {k.get("occurrences")} · '
                     f'смещение <span class="mono">{_fmt_off(k.get("offset"))}</span><br>'
                     f'<span class="mono meta">{e(str(k.get("banner", ""))[:170])}</span></div>')

        cv = s.get("CROSS_VIEW") or {}
        parts.append("<h2>2. Перекрёстная проверка процессов</h2>")
        rows = [[str(h.get("pid")), str(h.get("tid")), e(str(h.get("name"))),
                 str(h.get("ppid")), e(str(h.get("exit_state"))),
                 f'<span class="mono">{_fmt_off(h.get("offset"))}</span>']
                for h in cv.get("hidden", [])]
        parts.append(table(["PID", "TID", "COMM", "PPID", "EXIT_STATE", "task_struct"], rows)
                     if rows else '<div class="card">Скрытых процессов не обнаружено</div>')
        st = cv.get("stats", {})
        parts.append(f'<div class="meta">Отбраковано предфильтром критерия: потоков — '
                     f'{st.get("rejected_threads")}, завершённых задач — {st.get("rejected_exited")}. '
                     f'Наивный критерий курсовой дал бы {len(cv.get("naive_hidden", []))} срабатываний.</div>')

        bash = s.get("BASH") or {}
        parts.append("<h2>3. Подозрительные команды (история bash)</h2>")
        rows = [[badge(i["severity"]), f'<span class="mono">{e(str(i.get("command")))}</span>',
                 e(i["reason"]), f'<span class="mono">{e(i["rule"])}</span>',
                 f'<span class="mono">{e(i["mitre"])}</span>',
                 (f'PID {i["running_pid"]}' if i.get("running_pid") else "—")]
                for i in bash.get("iocs", [])]
        parts.append(table(["Крит.", "Команда", "Признак", "Правило", "MITRE", "Активность"], rows))
        if bash.get("suppressed"):
            rows = [[f'<span class="mono">{e(str(i.get("command")))}</span>',
                     e(i.get("suppressed_because", ""))] for i in bash["suppressed"]]
            parts.append('<div class="meta">Подавленные срабатывания (контекстный фильтр):</div>')
            parts.append(table(["Команда", "Причина подавления"], rows))

        mal = s.get("INJECTIONS") or {}
        parts.append("<h2>4. Области памяти: энтропийная предфильтрация и инъекции</h2>")
        rows = [[str(r.get("pid")), f'<span class="mono">{_fmt_off(r.get("start"))}</span>',
                 str(r.get("size")), str(r.get("entropy")), str(r.get("printable")),
                 badge(r.get("severity")), e(r.get("verdict")), e(r.get("why")),
                 "<br>".join(f'<span class="mono">{e(h["rule"])}</span>' for h in (r.get("yara") or [])) or "—"]
                for r in mal.get("regions", [])]
        parts.append(table(["PID", "Начало", "Размер, Б", "H, бит/Б", "Printable",
                            "Крит.", "Вердикт", "Обоснование", "YARA"], rows))

        ya = s.get("YARA") or {}
        parts.append("<h2>5. Сигнатурные находки YARA</h2>")
        rows = [[badge(f["severity"]), f'<span class="mono">{e(f["rule"])}</span>',
                 e(f["category"]), f'<span class="mono">{e(f["mitre"])}</span>',
                 str(f.get("pid", "—")), f'<span class="mono">{_fmt_off(f.get("offset"))}</span>',
                 f'<span class="mono">{e(str(f.get("snippet")))}</span>']
                for f in ya.get("findings", [])]
        parts.append(table(["Крит.", "Правило", "Категория", "MITRE", "PID", "Смещение", "Фрагмент"], rows))

        met = s.get("METRICS") or {}
        if met:
            parts.append("<h2>6. Качество детектирования (эталонная разметка стенда)</h2>")
            rows = [[e(n), m["tp"], m["fp"], m["fn"], m["precision"], m["recall"], m["f1"]]
                    for n, m in met["per_detector"].items()]
            o = met["overall"]
            rows.append(["<b>ИТОГО</b>", o["tp"], o["fp"], o["fn"],
                         o["precision"], o["recall"], o["f1"]])
            parts.append(table(["Детектор", "TP", "FP", "FN", "Precision", "Recall", "F1"], rows))

        tl = s.get("TIMELINE") or {}
        if tl.get("events"):
            parts.append("<h2>7. Хронология инцидента (timeline)</h2>")
            tst = tl.get("stats", {})
            parts.append(f'<div class="meta">Событий: {tst.get("total")} · '
                         f'окно наблюдения: {tst.get("window_first") or "—"} … '
                         f'{tst.get("window_last") or "—"} · '
                         + " ".join(f"{TYPE_RU.get(k, k)}: {v}" for k, v in tst.get("by_type", {}).items())
                         + '</div>')
            rows = []
            for ev in tl["events"]:
                stamp = ev.get("timestamp") or "—"
                if ev.get("time_source") != "artifact":
                    stamp += "*"
                rows.append([badge(ev.get("severity", "info")), stamp,
                             e(TYPE_RU.get(ev["type"], ev["type"])),
                             str(ev.get("pid", "—")), e(str(ev.get("process") or "—")),
                             e(str(ev.get("detail"))),
                             (f'<span class="mono">{e(ev["command"])}</span>'
                              if ev.get("command") else "—")])
            parts.append(table(["Крит.", "Время", "Событие", "PID", "Процесс", "Детали", "Команда"], rows))
            parts.append('<div class="meta">* событие привязано ко времени создания '
                         'процесса-владельца (собственного времени в дампе нет)</div>')

        tim = s.get("TIMINGS") or []
        if tim:
            parts.append("<h2>8. Время выполнения этапов</h2>")
            parts.append(table(["Этап", "Секунды"],
                               [[e(t["stage"]), t["seconds"]] for t in tim]
                               + [["<b>ИТОГО</b>", round(sum(t["seconds"] for t in tim), 3)]]))

        parts.append("<h2>Сводка</h2>")
        parts.append(table(["Показатель", "Значение"],
                           [[e(str(a)), e(str(b))] for a, b in (s.get("SUMMARY") or {}).items()]))
        parts.append("</body></html>")
        return "".join(str(p) for p in parts)

    # ------------------------------------------------------------ сохранение
    def save(self, prefix: str, formats=("txt", "json", "html")) -> dict:
        os.makedirs(os.path.dirname(os.path.abspath(prefix)) or ".", exist_ok=True)
        paths = {}
        if "txt" in formats:
            paths["txt"] = prefix + ".txt"
            with open(paths["txt"], "w", encoding="utf-8") as fh:
                fh.write(self.generate())
        if "json" in formats:
            paths["json"] = prefix + ".json"
            with open(paths["json"], "w", encoding="utf-8") as fh:
                fh.write(self.to_json())
        if "html" in formats:
            paths["html"] = prefix + ".html"
            with open(paths["html"], "w", encoding="utf-8") as fh:
                fh.write(self.to_html())
        return paths
