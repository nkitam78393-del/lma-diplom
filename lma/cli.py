# -*- coding: utf-8 -*-
"""Единая точка входа LMA 2.1: конвейер анализа образа памяти Linux.

Команды:
  analyze   — полный конвейер: ядро -> ISF -> артефакты -> cross-view ->
              энтропийный анализ областей -> YARA -> репутация -> timeline ->
              метрики -> отчёт
  compare   — сравнение критериев: наивный (курсовой) против уточнённого
  bench     — сравнение режимов YARA: весь образ против отобранных областей
  env       — сведения об окружении и проверка готовности инструментов
  profile   — подготовка таблицы символов ISF для указанной версии ядра
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from core import cross_view, malfind, metrics
from core.kernel_identifier import identify_kernel
from core.profile_manager import ProfileManager
from core.report_generator import ReportGenerator
from core.reputation import ReputationChecker
from core import timeline
from core.utils import Console, StageTimer, human_size
from core.volatility_handler import VolatilityHandler
from core.yara_scanner import YaraScanner, by_category, by_severity, dedup

VERSION = "2.1"
BANNER_TXT = f"LMA {VERSION} — Linux Memory Analyzer (дипломная версия)"


# ------------------------------------------------------------------ утилиты
def attribute(findings: list[dict], memory_map: list[dict]) -> list[dict]:
    """Атрибуция находки процесса по карте областей памяти (смещение в образе)."""
    if not memory_map:
        return findings
    for f in findings:
        off = f.get("offset")
        if off is None or f.get("pid") is not None:
            continue
        for reg in memory_map:
            if reg["offset"] <= off < reg["offset"] + reg["size"]:
                f["pid"] = reg["pid"]
                f["process"] = reg["process"]
                f["attribution"] = "memory_map"
                break
    return findings


def load_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ------------------------------------------------------------------ analyze
def cmd_analyze(args, log: Console) -> int:
    timer = StageTimer()
    rep = ReportGenerator(f"LMA {VERSION} — отчёт анализа образа памяти")
    image_size = os.path.getsize(args.file)
    rep.add_section("IMAGE", {"path": os.path.abspath(args.file),
                              "size_bytes": image_size,
                              "size_human": human_size(image_size)})
    env = VolatilityHandler.environment()
    rep.add_section("ENVIRONMENT", env)

    print(BANNER_TXT)
    log.rule("исследуемый образ")
    print(f"    {args.file}  ({human_size(image_size)})")
    print(f"    режим артефактов: {'фикстуры ' + args.fixtures if args.fixtures else 'Volatility 3'}"
          f"   режим YARA: {args.yara_mode}")

    # --- 1. ядро ------------------------------------------------------------
    log.step("1/9", "идентификация версии ядра по сырому образу")
    with timer.stage("Идентификация ядра (потоковый поиск баннеров)"):
        kernel = identify_kernel(args.file, log)
    if not kernel and not args.kernel_version:
        log.bad("версия ядра не определена; укажите --kernel-version")
        return 2
    if args.kernel_version:
        kernel = kernel or {}
        kernel["version"] = args.kernel_version
        kernel["source"] = "operator"
    rep.add_section("KERNEL", kernel)

    # --- 2. ISF -------------------------------------------------------------
    log.step("2/9", "подготовка таблицы символов ISF")
    with timer.stage("Подготовка ISF-профиля") as st:
        if args.fixtures:
            profile = {"ok": True, "source": "fixture_stand", "path": None, "seconds": 0.0,
                       "detail": "не требуется: артефакты читаются из фикстур плагинов"}
            log.info("    режим фикстур: построение слоёв трансляции не требуется")
        else:
            pm = ProfileManager(args.vol_path, args.dwarf2json, log)
            profile = pm.ensure_profile(kernel["version"])
    rep.add_section("PROFILE", profile)
    if not profile["ok"]:
        log.bad("таблица символов не подготовлена — анализ невозможен")
        return 3

    # --- 3. артефакты -------------------------------------------------------
    vol = VolatilityHandler(args.vol_path, args.file, log, fixtures=args.fixtures,
                            cache_dir=args.cache_dir)
    log.step("3/9", "извлечение артефактов (pslist, psscan, bash, malfind)")
    with timer.stage("Извлечение артефактов (4 плагина)"):
        processes = vol.get_process_list()
        psscan = vol.get_psscan()
        bash_hist = vol.get_bash_history()
        mal_rows = vol.get_malfind()
    rep.add_section("PROCESSES", processes)
    print(f"    процессов: {len(processes)}  task_struct: {len(psscan)}  "
          f"команд: {len(bash_hist)}  областей-кандидатов: {len(mal_rows)}")
    for call in vol.calls:
        print(f"      {call['plugin']:<28} {call['rows']:>5} записей  "
              f"{call['seconds']:>6} с  [{call['backend']}]")

    # --- 4. cross-view ------------------------------------------------------
    log.step("4/9", "перекрёстная проверка артефактов")
    with timer.stage("Cross-View Validation + эвристики bash"):
        hidden = cross_view.detect_hidden_processes(processes, psscan, threads_listed=False)
        naive = cross_view.detect_hidden_naive([p["pid"] for p in processes],
                                               [p["pid"] for p in psscan])
        bash = cross_view.analyze_bash_history(bash_hist, suppress=not args.no_suppress)
        bash["iocs"] = cross_view.correlate_with_processes(bash["iocs"], processes)
    cv = {**hidden, "naive_hidden": naive}
    rep.add_section("CROSS_VIEW", cv)
    rep.add_section("BASH", bash)
    truth_pids = {h["pid"] for h in hidden["hidden"]}
    print(f"    скрытых процессов (уточнённый критерий): {len(hidden['hidden'])}"
          f"{'  ' + ', '.join(map(str, sorted(truth_pids))) if truth_pids else ''}")
    print(f"    отбраковано: потоков {hidden['stats']['rejected_threads']}, "
          f"завершённых задач {hidden['stats']['rejected_exited']}")
    print(f"    наивный критерий курсовой: {len(naive)} срабатываний "
          f"(ложных {len(set(naive) - truth_pids)})")
    print(f"    подозрительных команд: {bash['stats']['iocs']} "
          f"(подавлено контекстом: {bash['stats']['suppressed']})")

    # --- 5. области памяти + энтропия --------------------------------------
    scanner = None
    if args.yara_mode != "none":
        scanner = YaraScanner(args.rules, log)
        print(f"    правил YARA загружено: {scanner.stats['rules']} "
              f"из {scanner.stats['files']} файлов")
    log.step("5/9", "энтропийная предфильтрация областей и сигнатуры по областям")
    with timer.stage("Анализ областей памяти (энтропия + YARA по областям)"):
        injections = malfind.analyze_regions(mal_rows, args.regions_dir, scanner, log)
    rep.add_section("INJECTIONS", injections)
    st = injections["stats"]
    print(f"    областей: {st['regions_total']} → отобрано {st['regions_scanned']}, "
          f"отсеяно {st['regions_dropped']}; "
          f"объём сканирования сокращён на {100 * st['prefilter_ratio']:.1f} %")
    for r in injections["regions"]:
        print(f"      PID {r['pid']} {hex(r['start']) if isinstance(r['start'], int) else r['start']} "
              f"H={r['entropy']:<6} {r['verdict']}"
              f"{'  YARA: ' + ', '.join(h['rule'] for h in r['yara']) if r.get('yara') else ''}")

    # --- 6. YARA по образу --------------------------------------------------
    log.step("6/9", f"сигнатурное сканирование (режим {args.yara_mode})")
    region_findings = [h for r in injections["regions"] for h in (r.get("yara") or [])]
    findings = list(region_findings)
    yara_info = {"mode": args.yara_mode, "seconds": 0.0, "bytes": st["bytes_scanned"],
                 "throughput_mibs": None}
    if args.yara_mode in ("full", "hybrid"):
        with timer.stage("YARA: сканирование полного образа"):
            full = scanner.scan_file(args.file)
        memory_map = load_json(args.memory_map) if args.memory_map else []
        attributed = attribute(full["findings"], memory_map)
        findings = dedup(findings + attributed)
        yara_info = {"mode": args.yara_mode, "seconds": full["seconds"],
                     "bytes": full["bytes"], "throughput_mibs": full["throughput_mibs"],
                     "full_image_findings": len(full["findings"]),
                     "attributed": sum(1 for f in attributed if f.get("attribution"))}
        print(f"    полный образ: {full['seconds']} с, "
              f"{full['throughput_mibs']} МиБ/с, находок {len(full['findings'])}, "
              f"атрибутировано процессам {yara_info['attributed']}")
    else:
        findings = dedup(findings)
    yara_info["findings"] = findings
    rep.add_section("YARA", yara_info)
    print(f"    итого находок: {len(findings)}  по категориям: {by_category(findings)}")
    print(f"    по критичности: {by_severity(findings)}")

    # --- 7. репутация -------------------------------------------------------
    log.step("7/9", "репутационная проверка хешей извлечённых объектов")
    rep_data = {}
    if args.reputation != "off":
        with timer.stage("Репутационная проверка хешей (кеш SQLite)"):
            checker = ReputationChecker(args.mb_cache, provider=args.reputation,
                                        local_list=args.reference_hashes, logger=log)
            digests = [r["sha256"] for r in injections["regions"] if r.get("sha256")]
            results = checker.check_many(digests)
            rep_data = {"results": results, "stats": checker.stats()}
        rep.add_section("REPUTATION", rep_data)
        for r in rep_data["results"]:
            print(f"    {r['sha256'][:24]}…  {r['verdict']:<11} "
                  f"{r.get('signature') or '':<24} [{r.get('provider')}/{r.get('source')}]")
    else:
        log.info("    отключена (--reputation off)")

    # --- 8. хронология инцидента ---------------------------------------------
    log.step("8/9", "построение хронологии инцидента (timeline)")
    with timer.stage("Построение хронологии инцидента (timeline)"):
        tl = timeline.build_timeline(processes, bash_hist, hidden, bash["iocs"],
                                     findings, injections["regions"], rep_data)
    rep.add_section("TIMELINE", tl)
    tst = tl["stats"]
    print(f"    событий: {tst['total']}  "
          f"по типам: {', '.join(f'{timeline.TYPE_RU.get(k, k)}: {v}' for k, v in tst['by_type'].items())}")
    if tst.get("window_first"):
        print(f"    окно наблюдения: {tst['window_first']} … {tst['window_last']}")
    critical = [e for e in tl["events"] if e["severity"] == "critical"]
    print(f"    критических событий: {len(critical)}")
    for e in critical[:5]:
        mark = "[СКРЫТЫЙ] " if e["type"] == "hidden_process" else ""
        print(f"      {e.get('timestamp') or '—'}  {mark}{e.get('process') or '-'}: {e['detail'][:80]}")

    # --- 9. метрики и отчёт -------------------------------------------------
    log.step("9/9", "оценка качества детектирования и формирование отчёта")
    if args.ground_truth:
        truth = load_json(args.ground_truth)
        detections = {
            "hidden_pids": [h["pid"] for h in hidden["hidden"]],
            "iocs": bash["iocs"],
            "yara": findings,
            "regions": [{"pid": r["pid"], "start": r["start"]}
                        for r in injections["regions"]
                        if r["verdict"] in ("packed_or_encrypted", "probable_injected_code")],
        }
        with timer.stage("Сверка с эталонной разметкой (метрики)"):
            met = metrics.evaluate(detections, truth)
        rep.add_section("METRICS", met)
        print(f"    {'детектор':<34}{'TP':>4}{'FP':>4}{'FN':>4}{'P':>8}{'R':>8}{'F1':>8}")
        for name, m in met["per_detector"].items():
            print(f"    {name:<34}{m['tp']:>4}{m['fp']:>4}{m['fn']:>4}"
                  f"{m['precision']:>8}{m['recall']:>8}{m['f1']:>8}")
        o = met["overall"]
        print(f"    {'ИТОГО':<34}{o['tp']:>4}{o['fp']:>4}{o['fn']:>4}"
              f"{o['precision']:>8}{o['recall']:>8}{o['f1']:>8}")
        bc = met["benign_controls"]
        print(f"    контрольные «чистые» двойники: {bc['total']}, "
              f"ложно помечено: {bc['flagged']}")

    rep.add_section("TIMINGS", timer.as_list())
    total_seconds = sum(t["seconds"] for t in timer.as_list())
    rep.add_section("EFFORT", metrics.effort_comparison(total_seconds))
    rep.add_section("PLUGIN_CALLS", vol.calls)
    rep.add_section("SUMMARY", {
        "Версия ядра": kernel.get("version"),
        "Процессов / task_struct": f"{len(processes)} / {len(psscan)}",
        "Скрытых процессов (DKOM)": len(hidden["hidden"]),
        "Подозрительных команд": bash["stats"]["iocs"],
        "Подавлено контекстным фильтром": bash["stats"]["suppressed"],
        "Областей с признаками инъекции": sum(
            1 for r in injections["regions"]
            if r["verdict"] in ("packed_or_encrypted", "probable_injected_code")),
        "Находок YARA": len(findings),
        "Категории находок": ", ".join(f"{k}: {v}" for k, v in by_category(findings).items()),
        "Время анализа, с": round(total_seconds, 3),
    })

    paths = rep.save(args.output, formats=tuple(args.formats.split(",")))
    log.rule("готово")
    for kind, path in paths.items():
        print(f"    {kind.upper():<5} {path}")
    print(f"    суммарное время конвейера: {total_seconds:.3f} с")
    return 0


# ------------------------------------------------------------------ compare
def cmd_compare(args, log: Console) -> int:
    vol = VolatilityHandler(args.vol_path, args.file or "", log, fixtures=args.fixtures)
    processes, psscan = vol.get_process_list(), vol.get_psscan()
    bash_hist = vol.get_bash_history()
    truth = load_json(args.ground_truth) if args.ground_truth else None

    print(BANNER_TXT)
    log.rule("сравнение критериев Cross-View Validation")
    naive = cross_view.detect_hidden_naive([p["pid"] for p in processes],
                                           [p["pid"] for p in psscan])
    refined = cross_view.detect_hidden_processes(processes, psscan)
    rows = [("Курсовой проект: разность множеств PID", len(naive)),
            ("Диплом: TID == PID и EXIT_STATE = TASK_RUNNING", len(refined["hidden"]))]
    print(f"{'Критерий':<52}{'Срабатываний':>14}")
    for name, cnt in rows:
        print(f"{name:<52}{cnt:>14}")
    print(f"\nОтбраковано уточнённым критерием:")
    print(f"  потоки (TID != PID)             : {refined['stats']['rejected_threads']}")
    print(f"  завершённые (EXIT_ZOMBIE/DEAD)  : {refined['stats']['rejected_exited']}")
    print(f"  присутствуют в pslist           : {refined['rejected']['known']}")

    if truth:
        exp = {x["pid"] for x in truth["hidden_processes"]}
        m_naive = metrics.prf(len(set(naive) & exp), len(set(naive) - exp), len(exp - set(naive)))
        got = {h["pid"] for h in refined["hidden"]}
        m_ref = metrics.prf(len(got & exp), len(got - exp), len(exp - got))
        print(f"\n{'Критерий':<20}{'TP':>4}{'FP':>4}{'FN':>4}{'Precision':>11}{'Recall':>9}{'F1':>7}")
        for name, m in (("наивный (курсовой)", m_naive), ("уточнённый (диплом)", m_ref)):
            print(f"{name:<20}{m['tp']:>4}{m['fp']:>4}{m['fn']:>4}"
                  f"{m['precision']:>11}{m['recall']:>9}{m['f1']:>7}")

    log.rule("контекстное подавление ложных срабатываний эвристик bash")
    raw = cross_view.analyze_bash_history(bash_hist, suppress=False)
    sup = cross_view.analyze_bash_history(bash_hist, suppress=True)
    print(f"{'Режим':<40}{'Срабатываний':>14}")
    print(f"{'Без контекстного фильтра (курсовой)':<40}{len(raw['iocs']):>14}")
    print(f"{'С контекстным фильтром (диплом)':<40}{len(sup['iocs']):>14}")
    if truth:
        exp_cmd = {metrics.normalize_command(x["command"]) for x in truth["malicious_commands"]}
        for name, res in (("без фильтра", raw), ("с фильтром", sup)):
            got = {metrics.normalize_command(i["command"]) for i in res["iocs"]}
            m = metrics.prf(len(got & exp_cmd), len(got - exp_cmd), len(exp_cmd - got))
            print(f"  {name:<14} precision={m['precision']}  recall={m['recall']}  F1={m['f1']}")
    print("\nПодавленные срабатывания:")
    for s in sup["suppressed"]:
        print(f"  $ {s['command']}")
        print(f"    → {s['suppressed_because']}")
    return 0


# ------------------------------------------------------------------ bench
def cmd_bench(args, log: Console) -> int:
    scanner = YaraScanner(args.rules, log)
    vol = VolatilityHandler(args.vol_path, args.file, log, fixtures=args.fixtures)
    mal_rows = vol.get_malfind()
    truth = load_json(args.ground_truth) if args.ground_truth else None

    print(BANNER_TXT)
    log.rule("сравнение режимов сигнатурного сканирования")
    injections = malfind.analyze_regions(mal_rows, args.regions_dir, scanner, log)
    region_findings = dedup([h for r in injections["regions"] for h in (r.get("yara") or [])])
    reg_seconds = sum(r.get("seconds", 0) for r in [])  # время учтено внутри сканера
    full = scanner.scan_file(args.file)
    memory_map = load_json(args.memory_map) if args.memory_map else []
    full_findings = attribute(full["findings"], memory_map)

    print(f"{'Режим':<34}{'Объём, Б':>14}{'Время, с':>11}{'Находок':>10}")
    print(f"{'Весь образ (full)':<34}{full['bytes']:>14}{full['seconds']:>11}"
          f"{len(full_findings):>10}")
    print(f"{'Отобранные области (regions)':<34}{injections['stats']['bytes_scanned']:>14}"
          f"{scanner.stats.get('last_seconds', 0):>11}{len(region_findings):>10}")
    ratio = full["bytes"] / max(1, injections["stats"]["bytes_scanned"])
    print(f"\nСокращение объёма сканирования: ×{ratio:.1f}")
    if truth:
        exp = {(x["rule"], x["pid"]) for x in truth["yara_findings"]}
        for name, fnd in (("full", full_findings), ("regions", region_findings)):
            got = {(f["rule"], f.get("pid")) for f in fnd}
            m = metrics.prf(len(got & exp), len(got - exp), len(exp - got))
            print(f"  {name:<9} полнота(recall)={m['recall']}  точность(precision)={m['precision']}"
                  f"  пропущено={m['fn']}")
        print("\nВывод: режим regions быстрее, но теряет находки категории secrets,")
        print("которые лежат в областях без прав на исполнение. Обоснован гибрид:")
        print("malware/injection — по отобранным областям, secrets — по всему образу.")
    return 0


# ------------------------------------------------------------------ env / profile
def cmd_env(args, log: Console) -> int:
    env = VolatilityHandler.environment()
    print(BANNER_TXT)
    log.rule("окружение")
    for k, v in env.items():
        print(f"    {k:<18}{v}")
    try:
        s = YaraScanner(args.rules, log)
        print(f"    правил YARA       {s.stats['rules']} ({', '.join(os.path.basename(f) for f in s.rule_files)})")
        cats = {}
        for name, meta in s.meta.items():
            cats.setdefault(meta["category"], []).append(name)
        for cat, names in cats.items():
            print(f"      {cat:<12}{len(names)} правил: {', '.join(sorted(names))}")
    except Exception as exc:                        # noqa: BLE001
        log.bad(f"YARA: {exc}")
    return 0


def cmd_profile(args, log: Console) -> int:
    print(BANNER_TXT)
    log.rule("каскадная подготовка таблицы символов ISF")
    pm = ProfileManager(args.vol_path, args.dwarf2json, log)
    print(f"    хранилище символов: {pm.symbols_dir}")
    print(f"    конвертер        : {args.dwarf2json}")
    res = pm.ensure_profile(args.kernel_version)
    print(f"    результат        : {res}")
    return 0 if res["ok"] else 1


# ------------------------------------------------------------------ парсер
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="lma.py", description=BANNER_TXT,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    sub = ap.add_subparsers(dest="command")

    def common(p, need_file=True):
        p.add_argument("-f", "--file", required=need_file, help="образ памяти (.raw/.lime)")
        p.add_argument("--fixtures", default=None,
                       help="каталог фикстур плагинов (лабораторный стенд)")
        p.add_argument("--vol-path", default=os.path.expanduser("~/volatility3"))
        p.add_argument("--dwarf2json", default=os.path.expanduser("~/dwarf2json-linux-amd64"))
        p.add_argument("--rules", default=os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "rules"))
        p.add_argument("--regions-dir", default=None, help="каталог выгруженных областей (malfind --dump)")
        p.add_argument("--memory-map", default=None, help="карта областей для атрибуции находок")
        p.add_argument("--ground-truth", default=None, help="эталонная разметка стенда")

    a = sub.add_parser("analyze", help="полный конвейер анализа")
    common(a)
    a.add_argument("--kernel-version", default=None, help="резервный ручной ввод версии ядра")
    a.add_argument("--yara-mode", choices=("hybrid", "full", "regions", "none"), default="hybrid")
    a.add_argument("--no-suppress", action="store_true", help="отключить контекстное подавление")
    a.add_argument("--reputation", choices=("off", "local", "malwarebazaar"), default="off")
    a.add_argument("--reference-hashes", default=None, help="локальный справочник хешей")
    a.add_argument("--mb-cache", default="build/mb_cache.sqlite3")
    a.add_argument("--cache-dir", default=None, help="кеш результатов плагинов")
    a.add_argument("-o", "--output", default="build/report")
    a.add_argument("--formats", default="txt,json,html")

    c = sub.add_parser("compare", help="наивный и уточнённый критерии cross-view")
    common(c, need_file=False)

    b = sub.add_parser("bench", help="сравнение режимов YARA")
    common(b)

    e = sub.add_parser("env", help="сведения об окружении")
    e.add_argument("--rules", default=os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "rules"))

    pr = sub.add_parser("profile", help="подготовка ISF для версии ядра")
    pr.add_argument("--kernel-version", required=True)
    pr.add_argument("--vol-path", default=os.path.expanduser("~/volatility3"))
    pr.add_argument("--dwarf2json", default=os.path.expanduser("~/dwarf2json-linux-amd64"))

    # совместимость с LMA 1.x: запуск без подкоманды = analyze
    ap.add_argument("-f", "--file", default=None, help=argparse.SUPPRESS)
    return ap


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help")):
        argv.insert(0, "analyze")
    args = parser.parse_args(argv)
    log = Console()
    handlers = {"analyze": cmd_analyze, "compare": cmd_compare, "bench": cmd_bench,
                "env": cmd_env, "profile": cmd_profile}
    if not args.command:
        parser.print_help()
        return 0
    try:
        return handlers[args.command](args, log)
    except FileNotFoundError as exc:
        log.bad(str(exc))
        return 2
    except RuntimeError as exc:
        log.bad(str(exc))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
