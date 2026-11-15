# -*- coding: utf-8 -*-
"""Количественная оценка эффективности (материал главы 3).

Две группы метрик:
  1) качество детектирования — сопоставление находок с эталонной разметкой
     лабораторного стенда (ground truth): TP/FP/FN, полнота (recall),
     точность (precision), F1-мера — по каждому детектору и в целом;
  2) трудозатраты — число обязательных действий оператора и время этапов.
     Время конвейера измеряется фактически; время ручного режима задаётся
     явной моделью трудозатрат (параметры и источник помечены как оценка).
"""
from __future__ import annotations

import json


def prf(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3)}


def _set_metrics(detected: set, expected: set) -> dict:
    tp = len(detected & expected)
    return prf(tp, len(detected - expected), len(expected - detected))


def normalize_command(cmd: str) -> str:
    return " ".join((cmd or "").split()).strip()


def evaluate(detections: dict, truth: dict) -> dict:
    """detections: скрытые PID, команды, находки YARA, области инъекций.

    truth: эталонная разметка стенда с теми же сущностями.
    """
    per_detector = {}

    exp_hidden = {int(x["pid"]) for x in truth.get("hidden_processes", [])}
    got_hidden = {int(p) for p in detections.get("hidden_pids", [])}
    per_detector["Скрытые процессы (DKOM)"] = _set_metrics(got_hidden, exp_hidden)

    exp_cmd = {normalize_command(x["command"]) for x in truth.get("malicious_commands", [])}
    got_cmd = {normalize_command(x["command"]) for x in detections.get("iocs", [])}
    per_detector["Эвристики истории bash"] = _set_metrics(got_cmd, exp_cmd)

    def ykey(x):
        pid = x.get("pid")
        return (x["rule"], int(pid) if pid is not None else -1)

    exp_yara = {ykey(x) for x in truth.get("yara_findings", [])}
    got_yara = {ykey(x) for x in detections.get("yara", [])}
    per_detector["Сигнатуры YARA"] = _set_metrics(got_yara, exp_yara)

    exp_reg = {(int(x["pid"]), int(x["start"])) for x in truth.get("injected_regions", [])}
    got_reg = {(int(x["pid"]), int(x["start"])) for x in detections.get("regions", [])}
    per_detector["Инъекции (malfind + энтропия)"] = _set_metrics(got_reg, exp_reg)

    tp = sum(m["tp"] for m in per_detector.values())
    fp = sum(m["fp"] for m in per_detector.values())
    fn = sum(m["fn"] for m in per_detector.values())

    # ложные срабатывания на «чистых» двойниках — отдельный показатель.
    # Правило-контроль с известным диапазоном офсетов в образе считается
    # сработавшим, только если находка YARA того же правила попала в диапазон.
    # Сопоставление по (правило, pid) здесь некорректно: у двойников и настоящих
    # секретов один процесс-владелец кучи, ключ (rule, pid) совпадает.
    benign = truth.get("benign_lookalikes", [])
    benign_flagged = 0
    flagged_notes = []
    benign_cmd_set = {normalize_command(x["command"]) for x in benign if x.get("command")}
    for x in benign:
        if x.get("command") and normalize_command(x["command"]) in (benign_cmd_set & got_cmd):
            benign_flagged += 1
            flagged_notes.append(x.get("note", x["command"]))
    image_findings = [f for f in detections.get("yara", [])
                      if f.get("region") == "full_image"]
    for x in benign:
        if not x.get("rule"):
            continue
        if x.get("offset") is not None and x.get("end") is not None:
            hit = any(f["rule"] == x["rule"]
                      and x["offset"] <= f.get("offset", -1) < x["end"]
                      for f in image_findings)
        else:
            hit = ykey(x) in got_yara
        if hit:
            benign_flagged += 1
            flagged_notes.append(x.get("note", x["rule"]))
    benign_regs = {(int(x["pid"]), int(x["start"])) for x in benign
                   if x.get("start") is not None and not x.get("rule")}
    for pid_start in benign_regs & got_reg:
        benign_flagged += 1
        flagged_notes.append(f"RWX-область pid={pid_start[0]} start={hex(pid_start[1])}")

    return {
        "per_detector": per_detector,
        "overall": prf(tp, fp, fn),
        "benign_controls": {"total": len(benign), "flagged": benign_flagged,
                            "fp_rate": round(benign_flagged / len(benign), 3) if benign else 0.0,
                            "flagged_notes": flagged_notes},
    }


# модель трудозатрат ручного режима: значения — оценка по опыту выполнения
# соответствующих шагов при подготовке курсового проекта, подлежат уточнению
# прямым хронометражем на стенде (помечено в отчёте как estimate)
MANUAL_MODEL = [
    {"step": "Определение версии ядра (banners, ручной разбор вывода)", "minutes": 4.0,
     "source": "оценка по опыту курсового проекта"},
    {"step": "Подключение ddebs, подбор и загрузка пакета *-dbgsym (vmlinux)", "minutes": 12.0,
     "source": "оценка: зависит от канала связи"},
    {"step": "Генерация ISF через dwarf2json и укладка в symbols/linux", "minutes": 5.0,
     "source": "оценка: запуск + проверка результата"},
    {"step": "Запуск плагинов и сохранение вывода", "minutes": 3.0,
     "source": "оценка: 4 плагина, ручной ввод команд"},
    {"step": "Ручное сопоставление pslist/psscan и истории команд", "minutes": 15.0,
     "source": "оценка: визуальная сверка таблиц"},
    {"step": "Ручной запуск YARA и разбор срабатываний", "minutes": 8.0,
     "source": "оценка: без категоризации находок"},
]


def effort_comparison(stage_seconds: float, manual_model=None) -> dict:
    model = manual_model or MANUAL_MODEL
    manual_minutes = sum(s["minutes"] for s in model)
    auto_minutes = stage_seconds / 60.0
    return {
        "manual_steps": len(model),
        "manual_operator_actions": len(model) * 2,   # ввод команды + проверка результата
        "automated_operator_actions": 1,             # одна команда запуска
        "manual_minutes_estimate": round(manual_minutes, 1),
        "pipeline_minutes_measured": round(auto_minutes, 2),
        "speedup_estimate": round(manual_minutes / auto_minutes, 1) if auto_minutes > 0 else None,
        "model": model,
        "disclaimer": "Время ручного режима — оценочная модель трудозатрат, "
                      "время конвейера измерено фактически. Для итоговой таблицы "
                      "главы 3 требуется прямой хронометраж ручного режима на стенде.",
    }


def load_truth(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
