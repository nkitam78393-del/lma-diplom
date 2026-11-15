# -*- coding: utf-8 -*-
"""Анализ областей памяти с признаками инъекции кода (linux.malware.malfind).

Модуль отсутствовал в курсовом проекте. Реализует двухступенчатую схему:

  1) структурный признак — анонимная область с правами rwx (то, что отдаёт
     плагин malfind: в volatility3 отбор идёт по flags_str == "rwx");
  2) энтропийная предфильтрация содержимого области — отсев нулевых страниц и
     текстовых данных ДО сигнатурного сканирования, с классификацией остатка
     по энтропии Шеннона и признакам машинного кода.

Смысл предфильтрации: сигнатурный сканер получает только области, содержимое
которых статистически совместимо с кодом или упакованной полезной нагрузкой.
Это снижает объём сканируемых данных на порядки относительно прогона YARA по
всему образу памяти и даёт интерпретируемую причину для каждой находки.
"""
from __future__ import annotations

import os
import re

from .utils import byte_profile, sha256_bytes

# пороги обоснованы эмпирически: текст ~4.0-5.0, код x86-64 ~5.4-6.6,
# упакованные/шифрованные данные > 7.2, нулевые страницы < 1.0
ENT_ZERO = 1.0
ENT_TEXT_MAX = 5.2
ENT_CODE_MIN = 5.2
ENT_PACKED = 7.2
PRINTABLE_TEXT = 0.90
MIN_REGION = 512
MAX_READ = 4 << 20      # не более 4 МБ на область


def _region_file(row: dict, dump_dir: str | None) -> str | None:
    """Файл выгруженной области (malfind --dump) либо сопоставление по шаблону."""
    f = row.get("file") or ""
    if f and f not in ("Disabled", "-") and os.path.exists(f):
        return f
    if dump_dir:
        cand = os.path.join(dump_dir, os.path.basename(f)) if f else None
        if cand and os.path.exists(cand):
            return cand
        pat = re.compile(rf"^pid\.{row.get('pid')}\.vma\.", re.IGNORECASE)
        start = row.get("start")
        for name in sorted(os.listdir(dump_dir)):
            if pat.match(name) and (start is None or str(start).lower().replace("0x", "") in name.lower()):
                return os.path.join(dump_dir, name)
    return None


def classify(profile: dict, protection: str) -> dict:
    """Решение по области: категория, критичность, пропускать ли в YARA."""
    ent, printable, size = profile["entropy"], profile["printable"], profile["size"]
    rwx = "w" in protection and "x" in protection
    if size < MIN_REGION:
        return {"verdict": "too_small", "severity": "info", "scan": False,
                "why": f"область мала ({size} Б)"}
    if not rwx:
        return {"verdict": "not_executable", "severity": "info", "scan": False,
                "why": f"нет прав на исполнение ({protection or 'n/a'})"}
    if ent < ENT_ZERO:
        return {"verdict": "zero_padding", "severity": "info", "scan": False,
                "why": f"нулевое заполнение (энтропия {ent})"}
    if printable > PRINTABLE_TEXT and ent < ENT_TEXT_MAX:
        return {"verdict": "text_data", "severity": "low", "scan": False,
                "why": f"текстовые данные (printable={printable}, энтропия {ent})"}
    if ent >= ENT_PACKED:
        return {"verdict": "packed_or_encrypted", "severity": "high", "scan": True,
                "why": f"энтропия {ent} ≥ {ENT_PACKED}: упакованная/шифрованная нагрузка"}
    if ent >= ENT_CODE_MIN and (profile["x86_prologue"] or profile["elf"]):
        return {"verdict": "probable_injected_code", "severity": "high", "scan": True,
                "why": f"энтропия {ent} и признаки машинного кода"}
    if ent >= ENT_CODE_MIN:
        return {"verdict": "high_entropy_review", "severity": "medium", "scan": True,
                "why": f"энтропия {ent} в диапазоне кода, признаков пролога нет"}
    return {"verdict": "review", "severity": "low", "scan": True,
            "why": f"энтропия {ent}, требуется ручная проверка"}


def analyze_regions(rows: list[dict], dump_dir: str | None = None,
                    scanner=None, logger=None) -> dict:
    """Полный цикл: чтение области -> профиль байтов -> решение -> YARA по области."""
    results, dropped = [], []
    bytes_total = bytes_scanned = 0
    for row in rows:
        path = _region_file(row, dump_dir)
        data = b""
        if path:
            with open(path, "rb") as fh:
                data = fh.read(MAX_READ)
        elif row.get("hexdump"):
            try:
                data = bytes.fromhex(str(row["hexdump"]).replace(" ", "").replace("\n", ""))
            except ValueError:
                data = b""
        prof = byte_profile(data)
        size = prof["size"] or max(0, int(row.get("end") or 0) - int(row.get("start") or 0))
        bytes_total += size
        decision = classify(prof, str(row.get("protection") or ""))
        record = {
            "pid": row.get("pid"), "process": row.get("process"),
            "start": row.get("start"), "end": row.get("end"),
            "protection": row.get("protection"), "path": row.get("path") or "",
            "region_file": path, "size": size,
            "entropy": prof["entropy"], "printable": prof["printable"],
            "nulls": prof["nulls"], "sha256": sha256_bytes(data) if data else None,
            **decision,
        }
        if decision["scan"]:
            if scanner is not None and data:
                record["yara"] = scanner.scan_bytes(
                    data, context={"pid": row.get("pid"), "process": row.get("process"),
                                   "start": row.get("start"), "region": "vma"})
                bytes_scanned += len(data)
                if record["yara"]:
                    top = sorted(record["yara"], key=lambda h: h.get("severity") == "critical")
                    record["severity"] = top[0]["severity"] if top else record["severity"]
            results.append(record)
        else:
            dropped.append(record)

    kept = len(results)
    stats = {
        "regions_total": len(rows),
        "regions_scanned": kept,
        "regions_dropped": len(dropped),
        "bytes_total": bytes_total,
        "bytes_scanned": bytes_scanned,
        "prefilter_ratio": round(1 - (bytes_scanned / bytes_total), 4) if bytes_total else 0.0,
        "findings": sum(len(r.get("yara") or []) for r in results),
    }
    if logger:
        logger.info(f"    областей всего: {len(rows)}, отобрано для YARA: {kept}, "
                    f"отсеяно предфильтром: {len(dropped)}")
    return {"regions": results, "dropped": dropped, "stats": stats}
