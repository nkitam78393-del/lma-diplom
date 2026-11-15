# -*- coding: utf-8 -*-
"""Сигнатурный слой YARA с категоризацией находок.

Отличия от курсового проекта (там было два демонстрационных правила):
  * правила размечены метаданными category / severity / mitre / reference;
  * две категории с разной семантикой реагирования: malware (признак
    компрометации) и secrets (утечка, требует ротации, но не компрометация);
  * два режима сканирования: весь образ (полнота) и только отобранные области
    памяти (скорость) — сравнение времени выполнения даёт материал главы 3;
  * дедупликация находок и редактирование секретов: в отчёт не попадает
    ключевой материал целиком, только префикс и SHA-256 (требование к
    обращению с чувствительными данными при экспертизе).
"""
from __future__ import annotations

import os
import time

try:
    import yara
except ImportError:                                   # pragma: no cover
    yara = None

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
REDACT_CATEGORIES = {"secrets"}


def _snippet(data: bytes, category: str, limit: int = 48) -> str:
    text = data[:limit].decode("utf-8", "replace")
    text = "".join(ch if 32 <= ord(ch) < 127 else "·" for ch in text)
    if category in REDACT_CATEGORIES:
        from .utils import sha256_bytes
        return text[:12] + "…[REDACTED] sha256:" + sha256_bytes(data)[:16]
    return text


class YaraScanner:
    def __init__(self, rules_path: str, logger=None, timeout: int = 900):
        if yara is None:
            raise RuntimeError("модуль yara-python не установлен: pip install yara-python")
        self.log = logger
        self.timeout = timeout
        self.rule_files: list[str] = []
        if os.path.isdir(rules_path):
            self.rule_files = [os.path.join(rules_path, f) for f in sorted(os.listdir(rules_path))
                               if f.endswith((".yar", ".yara"))]
        elif os.path.isfile(rules_path):
            self.rule_files = [rules_path]
        if not self.rule_files:
            raise FileNotFoundError(f"правила YARA не найдены: {rules_path}")
        srcs = {os.path.basename(p): open(p, encoding="utf-8").read() for p in self.rule_files}
        self.rules = yara.compile(sources=srcs)
        self.meta = self._collect_meta()
        self.stats = {"rules": len(self.meta), "files": len(self.rule_files)}

    def _collect_meta(self) -> dict:
        """Метаданные правил читаются из исходников (надёжнее, чем через match)."""
        import re
        meta: dict[str, dict] = {}
        for path in self.rule_files:
            text = open(path, encoding="utf-8").read()
            for m in re.finditer(r"rule\s+(\w+)[^{]*\{(.*?)\n\}", text, re.S):
                name, body = m.group(1), m.group(2)
                fields = dict(re.findall(r'(\w+)\s*=\s*"([^"]*)"', body))
                meta[name] = {
                    "category": fields.get("category", "uncategorised"),
                    "severity": fields.get("severity", "medium"),
                    "mitre": fields.get("mitre", ""),
                    "description": fields.get("description", ""),
                    "reference": fields.get("reference", ""),
                    "file": os.path.basename(path),
                }
        return meta

    # ------------------------------------------------------------ сканирование
    def _findings(self, matches, context: dict, data_provider=None) -> list[dict]:
        out = []
        for m in matches:
            info = self.meta.get(m.rule, {})
            cat = info.get("category", "uncategorised")
            for inst in m.strings:
                for hit in inst.instances:
                    raw = hit.matched_data
                    out.append({
                        "rule": m.rule,
                        "category": cat,
                        "severity": info.get("severity", "medium"),
                        "mitre": info.get("mitre", ""),
                        "description": info.get("description", ""),
                        "reference": info.get("reference", ""),
                        "string_id": inst.identifier,
                        "offset": hit.offset,
                        "length": len(raw),
                        "snippet": _snippet(raw, cat),
                        **context,
                    })
        out.sort(key=lambda h: (SEV_ORDER.get(h["severity"], 9), h["offset"]))
        return out

    def scan_bytes(self, data: bytes, context: dict | None = None) -> list[dict]:
        t0 = time.perf_counter()
        matches = self.rules.match(data=data, timeout=self.timeout)
        res = dedup(self._findings(matches, context or {}))
        self.stats["last_seconds"] = round(time.perf_counter() - t0, 3)
        return res

    def scan_file(self, path: str, context: dict | None = None) -> dict:
        t0 = time.perf_counter()
        matches = self.rules.match(filepath=path, timeout=self.timeout)
        res = self._findings(matches, {"region": "full_image", **(context or {})})
        seconds = round(time.perf_counter() - t0, 3)
        size = os.path.getsize(path)
        return {
            "findings": dedup(res),
            "seconds": seconds,
            "bytes": size,
            "throughput_mibs": round(size / (1 << 20) / seconds, 1) if seconds > 0 else None,
            "mode": "full_image",
        }

    def scan_regions(self, regions: list[dict]) -> dict:
        """Сканирование только отобранных областей (после энтропийного фильтра)."""
        t0 = time.perf_counter()
        findings, scanned = [], 0
        for reg in regions:
            for hit in reg.get("yara") or []:
                findings.append(hit)
            scanned += reg.get("size") or 0
        seconds = round(time.perf_counter() - t0, 3)
        return {"findings": dedup(findings), "seconds": seconds, "bytes": scanned,
                "mode": "regions"}


def dedup(findings: list[dict]) -> list[dict]:
    """Схлопывание находок: одно правило + один контекст + неперекрывающийся фрагмент.

    Регулярные выражения YARA дают серию срабатываний со сдвигом на 1-2 байта
    внутри одной и той же строки (например, строки /etc/shadow). Такие серии
    подавляются: сохраняется первое срабатывание, последующие, попадающие в
    его интервал, отбрасываются. Это устраняет завышение числа находок.
    """
    groups: dict[tuple, list[dict]] = {}
    for f in findings:
        groups.setdefault((f["rule"], f.get("pid"), f.get("region")), []).append(f)
    out = []
    for _, items in groups.items():
        items.sort(key=lambda h: h["offset"])
        last_end = -1
        for f in items:
            if f["offset"] < last_end:
                continue
            out.append(f)
            last_end = f["offset"] + max(1, f.get("length") or 1)
    out.sort(key=lambda h: (SEV_ORDER.get(h["severity"], 9), h["offset"]))
    return out


def by_category(findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["category"]] = counts.get(f["category"], 0) + 1
    return counts


def by_severity(findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {k: counts[k] for k in sorted(counts, key=lambda s: SEV_ORDER.get(s, 9))}
