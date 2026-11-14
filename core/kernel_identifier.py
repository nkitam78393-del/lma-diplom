# -*- coding: utf-8 -*-
"""Идентификация ядра Linux напрямую из сырого дампа памяти.

Отличие от версии курсового проекта (LMA 1.x):
  * собирается ВСЕ множество баннеров, а не первый попавшийся (в дампе их
    десятки: сам буфер ядра, копии в kmsg, в логах journald, в памяти утилит);
  * выбор версии по частоте встречаемости и полноте баннера (устойчивость к
    обрезанным и «мусорным» копиям) — именно из-за этого штатный плагин
    banners.Banners на исследованном дампе давал неверный результат;
  * извлекаются дополнительные атрибуты (компилятор, дата сборки, архитектура),
    необходимые для подбора пакета отладочных символов;
  * возвращается оценка достоверности и смещение баннера в образе — для
    протокола исследования (криминалистическая воспроизводимость).
"""
from __future__ import annotations

import os
import re
from collections import Counter

# Полный баннер: Linux version 6.17.0-19-generic (buildd@lcy02-amd64-...) (gcc ...) #20~24.04.2-Ubuntu SMP ...
BANNER_RE = re.compile(
    rb"Linux version (?P<ver>\d+\.\d+\.\d+[^\s(\x00]{0,64})"
    rb"(?P<tail>[^\x00]{0,320})"
)
GCC_RE = re.compile(rb"\((?:gcc|Ubuntu clang|clang)[^)]{0,120}\)")
BUILD_RE = re.compile(rb"#\d+[^\x00]{0,80}(?:SMP|PREEMPT)[^\x00]{0,60}")
ARCH_HINTS = (
    (rb"x86_64", "x86_64"), (rb"amd64", "x86_64"),
    (rb"aarch64", "aarch64"), (rb"arm64", "aarch64"),
)

CHUNK = 64 * 1024 * 1024      # потоковое чтение блоками по 64 МБ
OVERLAP = 512                 # нахлёст: баннер не должен разрываться на стыке


def _arch_of(tail: bytes) -> str | None:
    for token, arch in ARCH_HINTS:
        if token in tail:
            return arch
    return None


def identify_kernel(dump_path: str, logger=None, max_hits: int = 4096) -> dict | None:
    """Потоковый поиск баннеров ядра. Возвращает сводку либо None.

    Результат: {"version", "banner", "offset", "occurrences", "candidates",
                "compiler", "build", "arch", "confidence", "scanned_bytes"}
    """
    if not os.path.exists(dump_path):
        raise FileNotFoundError(dump_path)

    versions: Counter = Counter()
    best: dict = {}
    scanned = 0
    hits = 0
    tail = b""
    base = 0

    with open(dump_path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            window = tail + chunk
            for m in BANNER_RE.finditer(window):
                hits += 1
                ver = m.group("ver").decode("ascii", "ignore")
                rest = m.group("tail")
                versions[ver] += 1
                # полнота баннера = длина осмысленного «хвоста»
                quality = len(rest.split(b"\x00")[0])
                cur = best.get(ver)
                if cur is None or quality > cur["quality"]:
                    gcc = GCC_RE.search(rest)
                    build = BUILD_RE.search(rest)
                    best[ver] = {
                        "quality": quality,
                        "offset": max(0, base - len(tail) + m.start()),
                        "banner": (b"Linux version " + m.group("ver") + rest[:quality])
                                  .decode("utf-8", "replace").strip(),
                        "compiler": gcc.group(0).decode("utf-8", "replace").strip("()") if gcc else None,
                        "build": build.group(0).decode("utf-8", "replace") if build else None,
                        "arch": _arch_of(rest),
                    }
                if hits >= max_hits:
                    break
            scanned += len(chunk)
            if hits >= max_hits:
                break
            tail = window[-OVERLAP:]
            base += len(chunk)

    if not versions:
        if logger:
            logger.bad("баннер 'Linux version' в образе не найден")
        return None

    version, count = versions.most_common(1)[0]
    info = best[version]
    total = sum(versions.values())
    # достоверность: доля выбранной версии среди всех найденных баннеров,
    # скорректированная на полноту баннера
    confidence = round(min(0.99, (count / total) * (0.7 + 0.3 * min(1.0, info["quality"] / 160))), 3)

    result = {
        "version": version,
        "banner": info["banner"],
        "offset": info["offset"],
        "occurrences": count,
        "candidates": [{"version": v, "count": c} for v, c in versions.most_common()],
        "compiler": info["compiler"],
        "build": info["build"],
        "arch": info["arch"],
        "confidence": confidence,
        "scanned_bytes": scanned,
    }
    if logger:
        logger.ok(f"ядро определено: {version} (баннеров: {count}/{total}, "
                  f"достоверность {confidence}, смещение {hex(info['offset'])})")
        if len(versions) > 1:
            others = ", ".join(f"{v}×{c}" for v, c in versions.most_common()[1:4])
            logger.info(f"    прочие версии-кандидаты: {others}")
    return result


def kernel_version(dump_path: str, logger=None) -> str | None:
    """Совместимость с интерфейсом LMA 1.x."""
    res = identify_kernel(dump_path, logger)
    return res["version"] if res else None
