# -*- coding: utf-8 -*-
"""Рендер терминальных скриншотов (PNG) из логов прогона LMA.

Используется для приложения к отчёту о проделанной работе: каждый лог
превращается в изображение окна терминала с тёмной темой.

Запуск:  python3 tools/render_screens.py
"""
from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(HERE, "build")
OUT = os.path.join(BUILD, "screens")

FONT = None
for cand in (
    os.path.expanduser("~/.local/lib/python3.12/site-packages/matplotlib/"
                       "mpl-data/fonts/ttf/DejaVuSansMono.ttf"),
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
):
    if os.path.exists(cand):
        FONT = cand
        break

BG = (26, 27, 38)
FG = (192, 202, 245)
HEADER_BG = (36, 40, 59)
ACCENT = (125, 207, 255)

SCREENS = [
    ("01_make_stand", "make_stand.log", "python3 -m lab.make_stand --out build/lab --size-mib 128", 24),
    ("02_analyze_start", "analyze_full.log", "python3 -m lma.cli analyze -f build/lab/memory_lab.raw … (часть 1: ядро, ISF, артефакты, cross-view)", 44),
    ("03_analyze_yara", "analyze_full.log", "… (часть 2: энтропия, YARA, репутация)", 22),
    ("04_analyze_timeline", "analyze_full.log", "… (часть 3: timeline, метрики, отчёт)", 26),
    ("05_compare", "compare.log", "python3 -m lma.cli compare --fixtures build/lab/plugins --ground-truth …", 46),
    ("06_bench", "bench.log", "python3 -m lma.cli bench -f build/lab/memory_lab.raw …", 40),
    ("07_env", "env.log", "python3 -m lma.cli env", 30),
    ("08_unittest", "unittest.log", "python3 -m unittest discover -s tests -v", 40),
]


def segment(line: str):
    """Простая подсветка: строки этапов, вердиктов и итогов."""
    if line.startswith("[") and "/9]" in line[:8]:
        return (125, 207, 255)
    if line.startswith("--") or line.startswith("=="):
        return (98, 114, 164)
    for key, color in (
        ("ИТОГО", (139, 233, 253)),
        ("F1", None),
        ("malicious", (255, 85, 85)),
        ("suspicious", (255, 184, 108)),
        ("СКРЫТЫЙ", (255, 85, 85)),
        ("critical", (255, 85, 85)),
        ("ОК", (114, 230, 138)),
        ("ok", (114, 230, 138)),
    ):
        if key in line and color:
            return color
    return FG


def render(name: str, log_name: str, title: str, max_lines: int):
    path = os.path.join(BUILD, log_name)
    if not os.path.exists(path):
        print(f"  [пропуск] нет лога {log_name}")
        return
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    if len(lines) > max_lines:
        head = lines[: max_lines - 2]
        tail = lines[-2:]
        lines = head + ["    … (сокращено) …"] + tail
    lines = [title, ""] + lines

    fnt = ImageFont.truetype(FONT, 15)
    fnt_bold = ImageFont.truetype(FONT.replace(".ttf", "-Bold.ttf") if os.path.exists(
        FONT.replace(".ttf", "-Bold.ttf")) else FONT, 15)
    lh = 21
    pad = 14
    width = 1180
    height = pad * 2 + 34 + lh * len(lines)
    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, width, 34], fill=HEADER_BG)
    for i, c in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        d.ellipse([14 + i * 22, 11, 26 + i * 22, 23], fill=c)
    d.text((width // 2 - 180, 9), f"{name} — LMA 2.1", font=fnt, fill=(125, 148, 179))
    y = 34 + pad
    for ln in lines:
        d.text((pad, y), ln, font=fnt, fill=segment(ln))
        y += lh
    out_path = os.path.join(OUT, f"{name}.png")
    img.save(out_path)
    print(f"  [ок] {out_path} ({len(lines)} строк, {width}x{height})")


def main():
    os.makedirs(OUT, exist_ok=True)
    print("Рендер скриншотов ->", OUT)
    for name, log, title, n in SCREENS:
        render(name, log, title, n)


if __name__ == "__main__":
    main()
