# -*- coding: utf-8 -*-
"""Генерация схемы конвейера анализа дампов памяти LMA (Рисунок 1 статьи).

Рисует «змейку» из 9 блоков (3 ряда по 3 блока) со стрелками на белом фоне.
Требует Pillow и файлов шрифтов DejaVuSans*.ttf (берутся из /workspace/fonts,
если не найдены в системе).  Запуск:  python3 tools/make_scheme.py
"""
import os
import sys
from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUT = os.path.join(ROOT, "docs", "article", "fig1_conveyor.png")

# Шаги конвейера: (название, имя модуля)
STAGES = [
    ("Идентификация ядра", "kernel_identifier"),
    ("Построение ISF-профиля", "profile_manager"),
    ("Извлечение артефактов", "volatility_handler"),
    ("Перекрёстная корреляция", "cross_view"),
    ("Энтропийный префильтр", "malfind"),
    ("YARA-сканирование", "yara_scanner"),
    ("Репутация хешей", "reputation"),
    ("Хронология инцидента", "timeline"),
    ("Метрики и отчёты", "metrics, report_generator"),
]


def find_font(name, size, bold=False):
    candidates = [
        os.path.join("/workspace", "fonts", name),
        os.path.join("/usr/share/fonts/truetype/dejavu", name),
    ]
    for p in candidates:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default(size)


def arrow(d, x0, y0, x1, y1, color="#000000", w=3):
    """Прямая стрелка от (x0,y0) к (x1,y1)."""
    d.line([(x0, y0), (x1, y1)], fill=color, width=w)
    import math
    ang = math.atan2(y1 - y0, x1 - x0)
    L, spread = 16, 0.42
    for delta in (spread, -spread):
        d.line([(x1, y1),
                (x1 - L * math.cos(ang + delta), y1 - L * math.sin(ang + delta))],
               fill=color, width=w)


def draw_block(d, box, title, module, f_title, f_module):
    x0, y0, x1, y1 = box
    d.rectangle(box, fill="#FFFFFF", outline="#000000", width=3)
    # заголовок по центру
    tb = f_title.getbbox(title)
    w = tb[2] - tb[0]
    d.text(((x0 + x1 - w) / 2 - tb[0], y0 + 18), title, fill="#000000", font=f_title)
    # имя модуля по центру ниже
    mb = f_module.getbbox(module)
    w2 = mb[2] - mb[0]
    d.text(((x0 + x1 - w2) / 2 - mb[0], y0 + 18 + tb[3] + 14), module,
           fill="#444444", font=f_module)


def main():
    # масштаб: строка-блок 3 по горизонтали, «змейка»
    BW, BH, GAP_X, GAP_Y = 430, 108, 120, 96   # блок, зазоры
    M = 60                                     # внешние поля
    W = M * 2 + BW * 3 + GAP_X * 2
    H = M * 2 + BH * 3 + GAP_Y * 2
    img = Image.new("RGB", (W, H), "#FFFFFF")
    d = ImageDraw.Draw(img)

    f_title = find_font("DejaVuSans-Bold.ttf", 21, bold=True)
    f_module = find_font("DejaVuSans.ttf", 18)

    # позиции блоков по «змейке»
    slots = {}
    # ряд 0 (сверху): слева направо 1,2,3
    slots.update({0: (0, 0), 1: (1, 0), 2: (2, 0)})
    # ряд 1: справа налево 4,5,6
    slots.update({3: (2, 1), 4: (1, 1), 5: (0, 1)})
    # ряд 2: слева направо 7,8,9
    slots.update({6: (0, 2), 7: (1, 2), 8: (2, 2)})

    def box_of(col, row):
        x0 = M + col * (BW + GAP_X)
        y0 = M + row * (BH + GAP_Y)
        return (x0, y0, x0 + BW, y0 + BH)

    boxes = [box_of(*slots[i]) for i in range(9)]

    for i, (title, module) in enumerate(STAGES):
        draw_block(d, boxes[i], title, module, f_title, f_module)

    # стрелки: 1->2->3, 3->4 (вниз), 4->5->6, 6->7 (вниз), 7->8->9
    for a, b in [(0, 1), (1, 2), (3, 4), (4, 5), (6, 7), (7, 8)]:
        (ax0, ay0, ax1, ay1), (bx0, by0, bx1, by1) = boxes[a], boxes[b]
        if abs(ay0 - by0) < 10:  # горизонтальная
            if bx0 > ax0:
                arrow(d, ax1 + 6, (ay0 + ay1) / 2, bx0 - 6, (by0 + by1) / 2)
            else:
                arrow(d, ax0 - 6, (ay0 + ay1) / 2, bx1 + 6, (by0 + by1) / 2)
    for a, b in [(2, 3), (5, 6)]:  # вертикальные переходы между рядами
        (ax0, ay0, ax1, ay1), (bx0, by0, bx1, by1) = boxes[a], boxes[b]
        arrow(d, (ax0 + ax1) / 2, ay1 + 6, (bx0 + bx1) / 2, by0 - 6)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    img.save(OUT, dpi=(300, 300))
    print("Сохранено:", OUT, img.size)


if __name__ == "__main__":
    main()
