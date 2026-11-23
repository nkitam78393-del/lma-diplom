# -*- coding: utf-8 -*-
"""Сборка научной статьи для конференции «Искусственный интеллект:
научные достижения и прикладные задачи» (УгГУ, 2–4.12.2026) из
источника с простой разметкой.

Разметка:
  %TB  — заголовок, полужирный, по центру
  %C   — центрированная строка
  %SP  — пустая строка-разделитель
  %HC  — центрированный полужирный мини-заголовок
  %P   — обычный абзац (выравнивание both, отступ 567)
  %H1  — заголовок раздела (полужирный)
  %TR  — подпись таблицы, выкл. вправо
  %TBL1/%TBL2/%TBL3 — плейсхолдер таблицы (данные ниже)
"""
import sys
import os

SRC = "/workspace/article_src.md"
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "docs", "Статья_Михалёв_ИИ_2026.docx")
import docx_lib as dl

# Требования конференции: поля по 2 см (1134 twips) со всех сторон,
# отступ первой строки 1 см (567 twips) вместо дефолтных 709.
dl.SECT = ('<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
           '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" '
           'w:header="709" w:footer="709" w:gutter="0"/>'
           '<w:cols w:space="708"/><w:docGrid w:linePitch="360"/></w:sectPr>')
dl.STYLES = dl.STYLES.replace('w:firstLine="709"', 'w:firstLine="567"')


TBL_HEADERS_1 = ["Шаг", "Модуль", "Назначение"]
TBL_WIDTHS_1 = [500, 2400, 3600]
TBL_ROWS_1 = [
    ["1", "kernel_identifier", "Идентификация версии ядра по строкам-баннерам в образе"],
    ["2", "profile_manager", "Каскадное построение ISF-профиля (dwarf2json, отладочные символы ядра)"],
    ["3", "volatility_handler", "Извлечение артефактов: pslist, psscan, bash, кандидаты malfind"],
    ["4", "cross_view", "Перекрёстная корреляция источников; выявление DKOM-скрытых процессов"],
    ["5", "malfind", "Энтропийное предфильтрование анонимных исполняемых областей"],
    ["6", "yara_scanner", "Сигнатурное сканирование в режимах full, regions, hybrid"],
    ["7", "reputation", "Сверка хешей образцов: локальный список, оффлайн-режим, MalwareBazaar"],
    ["8", "timeline", "Построение хронологии инцидента"],
    ["9", "metrics, report_generator", "Расчёт TP/FP/FN и F1; формирование отчётов TXT, JSON, HTML"],
]

TBL_HEADERS_2 = ["Показатель", "Значение"]
TBL_WIDTHS_2 = [3300, 2400]
TBL_ROWS_2 = [
    ["Объём образа, МиБ", "128"],
    ["Скрытый DKOM-процесс", "обнаружен (PID 4242)"],
    ["YARA-срабатывания", "29 (22 маркеры ВПО, 7 утечки паролей)"],
    ["События хронологии", "57 (17 критических)"],
    ["Ложные срабатывания (FP)", "0"],
    ["F1-мера", "1,0"],
    ["Время полного анализа, с", "0,49"],
    ["Ускорение YARA-сканирования", "в 910 раз"],
]

TBL_HEADERS_3 = ["Показатель", "Значение"]
TBL_WIDTHS_3 = [3300, 2400]
TBL_ROWS_3 = [
    ["ОС и ядро исследуемой машины", "Ubuntu 22.04.5 LTS, 6.8.0-149-generic"],
    ["Баннеры ядра / доверие идентификации", "4 / 0,667"],
    ["Идентификация ядра, с", "13,9"],
    ["Построение ISF-профиля, с", "57,2"],
    ["Извлечение артефактов Volatility 3, с", "230,0"],
    ["YARA-сканирование (режим hybrid), с", "22,2"],
    ["Полное время анализа, с", "323,4"],
    ["Процессы pslist / psscan", "236 / 806"],
    ["Скрытые процессы (DKOM)", "не обнаружены"],
    ["YARA-находки", "17 (6 типов, картированы на MITRE ATT&CK)"],
]

TABLES = {
    "%TBL1": (TBL_HEADERS_1, TBL_ROWS_1, TBL_WIDTHS_1),
    "%TBL2": (TBL_HEADERS_2, TBL_ROWS_2, TBL_WIDTHS_2),
    "%TBL3": (TBL_HEADERS_3, TBL_ROWS_3, TBL_WIDTHS_3),
}


def placeholder(line):
    line = line.strip()
    return line if line in TABLES else None


def build():
    with open(SRC, encoding="utf-8") as f:
        lines = f.read().split("\n")

    body = []
    in_refs = False
    for line in lines:
        if not line.strip():
            continue
        if line.startswith("%H1 СПИСОК ЛИТЕРАТУРЫ"):
            in_refs = True
            body.append(dl.p(line[4:], bold=True, align="center", first=0, before=240, after=120))
            continue
        ph = placeholder(line)
        if ph:
            headers, rows, widths = TABLES[ph]
            body.append(dl.table(headers, rows, widths, sz=24, header_sz=24))
        elif line.startswith("%TB "):
            body.append(dl.p(line[4:], bold=True, align="center", first=0))
        elif line.startswith("%HC "):
            body.append(dl.p(line[4:], bold=True, align="center", first=0, before=200, after=100))
        elif line.startswith("%C "):
            body.append(dl.p(line[3:], align="center", first=0))
        elif line == "%SP":
            body.append(dl.p("", first=0, line=240))
        elif line.startswith("%TR "):
            body.append(dl.p(line[4:], align="right", first=0, before=160, after=80))
        elif line.startswith("%H1 "):
            body.append(dl.p(line[4:], bold=True, first=0, before=240, after=120))
        elif line.startswith("%P "):
            text = line[3:]
            if in_refs:
                body.append(dl.p(text, align="both", first=0, line=300))
            else:
                body.append(dl.p(text, align="both", first=567))
        else:
            raise ValueError("Неизвестная строка разметки: %r" % line[:80])

    return "".join(body)


def main():
    body = build()

    # Контроль аннотации: 1000–1200 печатных знаков
    with open(SRC, encoding="utf-8") as f:
        for l in f:
            if l.startswith("%P ") and "Цель." in l[:20]:
                print("Аннотация РУ: %d печатных знаков" % len(l.strip()[3:]))
            if l.startswith("%P Purpose."):
                print("Abstract EN: %d chars" % len(l.strip()[3:]))

    out_path = os.path.abspath(OUT)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    dl.save(out_path, body, title="Научная статья для конференции «ИИ-2026»")
    print("Сохранено:", out_path)

    # Грубая оценка объёма: символов основного текста
    txt = open(SRC, encoding="utf-8").read()
    visible = sum(len(l) for l in txt.split("\n")
                  if l.startswith("%P") or not l.startswith("%"))
    print("Символов основного текста (без шапки):", visible)
    print("Грубая оценка: ~%.1f стр. текста + 3 таблицы" % (visible / 1800.0))


if __name__ == "__main__":
    main()
