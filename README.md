# LMA 2.1 — Linux Memory Analyzer

Консольный конвейер анализа дампов памяти Linux (дипломная работа, версия 2.1):

идентификация ядра → ISF-профиль → артефакты (Volatility 3: pslist/psscan/bash/malfind) →
кросс-вид (DKOM) → энтропийный префильтр + YARA → репутация хешей (MalwareBazaar + SQLite-кэш) →
хронология инцидента → метрики качества → отчёт TXT/JSON/HTML.

## Результаты на лабораторном стенде 128 МиБ

- F1 = 1.0 (precision = recall = 1.0), ложных срабатываний на benign-контролях нет;
- 29 сигнатурных находок (22 malware, 7 secrets), скрытый процесс DKOM (PID 4242);
- ускорение сканирования по областям ×910 (bench);
- 19 модульных тестов — все проходят.

## Структура

```
lma.py                 # точка входа (python3 lma.py ...)
lma/cli.py             # разбор команд и конвейер analyze
core/                  # 12 модулей этапов анализа
lab/make_stand.py      # генератор лабораторного стенда
rules/                 # YARA-правила (malware, injection, secrets)
tests/test_lma.py      # 19 модульных тестов
tools/render_screens.py# рендер скриншотов из логов
docs/                  # ГАЙД запуска, сообщение руководителю
build/                 # логи прогонов, отчёты, скриншоты, docx-отчёт
```

## Быстрый старт

```bash
pip install yara-python
python3 -m lab.make_stand --out build/lab --size-mib 128
python3 lma.py analyze --image build/lab/memory_lab.raw --map build/lab/memory_map.json \
        --truth build/lab/ground_truth.json --out build
python3 -m unittest discover -s tests -v
```

Подробная пошаговая инструкция — в [docs/ГАЙД_запуск.md](docs/ГАЙД_запуск.md).
