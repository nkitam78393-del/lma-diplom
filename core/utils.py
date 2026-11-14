# -*- coding: utf-8 -*-
"""Вспомогательные функции LMA 2.1: энтропия, хеширование, тайминг, логирование."""
from __future__ import annotations

import hashlib
import math
import os
import time
from collections import Counter


# ---------------------------------------------------------------- энтропия
def shannon_entropy(data: bytes) -> float:
    """Энтропия Шеннона в битах на байт (0.0 .. 8.0).

    Используется как предфильтр областей памяти: машинный код и текстовые
    данные дают 3.5-6.5 бит/байт, упакованные/шифрованные полезные нагрузки
    приближаются к 8.0, нулевые страницы дают 0.0.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def byte_profile(data: bytes) -> dict:
    """Признаки содержимого области памяти, используемые классификатором."""
    if not data:
        return {"size": 0, "entropy": 0.0, "printable": 0.0, "nulls": 0.0,
                "elf": False, "x86_prologue": False}
    n = len(data)
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13)) / n
    nulls = data.count(0) / n
    return {
        "size": n,
        "entropy": round(shannon_entropy(data), 3),
        "printable": round(printable, 3),
        "nulls": round(nulls, 3),
        "elf": data[:4] == b"\x7fELF",
        # typичные прологи x86-64 и syscall-инструкции shellcode
        "x86_prologue": (b"\x55\x48\x89\xe5" in data[:4096]
                         or b"\x0f\x05" in data[:4096]
                         or b"\x48\x31\xc0" in data[:4096]),
    }


# ---------------------------------------------------------------- хеши
def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- тайминг
class StageTimer:
    """Замер времени этапов конвейера (для главы 3: таблица времени выполнения)."""

    def __init__(self):
        self.stages: list[dict] = []
        self._t0 = time.perf_counter()

    def stage(self, name: str, **extra):
        timer = self

        class _Ctx:
            def __enter__(self):
                self.t = time.perf_counter()
                return self

            def __exit__(self, *exc):
                rec = {"stage": name, "seconds": round(time.perf_counter() - self.t, 3)}
                rec.update(extra)
                timer.stages.append(rec)
                return False

        return _Ctx()

    @property
    def total(self) -> float:
        return round(time.perf_counter() - self._t0, 3)

    def as_list(self) -> list[dict]:
        return list(self.stages)


# ---------------------------------------------------------------- вывод
def human_size(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TiB"


class Console:
    """Простой консольный логгер в стиле прежней версии LMA (без сторонних зависимостей)."""

    def __init__(self, verbose: bool = True, width: int = 78):
        self.verbose = verbose
        self.width = width

    def rule(self, title: str = ""):
        if title:
            print(f"-- {title} " + "-" * max(0, self.width - len(title) - 4))
        else:
            print("-" * self.width)

    def info(self, msg: str):
        if self.verbose:
            print(msg)

    def ok(self, msg: str):
        print(f"[+] {msg}")

    def warn(self, msg: str):
        print(f"[!] {msg}")

    def bad(self, msg: str):
        print(f"[-] {msg}")

    def step(self, idx: str, msg: str):
        print(f"[{idx}] {msg}")


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path
