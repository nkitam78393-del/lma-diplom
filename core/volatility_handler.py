# -*- coding: utf-8 -*-
"""Интеграция с Volatility 3.

Ключевые исправления относительно версии курсового проекта:
  * убран флаг --profile (синтаксис Volatility 2, в Volatility 3 ломает запуск);
  * вывод плагинов берётся JSON-рендерером и разбирается в структуры Python;
  * имена полей приведены к фактическим колонкам Volatility 3 (проверено по
    исходникам volatility3 2.28.x): pslist -> "PID","TID","PPID","COMM",
    "CREATION TIME"; psscan -> +"EXIT_STATE"; bash -> "CommandTime","Command";
    malfind -> "Start","End","Protection","Path";
  * дерево JSON ("<__children>") разворачивается в плоский список;
  * учтено переименование плагинов: linux.malfind -> linux.malware.malfind
    (устаревший псевдоним объявлен к удалению 2026-06-07);
  * добавлены кеш результатов плагинов на диск и режим фикстур — повторяемые
    прогоны эксперимента без повторного разбора дампа (глава 3).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

# фактические имена плагинов с учётом переименований в volatility3 >= 2.9
PLUGIN_ALIASES = {
    "linux.malfind": "linux.malware.malfind",
    "linux.pslist": "linux.pslist",
    "linux.psscan": "linux.psscan",
    "linux.bash": "linux.bash",
    "linux.proc.maps": "linux.proc.maps",
    "linux.lsmod": "linux.lsmod",
    "linux.hidden_modules": "linux.hidden_modules",
}


def flatten_tree(rows) -> list[dict]:
    """JSON-рендерер Volatility 3 отдаёт дерево: разворачиваем в плоский список."""
    out: list[dict] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        children = row.get("__children") or []
        out.append({k: v for k, v in row.items() if k != "__children"})
        if children:
            out.extend(flatten_tree(children))
    return out


def _get(row: dict, *names, default=None):
    for n in names:
        if n in row and row[n] is not None:
            return row[n]
    return default


class VolatilityHandler:
    """Два бэкенда: реальный запуск vol.py и режим фикстур (лабораторный стенд)."""

    def __init__(self, vol_path: str, dump_path: str, logger=None,
                 fixtures: str | None = None, cache_dir: str | None = None,
                 timeout: int = 900):
        self.vol_path = vol_path
        self.vol_script = os.path.join(vol_path, "vol.py")
        self.dump_path = dump_path
        self.log = logger
        self.fixtures = fixtures
        self.cache_dir = cache_dir
        self.timeout = timeout
        self.calls: list[dict] = []

    # ------------------------------------------------------------ запуск
    def _resolve(self, plugin: str) -> str:
        return PLUGIN_ALIASES.get(plugin, plugin)

    def _cache_path(self, plugin: str) -> str | None:
        if not self.cache_dir:
            return None
        os.makedirs(self.cache_dir, exist_ok=True)
        return os.path.join(self.cache_dir, plugin.replace(".", "_") + ".json")

    def run_plugin(self, plugin: str, extra: list[str] | None = None) -> list[dict]:
        name = self._resolve(plugin)
        t0 = time.perf_counter()

        if self.fixtures:
            path = os.path.join(self.fixtures, name.replace(".", "_") + ".json")
            if not os.path.exists(path):
                raise FileNotFoundError(f"фикстура плагина не найдена: {path}")
            with open(path, encoding="utf-8") as fh:
                rows = flatten_tree(json.load(fh))
            self.calls.append({"plugin": name, "backend": "fixture",
                               "rows": len(rows), "seconds": round(time.perf_counter() - t0, 3)})
            return rows

        cache = self._cache_path(name)
        if cache and os.path.exists(cache) and not extra:
            with open(cache, encoding="utf-8") as fh:
                rows = json.load(fh)
            self.calls.append({"plugin": name, "backend": "cache",
                               "rows": len(rows), "seconds": round(time.perf_counter() - t0, 3)})
            return rows

        cmd = [sys.executable, self.vol_script, "-f", self.dump_path,
               "--renderer", "json", name] + (extra or [])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"плагин {name}: превышен таймаут {self.timeout} с")
        if proc.returncode != 0:
            raise RuntimeError(f"плагин {name} завершился с ошибкой: {proc.stderr[-400:]}")
        try:
            rows = flatten_tree(json.loads(proc.stdout))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"плагин {name}: не удалось разобрать JSON ({exc}); "
                               f"вывод: {proc.stdout[:200]!r}")
        if cache and not extra:
            with open(cache, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, ensure_ascii=False)
        self.calls.append({"plugin": name, "backend": "vol3",
                           "rows": len(rows), "seconds": round(time.perf_counter() - t0, 3)})
        return rows

    # ------------------------------------------------------------ обёртки
    def get_process_list(self, threads: bool = False) -> list[dict]:
        extra = ["--threads"] if threads else None
        return [{
            "pid": _get(r, "PID"),
            "tid": _get(r, "TID", default=_get(r, "PID")),
            "ppid": _get(r, "PPID"),
            "name": _get(r, "COMM", "Name", default=""),
            "uid": _get(r, "UID"),
            "offset": _get(r, "OFFSET (V)", "OFFSET"),
            "created": _get(r, "CREATION TIME", "CreateTime"),
        } for r in self.run_plugin("linux.pslist", extra)]

    def get_psscan(self) -> list[dict]:
        """Сканирование памяти по сигнатурам task_struct: TID и EXIT_STATE обязательны."""
        return [{
            "pid": _get(r, "PID"),
            "tid": _get(r, "TID", default=_get(r, "PID")),
            "ppid": _get(r, "PPID"),
            "name": _get(r, "COMM", "Name", default=""),
            "exit_state": _get(r, "EXIT_STATE", default="TASK_RUNNING"),
            "offset": _get(r, "OFFSET (P)", "OFFSET"),
        } for r in self.run_plugin("linux.psscan")]

    def get_psscan_pids(self) -> set:
        return {r["pid"] for r in self.get_psscan()}

    def get_bash_history(self) -> list[dict]:
        return [{
            "pid": _get(r, "PID"),
            "process": _get(r, "Process", default="bash"),
            "timestamp": str(_get(r, "CommandTime", "Timestamp", default="")),
            "command": _get(r, "Command", "CommandLine", default=""),
        } for r in self.run_plugin("linux.bash")]

    def get_malfind(self, dump_regions: bool = False) -> list[dict]:
        extra = ["--dump"] if dump_regions else None
        return [{
            "pid": _get(r, "PID"),
            "process": _get(r, "Process", "COMM", default=""),
            "start": _get(r, "Start"),
            "end": _get(r, "End"),
            "path": _get(r, "Path", default=""),
            "protection": _get(r, "Protection", default=""),
            "hexdump": _get(r, "Hexdump", default=""),
            "file": _get(r, "File output", default=""),
        } for r in self.run_plugin("linux.malfind", extra)]

    def get_maps(self) -> list[dict]:
        return [{
            "pid": _get(r, "PID"),
            "process": _get(r, "Process", default=""),
            "start": _get(r, "Start"),
            "end": _get(r, "End"),
            "flags": _get(r, "Flags", default=""),
            "path": _get(r, "File Path", default=""),
        } for r in self.run_plugin("linux.proc.maps")]

    # ------------------------------------------------------------ окружение
    @staticmethod
    def environment() -> dict:
        info = {"python": sys.version.split()[0]}
        try:
            import volatility3
            from volatility3.framework import constants
            info["volatility3"] = constants.PACKAGE_VERSION
            info["volatility3_path"] = os.path.dirname(volatility3.__file__)
        except Exception:
            info["volatility3"] = None
        try:
            import yara
            info["yara"] = yara.__version__
        except Exception:
            info["yara"] = None
        info["dwarf2json"] = shutil.which("dwarf2json")
        return info
