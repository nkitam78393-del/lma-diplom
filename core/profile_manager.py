# -*- coding: utf-8 -*-
"""Каскадная подготовка таблиц символов ISF (Intermediate Symbol Format).

Каскад: локальное хранилище -> поиск vmlinux -> dwarf2json -> проверка результата.

Отличие от LMA 1.x:
  * результат конвертации проверяется (валидный JSON, наличие нужных секций),
    «битый» профиль не попадает в хранилище и не ломает последующие плагины;
  * ведётся манифест profiles.json: версия ядра, источник vmlinux, его SHA-256,
    время генерации, время выполнения — воспроизводимость эксперимента (глава 3);
  * повторный запуск не перегенерирует профиль (кеш), что и даёт экономию времени;
  * при отсутствии vmlinux выдаётся точная команда подключения ddebs и скачивания
    пакета *-dbgsym под конкретную версию ядра (диагностика вместо «не найдено»).
"""
from __future__ import annotations

import json
import os
import subprocess
import time

from .utils import sha256_file

VMLINUX_CANDIDATES = (
    "{symbols}/vmlinux-{ver}",
    "/usr/lib/debug/boot/vmlinux-{ver}",     # сюда ставится пакет *-dbgsym (ddebs)
    "/usr/lib/debug/vmlinux-{ver}",
    "/boot/vmlinux-{ver}",
)

DDEBS_HINT = (
    "sudo tee /etc/apt/sources.list.d/ddebs.list <<'EOF'\n"
    "deb http://ddebs.ubuntu.com {codename} main restricted universe multiverse\n"
    "deb http://ddebs.ubuntu.com {codename}-updates main restricted universe multiverse\n"
    "EOF\n"
    "sudo apt install ubuntu-dbgsym-keyring && sudo apt update\n"
    "sudo apt install linux-image-unsigned-{ver}-dbgsym"
)


class ProfileManager:
    def __init__(self, vol_path: str, dwarf_path: str, logger=None,
                 codename: str = "noble", manifest: str | None = None):
        self.symbols_dir = os.path.join(vol_path, "volatility3", "symbols", "linux")
        if not os.path.isdir(self.symbols_dir):
            # вариант установки из pip: symbols лежат внутри пакета
            alt = os.path.join(vol_path, "symbols", "linux")
            if os.path.isdir(alt):
                self.symbols_dir = alt
        self.dwarf_path = dwarf_path
        self.log = logger
        self.codename = codename
        self.manifest_path = manifest or os.path.join(self.symbols_dir, "lma_profiles.json")

    # ------------------------------------------------------------ манифест
    def _manifest(self) -> dict:
        try:
            with open(self.manifest_path, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}

    def _save_manifest(self, data: dict):
        try:
            os.makedirs(os.path.dirname(self.manifest_path), exist_ok=True)
            with open(self.manifest_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _info(self, msg):
        if self.log:
            self.log.info(msg)

    # ------------------------------------------------------------ поиск
    def find_profile(self, version: str) -> str | None:
        for ext in (".json", ".json.xz"):
            path = os.path.join(self.symbols_dir, version + ext)
            if os.path.exists(path):
                return path
        return None

    def find_vmlinux(self, version: str) -> str | None:
        for tpl in VMLINUX_CANDIDATES:
            path = tpl.format(symbols=self.symbols_dir, ver=version)
            if os.path.exists(path):
                return path
        return None

    @staticmethod
    def validate_isf(path: str) -> tuple[bool, str]:
        """Минимальная проверка пригодности таблицы символов."""
        try:
            opener = open
            if path.endswith(".xz"):
                import lzma
                opener = lzma.open
            with opener(path, "rt", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:                        # noqa: BLE001
            return False, f"не читается как JSON: {exc}"
        base = data.get("base_types") or {}
        symbols = data.get("symbols") or {}
        enums = data.get("enums") or {}
        if not symbols and not enums:
            return False, "нет секций symbols/enums"
        meta = data.get("metadata") or {}
        if "linux" not in json.dumps(meta).lower() and not base:
            return False, "не похоже на профиль Linux (нет base_types)"
        return True, f"symbols={len(symbols)}, enums={len(enums)}, base_types={len(base)}"

    # ------------------------------------------------------------ каскад
    def ensure_profile(self, version: str) -> dict:
        """Возвращает {"ok", "source", "path", "seconds", "detail"}."""
        t0 = time.perf_counter()
        existing = self.find_profile(version)
        if existing:
            ok, detail = self.validate_isf(existing)
            if ok:
                self._info(f"[+] ISF-профиль найден в хранилище: {os.path.basename(existing)} ({detail})")
                return {"ok": True, "source": "cache", "path": existing,
                        "seconds": round(time.perf_counter() - t0, 3), "detail": detail}
            self._info(f"[!] профиль {existing} непригоден ({detail}) — перегенерация")

        vmlinux = self.find_vmlinux(version)
        if not vmlinux:
            if self.log:
                self.log.bad(f"vmlinux для {version} не найден ни в одном источнике")
                self.log.info("    подключить репозиторий отладочных символов и установить пакет:")
                for line in DDEBS_HINT.format(codename=self.codename, ver=version).splitlines():
                    self.log.info("      " + line)
            return {"ok": False, "source": "missing", "path": None,
                    "seconds": round(time.perf_counter() - t0, 3),
                    "detail": "vmlinux не найден; требуется пакет *-dbgsym (ddebs)"}

        if not (os.path.isfile(self.dwarf_path) and os.access(self.dwarf_path, os.X_OK)):
            return {"ok": False, "source": "no-converter", "path": None,
                    "seconds": round(time.perf_counter() - t0, 3),
                    "detail": f"dwarf2json не найден или не исполняемый: {self.dwarf_path}"}

        os.makedirs(self.symbols_dir, exist_ok=True)
        profile = os.path.join(self.symbols_dir, version + ".json")
        tmp = profile + ".part"
        self._info(f"[*] dwarf2json linux --elf {vmlinux} -> {profile}")
        try:
            with open(tmp, "w", encoding="utf-8") as out:
                proc = subprocess.run([self.dwarf_path, "linux", "--elf", vmlinux],
                                      stdout=out, stderr=subprocess.PIPE, timeout=1800)
            if proc.returncode != 0:
                os.replace(tmp, tmp + ".failed")
                return {"ok": False, "source": "dwarf2json", "path": None,
                        "seconds": round(time.perf_counter() - t0, 3),
                        "detail": proc.stderr.decode("utf-8", "replace")[-300:]}
            ok, detail = self.validate_isf(tmp)
            if not ok:
                os.replace(tmp, tmp + ".invalid")
                return {"ok": False, "source": "dwarf2json", "path": None,
                        "seconds": round(time.perf_counter() - t0, 3), "detail": detail}
            os.replace(tmp, profile)
        except subprocess.TimeoutExpired:
            return {"ok": False, "source": "timeout", "path": None,
                    "seconds": round(time.perf_counter() - t0, 3),
                    "detail": "dwarf2json превысил таймаут 1800 с"}

        seconds = round(time.perf_counter() - t0, 3)
        man = self._manifest()
        man[version] = {"path": profile, "vmlinux": vmlinux,
                        "vmlinux_sha256": sha256_file(vmlinux),
                        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "seconds": seconds, "detail": detail}
        self._save_manifest(man)
        if self.log:
            self.log.ok(f"ISF-профиль сгенерирован за {seconds} с ({detail})")
        return {"ok": True, "source": "dwarf2json", "path": profile,
                "seconds": seconds, "detail": detail}
