# -*- coding: utf-8 -*-
"""Репутационная проверка извлечённых объектов по хеш-суммам.

Модуль из курсового проекта переработан:
  * локальный кеш SQLite (повторные прогоны не обращаются к сети);
  * ограничение частоты запросов и лимит запросов за прогон (требование API);
  * два провайдера: MalwareBazaar (сеть, требуется Auth-Key) и локальный
    справочник хешей (offline-режим, воспроизводимый эксперимент);
  * провайдер и источник вердикта фиксируются в отчёте — находка не выдаётся
    за результат внешнего сервиса, если получена из локального справочника.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

MB_ENDPOINT = "https://mb-api.abuse.ch/api/v1/"
SCHEMA = """
CREATE TABLE IF NOT EXISTS hashes(
    sha256 TEXT PRIMARY KEY,
    verdict TEXT NOT NULL,
    signature TEXT,
    provider TEXT NOT NULL,
    first_seen TEXT,
    checked_at TEXT NOT NULL,
    raw TEXT
);
"""


class ReputationChecker:
    def __init__(self, cache_path: str, provider: str = "local",
                 local_list: str | None = None, auth_key: str | None = None,
                 min_interval: float = 1.0, max_queries: int = 40,
                 ttl_days: int = 14, logger=None):
        self.provider = provider
        self.auth_key = auth_key or os.environ.get("MB_AUTH_KEY")
        self.min_interval = min_interval
        self.max_queries = max_queries
        self.ttl = ttl_days * 86400
        self.log = logger
        self._last_request = 0.0
        self.queries = 0
        self.cache_hits = 0
        os.makedirs(os.path.dirname(os.path.abspath(cache_path)), exist_ok=True)
        self.db = sqlite3.connect(cache_path)
        self.db.executescript(SCHEMA)
        self.local: dict[str, dict] = {}
        if local_list and os.path.exists(local_list):
            with open(local_list, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 2)
                    if len(parts) >= 2:
                        self.local[parts[0].lower()] = {
                            "verdict": parts[1],
                            "signature": parts[2] if len(parts) > 2 else "",
                        }

    # ------------------------------------------------------------ кеш
    def _cached(self, digest: str) -> dict | None:
        row = self.db.execute(
            "SELECT verdict, signature, provider, checked_at FROM hashes WHERE sha256=?",
            (digest,)).fetchone()
        if not row:
            return None
        checked = time.mktime(time.strptime(row[3], "%Y-%m-%dT%H:%M:%S"))
        if time.time() - checked > self.ttl:
            return None
        self.cache_hits += 1
        return {"sha256": digest, "verdict": row[0], "signature": row[1],
                "provider": row[2], "source": "cache"}

    def _store(self, digest: str, verdict: str, signature: str, provider: str, raw=None):
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        self.db.execute(
            "INSERT INTO hashes(sha256, verdict, signature, provider, first_seen, checked_at, raw) "
            "VALUES(?,?,?,?,COALESCE((SELECT first_seen FROM hashes WHERE sha256=?),?),?,?) "
            "ON CONFLICT(sha256) DO UPDATE SET verdict=excluded.verdict, "
            "signature=excluded.signature, provider=excluded.provider, checked_at=excluded.checked_at",
            (digest, verdict, signature, provider, digest, now, now,
             json.dumps(raw, ensure_ascii=False) if raw else None))
        self.db.commit()

    # ------------------------------------------------------------ провайдеры
    def _query_local(self, digest: str) -> dict:
        item = self.local.get(digest)
        if item:
            return {"verdict": item["verdict"], "signature": item["signature"],
                    "provider": "local_reference_list"}
        return {"verdict": "unknown", "signature": "", "provider": "local_reference_list"}

    def _query_mb(self, digest: str) -> dict:
        if not self.auth_key:
            return {"verdict": "skipped", "signature": "",
                    "provider": "malwarebazaar", "note": "нет Auth-Key (MB_AUTH_KEY)"}
        if self.queries >= self.max_queries:
            return {"verdict": "skipped", "signature": "", "provider": "malwarebazaar",
                    "note": "достигнут лимит запросов за прогон"}
        wait = self.min_interval - (time.perf_counter() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        data = urllib.parse.urlencode({"query": "get_info", "hash": digest}).encode()
        req = urllib.request.Request(MB_ENDPOINT, data=data,
                                     headers={"Auth-Key": self.auth_key,
                                              "User-Agent": "LMA/2.1 (diploma research)"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            return {"verdict": "error", "signature": "", "provider": "malwarebazaar",
                    "note": str(exc)[:160]}
        finally:
            self._last_request = time.perf_counter()
            self.queries += 1
        status = payload.get("query_status")
        if status == "ok" and payload.get("data"):
            item = payload["data"][0]
            return {"verdict": "malicious", "signature": item.get("signature") or "n/a",
                    "provider": "malwarebazaar", "raw": item}
        if status in ("hash_not_found", "no_results"):
            return {"verdict": "not_found", "signature": "", "provider": "malwarebazaar"}
        return {"verdict": "error", "signature": "", "provider": "malwarebazaar",
                "note": str(status)}

    # ------------------------------------------------------------ публичный API
    def check(self, digest: str) -> dict:
        digest = (digest or "").lower()
        if len(digest) != 64:
            return {"sha256": digest, "verdict": "invalid", "provider": self.provider}
        cached = self._cached(digest)
        if cached:
            return cached
        res = self._query_mb(digest) if self.provider == "malwarebazaar" else self._query_local(digest)
        if res["verdict"] not in ("error", "skipped"):
            self._store(digest, res["verdict"], res.get("signature", ""),
                        res["provider"], res.get("raw"))
        return {"sha256": digest, "source": "query", **res}

    def check_many(self, digests: list[str]) -> list[dict]:
        seen, out = set(), []
        for d in digests:
            if not d or d in seen:
                continue
            seen.add(d)
            out.append(self.check(d))
        return out

    def stats(self) -> dict:
        rows = self.db.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
        return {"provider": self.provider, "cache_entries": rows,
                "cache_hits": self.cache_hits, "network_queries": self.queries,
                "local_reference_entries": len(self.local)}
