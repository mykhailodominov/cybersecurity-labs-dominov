# main.py
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from analytics import (
    Metrics,
    build_metrics,
    file_size_bytes,
    save_report_json,
    save_report_txt,
    sha256_file,
    sha256_bytes,
)
from encryption import encrypt_bytes, safe_decrypt_bytes
from steganography import embed_bytes_into_image, extract_bytes_from_image


def read_bytes(path: str | Path) -> bytes:
    return Path(path).read_bytes()


def write_bytes(path: str | Path, data: bytes) -> None:
    Path(path).write_bytes(data)


def ensure_parent(path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def protect(file_path: Path, carrier_image: Path, out_image: Path, seed: str, report_dir: Path) -> None:
    ensure_parent(out_image)
    ensure_parent(report_dir / "report.json")

    metrics: List[Dict[str, Any]] = []

    # Хеш оригіналу (для перевірки повного відновлення)
    sha_before = sha256_file(file_path)

    # 1) Encrypt
    t0 = datetime.now()
    import time
    start = time.perf_counter()
    plain = read_bytes(file_path)
    token, key_hint = encrypt_bytes(plain, seed)
    enc_duration = time.perf_counter() - start

    enc_tmp = report_dir / "ciphertext.bin"
    write_bytes(enc_tmp, token)

    m1 = build_metrics(
        operation="encrypt_file_fernet",
        input_path=str(file_path),
        output_path=str(enc_tmp),
        duration_seconds=enc_duration,
        extra={
            "key_derivation": "SHA-256(personal_seed) -> urlsafe_base64",
            "ciphertext_sha256": sha256_bytes(token),
        },
    )
    metrics.append(json.loads(json.dumps(m1, default=lambda o: o.__dict__)))

    # 2) Hide via LSB
    start = time.perf_counter()
    embed_info = embed_bytes_into_image(carrier_image, token, out_image)
    steg_duration = time.perf_counter() - start

    m2 = build_metrics(
        operation="lsb_hide_ciphertext_in_image",
        input_path=str(carrier_image),
        output_path=str(out_image),
        duration_seconds=steg_duration,
        extra={
            "payload_bytes": embed_info.payload_bytes,
            "capacity_bytes": embed_info.capacity_bytes,
            "used_total_bytes_in_stream": embed_info.used_bytes_total,
        },
    )
    metrics.append(json.loads(json.dumps(m2, default=lambda o: o.__dict__)))

    # Демонстрація: без дешифрування дані нечитабельні
    demo_note = (
        "Після LSB-вилучення отримуються зашифровані байти (Fernet token). "
        "Без правильного personal_seed файл відновити неможливо."
    )

    report = {
        "generated_at_local": datetime.now().isoformat(timespec="seconds"),
        "mode": "protect",
        "original_file": str(file_path),
        "carrier_image": str(carrier_image),
        "protected_image": str(out_image),
        "integrity": {
            "sha256_before": sha_before,
            "sha256_after": None,
            "status": "N/A (protect only)",
        },
        "metrics": metrics,
        "notes": {
            "both_stages_required": demo_note,
            "key_hint_base64_of_key": key_hint,  # НЕ ключ, а base64(base64(key)) для довідки (можна прибрати)
        },
    }

    save_report_json(report, report_dir / "report.json")
    save_report_txt(report, report_dir / "report.txt")

    print("✅ Захист завершено.")
    print(f" - Protected image: {out_image}")
    print(f" - Report: {report_dir / 'report.json'} / {report_dir / 'report.txt'}")


def restore(stego_image: Path, out_file: Path, seed: str, report_dir: Path) -> None:
    ensure_parent(out_file)
    ensure_parent(report_dir / "report.json")

    import time
    metrics: List[Dict[str, Any]] = []

    # 1) Extract ciphertext
    start = time.perf_counter()
    ex = extract_bytes_from_image(stego_image)
    extract_duration = time.perf_counter() - start

    if not ex.ok:
        print(f"❌ Не вдалося витягнути дані: {ex.error}")
        return

    cipher_tmp = report_dir / "ciphertext_extracted.bin"
    write_bytes(cipher_tmp, ex.payload)

    m1 = build_metrics(
        operation="lsb_extract_ciphertext_from_image",
        input_path=str(stego_image),
        output_path=str(cipher_tmp),
        duration_seconds=extract_duration,
        extra={"ciphertext_sha256": sha256_bytes(ex.payload)},
    )
    metrics.append(json.loads(json.dumps(m1, default=lambda o: o.__dict__)))

    # 2) Decrypt
    start = time.perf_counter()
    dec = safe_decrypt_bytes(ex.payload, seed)
    decrypt_duration = time.perf_counter() - start

    if not dec.ok:
        m2 = build_metrics(
            operation="decrypt_file_fernet",
            input_path=str(cipher_tmp),
            output_path=str(out_file),
            duration_seconds=decrypt_duration,
            extra={"status": "failed", "error": dec.error},
        )
        metrics.append(json.loads(json.dumps(m2, default=lambda o: o.__dict__)))

        report = {
            "generated_at_local": datetime.now().isoformat(timespec="seconds"),
            "mode": "restore",
            "protected_image": str(stego_image),
            "restored_file": str(out_file),
            "integrity": {
                "sha256_before": None,
                "sha256_after": None,
                "status": "FAILED (wrong key or corrupted data)",
            },
            "metrics": metrics,
            "notes": {"error": dec.error},
        }
        save_report_json(report, report_dir / "report.json")
        save_report_txt(report, report_dir / "report.txt")

        print(f"❌ Дешифрування не вдалося: {dec.error}")
        return

    write_bytes(out_file, dec.data)

    m2 = build_metrics(
        operation="decrypt_file_fernet",
        input_path=str(cipher_tmp),
        output_path=str(out_file),
        duration_seconds=decrypt_duration,
        extra={"status": "success"},
    )
    metrics.append(json.loads(json.dumps(m2, default=lambda o: o.__dict__)))

    # 3) Integrity check (sha256 of restored file)
    sha_after = sha256_file(out_file)

    report = {
        "generated_at_local": datetime.now().isoformat(timespec="seconds"),
        "mode": "restore",
        "protected_image": str(stego_image),
        "restored_file": str(out_file),
        "integrity": {
            "sha256_before": None,  # у відновленні може бути відома з попереднього звіту protect
            "sha256_after": sha_after,
            "status": "OK (file restored)" if len(dec.data) > 0 else "CHECK",
        },
        "metrics": metrics,
        "notes": {
            "both_stages_required": (
                "Без етапу LSB-вилучення немає ciphertext. Без етапу дешифрування ciphertext не перетвориться на файл."
            )
        },
    }

    save_report_json(report, report_dir / "report.json")
    save_report_txt(report, report_dir / "report.txt")

    print("✅ Відновлення завершено.")
    print(f" - Restored file: {out_file}")
    print(f" - Restored SHA-256: {sha_after}")
    print(f" - Report: {report_dir / 'report.json'} / {report_dir / 'report.txt'}")


def main():
    parser = argparse.ArgumentParser(
        description="ЛР7: Двоетапний захист файлу (Fernet + LSB) з аналітикою."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("protect", help="Зашифрувати файл і приховати у зображенні.")
    p1.add_argument("--file", required=True, type=Path, help="Шлях до файлу (наприклад resume.docx).")
    p1.add_argument("--carrier", required=True, type=Path, help="Зображення-контейнер (jpg/png).")
    p1.add_argument("--out-image", required=True, type=Path, help="Вихідне зображення зі схованими даними.")
    p1.add_argument("--seed", required=True, type=str, help="Персональні дані для генерації ключа (рядок).")
    p1.add_argument("--report-dir", default=Path("results/protect"), type=Path, help="Папка для звіту.")

    p2 = sub.add_parser("restore", help="Витягнути зображення, розшифрувати й відновити файл.")
    p2.add_argument("--stego", required=True, type=Path, help="Зображення зі схованими даними.")
    p2.add_argument("--out-file", required=True, type=Path, help="Куди зберегти відновлений файл.")
    p2.add_argument("--seed", required=True, type=str, help="Ті самі персональні дані (рядок).")
    p2.add_argument("--report-dir", default=Path("results/restore"), type=Path, help="Папка для звіту.")

    args = parser.parse_args()

    if args.cmd == "protect":
        protect(args.file, args.carrier, args.out_image, args.seed, args.report_dir)
    elif args.cmd == "restore":
        restore(args.stego, args.out_file, args.seed, args.report_dir)


if __name__ == "__main__":
    main()