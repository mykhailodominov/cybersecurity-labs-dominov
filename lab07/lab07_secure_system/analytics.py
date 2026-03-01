# analytics.py
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Optional


def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def file_size_bytes(path: str | Path) -> int:
    return Path(path).stat().st_size


def percent_change(before: int, after: int) -> float:
    if before == 0:
        return 0.0
    return ((after - before) / before) * 100.0


@dataclass
class Metrics:
    operation: str
    input_path: str
    output_path: str
    input_size_bytes: int
    output_size_bytes: int
    size_change_percent: float
    duration_seconds: float
    extra: Dict[str, Any]


def measure(operation: str, input_path: str, output_path: str):
    """
    Декоратор-помічник для вимірювання часу й розміру.
    Використання:
        with measure(...) as m:
            ... do work ...
            m["extra"]["key"]=...
    """
    class _Ctx:
        def __init__(self):
            self.t0 = 0.0
            self.extra: Dict[str, Any] = {}

        def __enter__(self):
            self.t0 = time.perf_counter()
            return {"extra": self.extra}

        def __exit__(self, exc_type, exc, tb):
            self.t1 = time.perf_counter()

    return _Ctx()


def build_metrics(
    operation: str,
    input_path: str,
    output_path: str,
    duration_seconds: float,
    extra: Optional[Dict[str, Any]] = None,
) -> Metrics:
    inp = file_size_bytes(input_path) if Path(input_path).exists() else 0
    out = file_size_bytes(output_path) if Path(output_path).exists() else 0
    return Metrics(
        operation=operation,
        input_path=str(input_path),
        output_path=str(output_path),
        input_size_bytes=inp,
        output_size_bytes=out,
        size_change_percent=percent_change(inp, out),
        duration_seconds=duration_seconds,
        extra=extra or {},
    )


def save_report_json(report: Dict[str, Any], path: str | Path) -> None:
    Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def save_report_txt(report: Dict[str, Any], path: str | Path) -> None:
    """
    Проста людиночитна версія звіту.
    """
    lines = []
    lines.append("ЗВІТ: Двоетапний захист з аналітикою (ЛР №7)")
    lines.append("")
    lines.append(f"Дата/час (локально): {report.get('generated_at_local')}")
    lines.append(f"Оригінальний файл: {report.get('original_file')}")
    lines.append(f"Контейнер-зображення: {report.get('carrier_image')}")
    lines.append(f"Результуюче зображення: {report.get('protected_image')}")
    lines.append("")

    integ = report.get("integrity", {})
    lines.append("Перевірка цілісності:")
    lines.append(f" - SHA-256 оригіналу (до):  {integ.get('sha256_before')}")
    lines.append(f" - SHA-256 оригіналу (після): {integ.get('sha256_after')}")
    lines.append(f" - Результат: {integ.get('status')}")
    lines.append("")

    lines.append("Метрики операцій:")
    for m in report.get("metrics", []):
        lines.append(f" * {m['operation']}: {m['duration_seconds']:.6f} c")
        lines.append(f"   - input:  {m['input_size_bytes']} bytes ({m['input_path']})")
        lines.append(f"   - output: {m['output_size_bytes']} bytes ({m['output_path']})")
        lines.append(f"   - size Δ: {m['size_change_percent']:.2f}%")
        if m.get("extra"):
            lines.append(f"   - extra: {m['extra']}")
        lines.append("")

    lines.append("Примітка: для доступу до даних потрібні обидва етапи: вилучення з LSB + дешифрування.")
    Path(path).write_text("\n".join(lines), encoding="utf-8")