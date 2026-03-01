# steganography.py
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from PIL import Image


MAGIC = b"LSB1"  # 4 байти маркер
LEN_BYTES = 4    # довжина payload у байтах (uint32 big-endian)
HASH_BYTES = 32  # SHA-256(payload)


@dataclass
class EmbedInfo:
    capacity_bytes: int
    payload_bytes: int
    used_bytes_total: int


def _bytes_to_bits(data: bytes):
    for b in data:
        for i in range(7, -1, -1):
            yield (b >> i) & 1


def _bits_to_bytes(bits):
    out = bytearray()
    cur = 0
    cnt = 0
    for bit in bits:
        cur = (cur << 1) | (bit & 1)
        cnt += 1
        if cnt == 8:
            out.append(cur)
            cur = 0
            cnt = 0
    return bytes(out)


def _sha256(data: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(data)
    return h.digest()


def _max_payload_capacity_bytes(img: Image.Image) -> int:
    """
    Використовуємо 1 LSB на канал RGB => 3 біти на піксель.
    """
    if img.mode != "RGB":
        img = img.convert("RGB")
    w, h = img.size
    total_bits = w * h * 3
    total_bytes = total_bits // 8
    overhead = len(MAGIC) + LEN_BYTES + HASH_BYTES
    return max(0, total_bytes - overhead)


def embed_bytes_into_image(carrier_path: str | Path, payload: bytes, out_path: str | Path) -> EmbedInfo:
    img = Image.open(carrier_path)
    img = img.convert("RGB")

    capacity = _max_payload_capacity_bytes(img)
    if len(payload) > capacity:
        raise ValueError(
            f"Недостатня місткість зображення: capacity={capacity} bytes, payload={len(payload)} bytes. "
            f"Візьми більше зображення або менший файл."
        )

    length = len(payload).to_bytes(LEN_BYTES, "big")
    payload_hash = _sha256(payload)
    blob = MAGIC + length + payload_hash + payload

    bits = list(_bytes_to_bits(blob))

    pixels = list(img.getdata())
    new_pixels = []
    bit_idx = 0
    total_bits = len(bits)

    for (r, g, b) in pixels:
        if bit_idx < total_bits:
            r = (r & 0xFE) | bits[bit_idx]; bit_idx += 1
        if bit_idx < total_bits:
            g = (g & 0xFE) | bits[bit_idx]; bit_idx += 1
        if bit_idx < total_bits:
            b = (b & 0xFE) | bits[bit_idx]; bit_idx += 1
        new_pixels.append((r, g, b))

    out_img = Image.new("RGB", img.size)
    out_img.putdata(new_pixels)
    out_img.save(out_path)

    overhead = len(MAGIC) + LEN_BYTES + HASH_BYTES
    return EmbedInfo(
        capacity_bytes=capacity,
        payload_bytes=len(payload),
        used_bytes_total=overhead + len(payload),
    )


@dataclass
class ExtractResult:
    ok: bool
    payload: bytes
    error: str = ""


def extract_bytes_from_image(stego_path: str | Path) -> ExtractResult:
    img = Image.open(stego_path).convert("RGB")
    pixels = list(img.getdata())

    # Зчитуємо LSB-біти з усіх каналів
    bits = []
    for (r, g, b) in pixels:
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)

    # Спершу потрібні: MAGIC(4) + LEN(4) + HASH(32) => 40 байтів = 320 біт
    header_len_bytes = len(MAGIC) + LEN_BYTES + HASH_BYTES
    header_bits = bits[: header_len_bytes * 8]
    header = _bits_to_bytes(header_bits)

    if header[: len(MAGIC)] != MAGIC:
        return ExtractResult(ok=False, payload=b"", error="Маркер MAGIC не знайдено. Файл не містить LSB-контейнера.")

    length_bytes = header[len(MAGIC): len(MAGIC) + LEN_BYTES]
    payload_len = int.from_bytes(length_bytes, "big")
    stored_hash = header[len(MAGIC) + LEN_BYTES: header_len_bytes]

    total_needed_bits = (header_len_bytes + payload_len) * 8
    if total_needed_bits > len(bits):
        return ExtractResult(ok=False, payload=b"", error="Некоректна довжина payload або пошкоджене зображення.")

    payload_bits = bits[header_len_bytes * 8: total_needed_bits]
    payload = _bits_to_bytes(payload_bits)

    if _sha256(payload) != stored_hash:
        return ExtractResult(ok=False, payload=b"", error="Контрольна сума payload не співпала (дані пошкоджені).")

    return ExtractResult(ok=True, payload=payload, error="")