# -*- coding: utf-8 -*-
"""
ЛР 3 — Стеганографія (LSB) у зображенні PNG
Вимоги:
- Етап 1: Пояснення процесу (покроковий алгоритм) — у вигляді коментарів нижче
- Етап 2: Реалізація hide_message() та extract_message()
- Етап 3: Демонстрація на власних персональних даних (вводить користувач)
- Етап 4: Аналіз змін у зображенні (розмір, візуальні відмінності/метрики)

Покроковий алгоритм (Етап 1):
1) Перетворити повідомлення (UTF-8) у байти.
2) Записати довжину повідомлення в байтах у 32 біти (header).
3) Перетворити header + payload у суцільний бітовий потік.
4) Перевірити, що ємність зображення достатня:
   capacity_bits = width * height * 3 (по 1 біту в LSB кожного каналу RGB)
5) Пройти по пікселях та послідовно підмінити LSB у R, G, B на біти повідомлення.
6) Зберегти результат у PNG (без втрат).
7) Для витягування:
   - зчитати послідовно LSB усіх каналів у бітовий потік
   - прочитати перші 32 біти як довжину payload у байтах
   - зчитати наступні (length_bytes * 8) біт і відновити байти → текст UTF-8
"""

from __future__ import annotations

from PIL import Image
import os
import math
import argparse
from typing import Iterable, List, Tuple


# -------------------------
# Допоміжні функції бітів
# -------------------------

def _int_to_bits(value: int, bit_count: int) -> str:
    """Повертає двійковий рядок довжини bit_count."""
    if value < 0:
        raise ValueError("value має бути невід'ємним")
    if value >= (1 << bit_count):
        raise ValueError(f"value завелике для {bit_count} біт")
    return format(value, f"0{bit_count}b")


def _bytes_to_bits(data: bytes) -> str:
    """bytes -> '010101...'"""
    return ''.join(format(b, '08b') for b in data)


def _bits_to_bytes(bits: str) -> bytes:
    """'010101...' -> bytes (довжина bits має бути кратна 8)."""
    if len(bits) % 8 != 0:
        raise ValueError("Довжина bits повинна бути кратна 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        out.append(int(bits[i:i+8], 2))
    return bytes(out)


def _safe_open_rgb(image_path: str) -> Image.Image:
    """Відкриває зображення і приводить до RGB."""
    img = Image.open(image_path)
    if img.mode != "RGB":
        img = img.convert("RGB")
    return img


# -------------------------
# Етап 2: hide_message / extract_message
# -------------------------

def hide_message(image_path: str, message: str, output_path: str) -> None:
    """
    Ховає message у зображенні image_path методом LSB і зберігає у output_path (PNG).
    Формат даних:
      [32 біти довжини payload у байтах] + [payload bytes у бітах]
    """
    img = _safe_open_rgb(image_path)
    width, height = img.size
    pixels = list(img.getdata())

    payload_bytes = message.encode("utf-8")
    payload_len_bytes = len(payload_bytes)

    header_bits = _int_to_bits(payload_len_bytes, 32)
    payload_bits = _bytes_to_bits(payload_bytes)
    data_bits = header_bits + payload_bits
    data_len_bits = len(data_bits)

    capacity_bits = width * height * 3  # 1 LSB на канал
    if data_len_bits > capacity_bits:
        # скільки максимум байтів можна сховати з урахуванням 32-бітного заголовка
        max_payload_bits = capacity_bits - 32
        max_payload_bytes = max_payload_bits // 8 if max_payload_bits > 0 else 0
        raise ValueError(
            "Повідомлення занадто довге для цього зображення.\n"
            f"Ємність: {capacity_bits} біт.\n"
            f"Потрібно: {data_len_bits} біт.\n"
            f"Максимум payload: {max_payload_bytes} байт (UTF-8)."
        )

    new_pixels: List[Tuple[int, int, int]] = []
    bit_idx = 0

    for (r, g, b) in pixels:
        if bit_idx < data_len_bits:
            r = (r & 0xFE) | int(data_bits[bit_idx])
            bit_idx += 1
        if bit_idx < data_len_bits:
            g = (g & 0xFE) | int(data_bits[bit_idx])
            bit_idx += 1
        if bit_idx < data_len_bits:
            b = (b & 0xFE) | int(data_bits[bit_idx])
            bit_idx += 1

        new_pixels.append((r, g, b))

    out = Image.new("RGB", (width, height))
    out.putdata(new_pixels)

    # ВАЖЛИВО: PNG — щоб не було втрат (JPEG зруйнує LSB)
    out.save(output_path, format="PNG")

    print("✓ Приховування виконано успішно.")
    print(f"  Файл-джерело: {image_path}")
    print(f"  Файл-результат: {output_path}")
    print(f"  Розмір повідомлення: {payload_len_bytes} байт (UTF-8)")
    print(f"  Використано біт: {data_len_bits} з {capacity_bits}")


def extract_message(image_path: str) -> str:
    """
    Витягує повідомлення зі зображення image_path.
    Очікує формат:
      [32 біти довжини payload у байтах] + [payload bits]
    """
    img = _safe_open_rgb(image_path)
    pixels = list(img.getdata())

    # Збираємо LSB у потік. Спочатку потрібні 32 біти заголовка.
    bits_collected = []

    # 1) зчитати header (32 біти)
    needed = 32
    for (r, g, b) in pixels:
        if len(bits_collected) < needed:
            bits_collected.append(str(r & 1))
        if len(bits_collected) < needed:
            bits_collected.append(str(g & 1))
        if len(bits_collected) < needed:
            bits_collected.append(str(b & 1))
        if len(bits_collected) >= needed:
            break

    if len(bits_collected) < 32:
        return "Помилка: недостатньо даних навіть для заголовка."

    header_bits = ''.join(bits_collected[:32])
    payload_len_bytes = int(header_bits, 2)

    if payload_len_bytes == 0:
        return ""

    payload_len_bits = payload_len_bytes * 8

    # 2) зчитати payload
    payload_bits_list: List[str] = []

    # Продовжимо читати з початку зображення, але вже повністю —
    # простіше зібрати все і вирізати потрібне.
    all_bits = []
    for (r, g, b) in pixels:
        all_bits.append(str(r & 1))
        all_bits.append(str(g & 1))
        all_bits.append(str(b & 1))

    all_bits_str = ''.join(all_bits)

    start = 32
    end = 32 + payload_len_bits

    if end > len(all_bits_str):
        return "Помилка: у файлі заявлена довжина повідомлення більша за доступні біти."

    payload_bits = all_bits_str[start:end]
    payload_bytes = _bits_to_bytes(payload_bits)

    try:
        return payload_bytes.decode("utf-8")
    except UnicodeDecodeError:
        # якщо файл пошкоджений або не той формат
        return payload_bytes.decode("utf-8", errors="replace")


# -------------------------
# Етап 4: Аналіз змін
# -------------------------

def analyze_images(original_path: str, stego_path: str) -> None:
    """
    Аналізує:
    - розмір файлів (байти)
    - роздільну здатність
    - кількість змінених пікселів
    - MSE та PSNR
    Примітка: очікуємо однаковий розмір та RGB.
    """
    print("\n" + "=" * 60)
    print("АНАЛІЗ ЗОБРАЖЕНЬ (Етап 4)")
    print("=" * 60)

    orig = _safe_open_rgb(original_path)
    steg = _safe_open_rgb(stego_path)

    if orig.size != steg.size:
        print("✗ Помилка: різна роздільна здатність зображень.")
        print(f"  Original: {orig.size}")
        print(f"  Stego:    {steg.size}")
        return

    orig_size = os.path.getsize(original_path)
    steg_size = os.path.getsize(stego_path)

    print("Розмір файлів:")
    print(f"  Оригінал: {orig_size:,} байт")
    print(f"  Стего:    {steg_size:,} байт")
    print(f"  Різниця:  {steg_size - orig_size:,} байт")

    width, height = orig.size
    print(f"\nРоздільна здатність: {width} x {height}")

    orig_pixels = list(orig.getdata())
    steg_pixels = list(steg.getdata())

    changed_pixels = 0
    sum_sq = 0  # для MSE по каналах

    # рахуємо по всіх каналах (3 * N значень)
    for (o_r, o_g, o_b), (s_r, s_g, s_b) in zip(orig_pixels, steg_pixels):
        dr = o_r - s_r
        dg = o_g - s_g
        db = o_b - s_b

        if dr != 0 or dg != 0 or db != 0:
            changed_pixels += 1

        sum_sq += dr * dr + dg * dg + db * db

    total_pixels = width * height
    total_values = total_pixels * 3

    mse = sum_sq / total_values  # середня квадр. помилка на канал
    if mse == 0:
        psnr = float("inf")
    else:
        # MAX_I = 255 для 8-bit каналів
        psnr = 10 * math.log10((255 * 255) / mse)

    changed_percent = (changed_pixels / total_pixels) * 100

    print("\nВізуальні/числові відмінності:")
    print(f"  Змінено пікселів: {changed_pixels:,} з {total_pixels:,}")
    print(f"  Відсоток змінених: {changed_percent:.2f}%")
    print("  Максимальна зміна на канал (LSB): ±1")

    print("\nМетрики:")
    print(f"  MSE (на канал): {mse:.6f}")
    if psnr == float("inf"):
        print("  PSNR: нескінченність (зображення ідентичні)")
    else:
        print(f"  PSNR: {psnr:.2f} dB")

    print("=" * 60 + "\n")


# -------------------------
# Демонстрація (Етап 3)
# -------------------------

def create_demo_image(path: str, width: int = 800, height: int = 600) -> None:
    """
    Створює тестове RGB-зображення (градієнт), щоб було що шифрувати.
    """
    img = Image.new("RGB", (width, height))
    px = []
    for y in range(height):
        for x in range(width):
            r = (x * 255) // max(1, width - 1)
            g = (y * 255) // max(1, height - 1)
            b = (128 + (x + y) // 20) % 256
            px.append((r, g, b))
    img.putdata(px)
    img.save(path, format="PNG")


def build_personal_message() -> str:
    """
    Користувач вводить персональні дані (Етап 3).
    Нічого не хардкодимо.
    """
    print("\nВведи персональні дані для повідомлення (Етап 3).")
    full_name = input("ПІБ (або ім'я): ").strip()
    birth_date = input("Дата народження (наприклад, 20.12.2004): ").strip()
    group = input("Група (наприклад, КН-31): ").strip()

    # формуємо текст
    msg = (
        "Стеганографія — мистецтво приховування інформації!\n"
        "Метод: LSB (найменш значущий біт) у каналах RGB.\n\n"
        f"Персональні дані:\n"
        f"- ПІБ/ім'я: {full_name}\n"
        f"- Дата народження: {birth_date}\n"
        f"- Група: {group}\n"
    )
    return msg


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ЛР3: LSB-стеганографія (PIL). Ховання та витягування тексту з PNG."
    )
    parser.add_argument("--in", dest="input_image", help="Шлях до вхідного PNG (якщо не задано — створиться demo).")
    parser.add_argument("--out", dest="output_image", default="stego_image.png", help="Шлях до вихідного PNG.")
    parser.add_argument("--orig", dest="original_save", default="original_image.png",
                        help="Куди зберегти оригінал (коли створюємо demo).")
    parser.add_argument("--extract", dest="extract_only", action="store_true",
                        help="Тільки витягнути повідомлення з --in і вийти.")
    args = parser.parse_args()

    if args.extract_only:
        if not args.input_image:
            print("✗ Для --extract потрібно задати --in <image.png>")
            return
        text = extract_message(args.input_image)
        print("\nВИТЯГНУТЕ ПОВІДОМЛЕННЯ:")
        print("-" * 60)
        print(text)
        print("-" * 60)
        return

    # Якщо не дали вхідну картинку — робимо demo
    if not args.input_image:
        print("Вхідне зображення не задано — створюю demo-оригінал...")
        create_demo_image(args.original_save)
        input_image_path = args.original_save
    else:
        input_image_path = args.input_image

    secret_message = build_personal_message()

    print("\nПОВІДОМЛЕННЯ ДЛЯ ПРИХОВУВАННЯ:")
    print("-" * 60)
    print(secret_message)
    print("-" * 60)

    print("\nПриховування повідомлення...")
    hide_message(input_image_path, secret_message, args.output_image)

    print("\nВитягування повідомлення...")
    extracted = extract_message(args.output_image)
    print("-" * 60)
    print(extracted)
    print("-" * 60)

    if extracted == secret_message:
        print("✓ Перевірка: повідомлення витягнуто КОРЕКТНО.")
    else:
        print("⚠ Перевірка: витягнуте повідомлення ВІДРІЗНЯЄТЬСЯ від оригіналу.")

    analyze_images(input_image_path, args.output_image)


if __name__ == "__main__":
    main()