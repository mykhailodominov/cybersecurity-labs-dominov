# -*- coding: utf-8 -*-
"""
ЛР4 — Крок 2: Генерація демонстраційної пари ключів
Приватний ключ: SHA-256(ім'я + дата народження + секретне слово) -> int
Публічний ключ: g^(private_key mod (p-1)) mod p
Збереження у два JSON-файли.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path


DEFAULT_P = 2**61 - 1  # просте число Мерсенна (для демонстрації)
DEFAULT_G = 2          # "генератор" (демонстраційно)


@dataclass
class PrivateKeyData:
    name: str
    birth_date: str  # формат: DD.MM.YYYY
    secret_word: str
    private_key: str  # зберігаємо як рядок, бо число дуже велике


@dataclass
class PublicKeyData:
    p: str
    g: str
    public_key: str


def normalize_name(name: str) -> str:
    # прибираємо зайві пробіли, але не змінюємо регістр (щоб було прозоро для звіту)
    return " ".join(name.strip().split())


def validate_birth_date(birth_date: str) -> str:
    """
    Приймає дату у форматі DD.MM.YYYY.
    Якщо формат некоректний — кидає ValueError.
    """
    birth_date = birth_date.strip()
    datetime.strptime(birth_date, "%d.%m.%Y")  # перевірка формату
    return birth_date


def sha256_int(text: str) -> int:
    digest_hex = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return int(digest_hex, 16)


def generate_keys(name: str, birth_date: str, secret_word: str, p: int = DEFAULT_P, g: int = DEFAULT_G) -> tuple[int, int]:
    """
    Повертає (private_key_int, public_key_int)
    """
    base = f"{name}{birth_date}{secret_word}"
    private_key = sha256_int(base)
    exponent = private_key % (p - 1)  # зменшуємо показник (демонстраційно)
    public_key = pow(g, exponent, p)
    return private_key, public_key


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ЛР4 (Крок 2): генерація демонстраційної пари ключів")
    parser.add_argument("--name", type=str, help="Ім'я (наприклад: Dominov)")
    parser.add_argument("--birth-date", type=str, help="Дата народження у форматі DD.MM.YYYY (наприклад: 20.12.2004)")
    parser.add_argument("--secret", type=str, help="Секретне слово (наприклад: mysecret)")
    parser.add_argument("--p", type=int, default=DEFAULT_P, help="Модуль p (за замовчуванням 2^61-1)")
    parser.add_argument("--g", type=int, default=DEFAULT_G, help="Основа g (за замовчуванням 2)")
    parser.add_argument("--out-private", type=str, default="private_key.json", help="Файл для приватного ключа")
    parser.add_argument("--out-public", type=str, default="public_key.json", help="Файл для публічного ключа")
    return parser.parse_args()


def prompt_if_missing(args: argparse.Namespace) -> tuple[str, str, str]:
    name = args.name or input("Введіть ім'я: ").strip()
    birth_date = args.birth_date or input("Введіть дату народження (DD.MM.YYYY): ").strip()
    secret = args.secret or input("Введіть секретне слово: ").strip()

    name = normalize_name(name)
    birth_date = validate_birth_date(birth_date)

    if not secret:
        raise ValueError("Секретне слово не може бути порожнім.")

    return name, birth_date, secret


def main() -> None:
    args = get_args()
    try:
        name, birth_date, secret = prompt_if_missing(args)
        private_key_int, public_key_int = generate_keys(name, birth_date, secret, p=args.p, g=args.g)

        private_payload = PrivateKeyData(
            name=name,
            birth_date=birth_date,
            secret_word=secret,
            private_key=str(private_key_int),
        )

        public_payload = PublicKeyData(
            p=str(args.p),
            g=str(args.g),
            public_key=str(public_key_int),
        )

        out_private = Path(args.out_private)
        out_public = Path(args.out_public)

        write_json(out_private, asdict(private_payload))
        write_json(out_public, asdict(public_payload))

        print(f"Приватний ключ (int): {private_key_int}")
        print(f"Публічний ключ  (int): {public_key_int}")
        print(f"\nКлючі збережено у файли: {out_private} та {out_public}")

    except ValueError as e:
        print(f"Помилка введення/валидації: {e}")


if __name__ == "__main__":
    main()