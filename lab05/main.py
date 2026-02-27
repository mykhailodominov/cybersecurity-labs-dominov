# lr5_email_encryptor.py
# -*- coding: utf-8 -*-

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken


def derive_fernet_key(user_seed: str) -> bytes:
    """
    Генерує 32-байтовий ключ Fernet на основі персонального рядка (user_seed).
    Fernet вимагає ключ у форматі urlsafe base64 (32 байти до кодування).
    """
    if not user_seed or not user_seed.strip():
        raise ValueError("user_seed не може бути порожнім.")

    digest = hashlib.sha256(user_seed.encode("utf-8")).digest()  # 32 bytes
    return base64.urlsafe_b64encode(digest)


@dataclass
class EmailCipher:
    """
    Простий шифратор/дешифратор текстових повідомлень.
    Ключ формується з персональних даних (рядок user_seed).
    """
    user_seed: str

    def __post_init__(self) -> None:
        self._key: bytes = derive_fernet_key(self.user_seed)
        self._fernet: Fernet = Fernet(self._key)

    @property
    def key_fingerprint(self) -> str:
        """
        Короткий відбиток ключа для демонстрації (не секрет, але й не повний ключ).
        """
        return hashlib.sha256(self.user_seed.encode("utf-8")).hexdigest()[:32] + "..."

    def encrypt_text(self, plaintext: str) -> str:
        if plaintext is None:
            raise ValueError("plaintext не може бути None.")
        token = self._fernet.encrypt(plaintext.encode("utf-8"))
        return token.decode("utf-8")

    def decrypt_text(self, token: str) -> str:
        if token is None:
            raise ValueError("token не може бути None.")
        plaintext_bytes = self._fernet.decrypt(token.encode("utf-8"))
        return plaintext_bytes.decode("utf-8")


def demo_exchange() -> None:
    print("=== ЛР5: ДЕМОНСТРАЦІЯ ЗАХИЩЕНОГО ОБМІНУ ПОВІДОМЛЕННЯМИ ===\n")

    # Відправник (Alice)
    sender_email = "ivan.petrenko@gmail.com"
    sender_seed = "IvanPetrenko1995"
    sender = EmailCipher(sender_seed)

    print(f"Відправник: {sender_email}")
    print(f"Дані для генерації ключа: {sender_seed}")
    print(f"Відбиток (SHA-256, 32 символи): {sender.key_fingerprint}\n")

    # Повідомлення
    message = "Зустрічаємося завтра о 15:00"
    token = sender.encrypt_text(message)

    print(f"Оригінальне повідомлення: {message}")
    print(f"Зашифровані дані (Fernet token): {token}\n")

    # Отримувач (Bob) — має ті самі дані для формування ключа
    receiver_email = "maria.kovalenko@gmail.com"
    receiver_seed = "IvanPetrenko1995"
    receiver = EmailCipher(receiver_seed)

    print(f"Отримувач: {receiver_email}")
    print(f"Дані для генерації ключа: {receiver_seed}")
    print(f"Відбиток (SHA-256, 32 символи): {receiver.key_fingerprint}")

    decrypted = receiver.decrypt_text(token)
    print(f"Розшифроване повідомлення: {decrypted}\n")

    if decrypted == message:
        print("✓ Повідомлення успішно розшифровано (ключі збігаються).")
    else:
        print("✗ Результат не збігається з оригіналом (помилка).")

    # Демонстрація неправильного ключа
    print("\n=== СПРОБА РОЗШИФРУВАННЯ З НЕВІРНИМ КЛЮЧЕМ ===\n")
    attacker = EmailCipher("WrongKey123")

    try:
        attacker.decrypt_text(token)
        print("✗ Неочікувано: розшифрування вдалося (так не повинно бути).")
    except InvalidToken:
        print("✓ Очікувано: розшифрування неможливе без правильного ключа (InvalidToken).")


def main() -> None:
    demo_exchange()


if __name__ == "__main__":
    main()