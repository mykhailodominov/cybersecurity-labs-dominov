# -*- coding: utf-8 -*-
import hashlib
from dataclasses import dataclass
from pathlib import Path

MOD_PRIVATE = 1_000_000
MOD_PUBLIC = 1_000_007
PUBLIC_MULT = 7


@dataclass
class KeyPair:
    private_key: int
    public_key: int


class SimpleDigitalSignature:
    """
    Спрощена демонстраційна система цифрового підпису:
    - приватний ключ: SHA-256(прізвище + дата + секрет) % 1_000_000
    - публічний ключ: (private_key * 7) % 1_000_007
    - підпис: int(SHA-256(документ),16) XOR private_key
    - перевірка: (signature XOR private_key) == int(SHA-256(документ),16)
    """

    def __init__(self, surname: str, birthdate: str, secret: str):
        self.surname = self._normalize(surname)
        self.birthdate = birthdate.strip()
        self.secret = secret.strip()
        self.keys = self._generate_keys()

    @staticmethod
    def _normalize(text: str) -> str:
        # прибираємо зайві пробіли
        return " ".join(text.strip().split())

    def _generate_keys(self) -> KeyPair:
        seed = f"{self.surname}{self.birthdate}{self.secret}"
        private_key = self._sha256_int(seed) % MOD_PRIVATE
        public_key = (private_key * PUBLIC_MULT) % MOD_PUBLIC
        return KeyPair(private_key=private_key, public_key=public_key)

    @staticmethod
    def _sha256_int(data: str) -> int:
        return int(hashlib.sha256(data.encode("utf-8")).hexdigest(), 16)

    @staticmethod
    def file_sha256_hex(file_path: str | Path) -> str:
        """
        SHA-256 для файлу (читання поблоково).
        """
        path = Path(file_path)
        sha = hashlib.sha256()
        with path.open("rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()

    def sign_file(self, file_path: str | Path) -> int:
        """
        Підписує файл: signature = hash_int XOR private_key
        """
        doc_hash_hex = self.file_sha256_hex(file_path)
        hash_int = int(doc_hash_hex, 16)
        signature = hash_int ^ self.keys.private_key
        return signature

    def verify_file(self, file_path: str | Path, signature: int) -> bool:
        """
        Перевіряє підпис: (signature XOR private_key) == hash_int
        """
        doc_hash_hex = self.file_sha256_hex(file_path)
        hash_int = int(doc_hash_hex, 16)
        decrypted = signature ^ self.keys.private_key
        return decrypted == hash_int


def write_text_file(path: str | Path, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8")


def main():
    print("=== ГЕНЕРАЦІЯ КЛЮЧІВ ===")
    ds = SimpleDigitalSignature("Петренко", "15031995", "secret_word")
    print(f"Приватний ключ: {ds.keys.private_key}")
    print(f"Публічний ключ: {ds.keys.public_key}")

    # 1) створюємо документ-файл
    original_path = Path("resume_petrenko.txt")
    original_text = "Резюме Петренко Івана. Освіта: КПІ. Досвід: 5 років."
    write_text_file(original_path, original_text)

    print("\n=== ПІДПИСАННЯ ДОКУМЕНТУ (ФАЙЛ) ===")
    signature = ds.sign_file(original_path)
    print(f"Файл: {original_path}")
    print(f"Підпис (число): {signature}")

    # 2) перевірка справжнього підпису
    print("\n=== ПЕРЕВІРКА ДІЙСНОГО ПІДПИСУ ===")
    ok = ds.verify_file(original_path, signature)
    print(f"Результат: {'Підпис ДІЙСНИЙ' if ok else 'Підпис ПІДРОБЛЕНИЙ'}")

    # 3) підробка: змінюємо документ, але підпис залишаємо старий
    print("\n=== ПЕРЕВІРКА ПІДРОБЛЕНОГО ДОКУМЕНТУ ===")
    fake_path = Path("resume_petrenko_fake.txt")
    fake_text = "Резюме Петренко Івана. Освіта: КПІ. Досвід: 10 років."
    write_text_file(fake_path, fake_text)

    ok_fake_doc = ds.verify_file(fake_path, signature)
    print(f"Змінений файл: {fake_path}")
    print(f"Результат: {'Підпис ДІЙСНИЙ' if ok_fake_doc else 'Підпис ПІДРОБЛЕНИЙ'}")

    # 4) підробка: підпис змінено
    print("\n=== ПЕРЕВІРКА ПІДРОБЛЕНОГО ПІДПИСУ ===")
    fake_signature = signature + 12345
    ok_fake_sig = ds.verify_file(original_path, fake_signature)
    print("Оригінальний файл з підробленим підписом")
    print(f"Результат: {'Підпис ДІЙСНИЙ' if ok_fake_sig else 'Підпис ПІДРОБЛЕНИЙ'}")

    # (опційно) збережемо підпис у файл
    Path("signature.txt").write_text(str(signature), encoding="utf-8")
    print("\nПідпис збережено у файл signature.txt")


if __name__ == "__main__":
    main()