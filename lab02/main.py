from dataclasses import dataclass
from typing import Dict, List


# 33 літери української абетки (нормативний порядок)
UA_ALPHABET = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
UA_SET = set(UA_ALPHABET)


def sum_digits(value: str) -> int:
    """Повертає суму всіх цифр у рядку (беремо лише цифри)."""
    total = 0
    for ch in value:
        if ch.isdigit():
            total += int(ch)
    return total


def validate_ua_key(key: str) -> str:
    """
    Перевіряє, що ключ містить лише українські літери.
    Повертає ключ у верхньому регістрі.
    """
    key_up = key.strip().upper()
    if not key_up:
        raise ValueError("Ключ не може бути порожнім.")
    if not all(ch in UA_SET for ch in key_up):
        raise ValueError("Ключ має містити лише українські літери (без пробілів, дефісів, латинки, цифр).")
    return key_up


class CaesarCipher:
    """Шифр Цезаря для української абетки."""
    def __init__(self, shift: int, alphabet: str = UA_ALPHABET):
        self.alphabet = alphabet
        self.n = len(alphabet)
        self.shift_raw = shift
        self.shift = shift % self.n  # нормалізований зсув 0..32
        self.pos: Dict[str, int] = {ch: i for i, ch in enumerate(alphabet)}

    def encrypt(self, text: str) -> str:
        return self._transform(text, self.shift)

    def decrypt(self, text: str) -> str:
        return self._transform(text, -self.shift)

    def _transform(self, text: str, shift: int) -> str:
        res = []
        for ch in text:
            up = ch.upper()
            if up in self.pos:
                old_i = self.pos[up]
                new_i = (old_i + shift) % self.n
                new_ch = self.alphabet[new_i]
                # зберігаємо регістр
                if ch.islower():
                    new_ch = new_ch.lower()
                res.append(new_ch)
            else:
                res.append(ch)
        return "".join(res)


class UkrainianVigenereCipher:
    """Шифр Віженера для української абетки (33 літери)."""
    def __init__(self, key: str, alphabet: str = UA_ALPHABET):
        self.alphabet = alphabet
        self.n = len(alphabet)
        self.pos: Dict[str, int] = {ch: i for i, ch in enumerate(alphabet)}
        self.key = validate_ua_key(key)

    def encrypt(self, text: str) -> str:
        return self._process(text, mode="encrypt")

    def decrypt(self, text: str) -> str:
        return self._process(text, mode="decrypt")

    def _process(self, text: str, mode: str) -> str:
        res = []
        k = 0  # індекс ключа збільшується лише коли шифруємо літеру

        for ch in text:
            up = ch.upper()
            if up in self.pos:
                t_i = self.pos[up]
                k_ch = self.key[k % len(self.key)]
                k_i = self.pos[k_ch]

                if mode == "encrypt":
                    new_i = (t_i + k_i) % self.n
                else:
                    new_i = (t_i - k_i) % self.n

                new_ch = self.alphabet[new_i]
                if ch.islower():
                    new_ch = new_ch.lower()

                res.append(new_ch)
                k += 1
            else:
                res.append(ch)

        return "".join(res)


@dataclass
class CipherReport:
    name: str
    key_info: str
    encrypted: str
    decrypted: str
    length: int
    unique_nonspace: int
    letter_share: float  # частка літер алфавіту серед непорожніх символів (0..1)


def compute_metrics(encrypted: str, alphabet_set: set) -> Dict[str, float]:
    """
    Метрики:
    - unique_nonspace: унікальні символи без пробілів і тире
    - letter_share: частка літер (з алфавіту) серед усіх символів, крім пробілу
    """
    cleaned = encrypted.replace(" ", "").replace("–", "").replace("—", "")
    unique_nonspace = len(set(cleaned))

    total = 0
    letters = 0
    for ch in encrypted:
        if ch == " ":
            continue
        total += 1
        if ch.upper() in alphabet_set:
            letters += 1

    letter_share = (letters / total) if total else 0.0
    return {"unique_nonspace": unique_nonspace, "letter_share": letter_share}


def make_report(name: str, key_info: str, original: str, encrypted: str, decrypted: str) -> CipherReport:
    m = compute_metrics(encrypted, UA_SET)
    return CipherReport(
        name=name,
        key_info=key_info,
        encrypted=encrypted,
        decrypted=decrypted,
        length=len(encrypted),
        unique_nonspace=int(m["unique_nonspace"]),
        letter_share=float(m["letter_share"]),
    )


def print_report(original: str, rep: CipherReport) -> None:
    print("\n" + "=" * 70)
    print(f"Алгоритм: {rep.name}")
    print("=" * 70)
    print(f"Ключ: {rep.key_info}")
    print(f"\nОригінал:     {original}")
    print(f"Зашифровано:  {rep.encrypted}")
    print(f"Розшифровано: {rep.decrypted}")

    print("\nМетрики:")
    print(f"- Довжина результату: {rep.length} символів")
    print(f"- Унікальних (без пробілів/тире): {rep.unique_nonspace}")
    print(f"- Частка літер (без пробілів): {rep.letter_share:.3f}")


def print_comparison(a: CipherReport, b: CipherReport) -> None:
    print("\n" + "=" * 70)
    print("ПОРІВНЯЛЬНА ТАБЛИЦЯ")
    print("=" * 70)

    header = f"{'Параметр':<28} | {a.name:<18} | {b.name:<18}"
    print(header)
    print("-" * len(header))

    def row(label: str, v1: str, v2: str) -> None:
        print(f"{label:<28} | {v1:<18} | {v2:<18}")

    row("Тип ключа", a.key_info, b.key_info)
    row("Довжина шифротексту", str(a.length), str(b.length))
    row("Унікальні символи", str(a.unique_nonspace), str(b.unique_nonspace))
    row("Частка літер", f"{a.letter_share:.3f}", f"{b.letter_share:.3f}")

    print("\n" + "=" * 70)
    print("ВИСНОВКИ")
    print("=" * 70)
    print("1) Шифр Цезаря:")
    print("   - Простий ключ: один параметр (зсув).")
    print("   - Низька стійкість: перебір усіх зсувів по алфавіту (0..32).")
    print("   - Зберігає частоти літер → можливий частотний аналіз.")
    print("2) Шифр Віженера:")
    print("   - Ключ — слово/рядок, зсув змінюється для кожної літери.")
    print("   - Стійкість вища, залежить від довжини ключа.")
    print("3) Загальний висновок:")
    print("   - Обидва шифри є класичними та застосовуються переважно в навчальних цілях.")


def main() -> None:
    print("=" * 70)
    print("ЛР2: Порівняння класичних шифрів (Цезар + Віженер)")
    print("=" * 70)

    # --- Ввід користувача ---
    name = input("Введіть ім'я (для виводу, не використовується як ключ): ").strip()
    surname = input("Введіть прізвище (ключ Віженера, укр. літерами): ").strip()
    birth_date = input("Введіть дату народження (наприклад 15.03.2003): ").strip()

    # --- Перевірки ---
    try:
        vigenere_key = validate_ua_key(surname)
    except ValueError as e:
        print(f"\nПомилка ключа Віженера: {e}")
        return

    shift_raw = sum_digits(birth_date)
    caesar_shift = shift_raw % len(UA_ALPHABET)

    print("\nПерсональні дані:")
    print(f"- Ім'я: {name if name else '(не вказано)'}")
    print(f"- Прізвище (ключ Віженера): {vigenere_key}")
    print(f"- Дата народження: {birth_date}")
    print(f"\nГенерація ключа Цезаря:")
    print(f"- Сума цифр дати: {shift_raw}")
    print(f"- Нормалізація: {shift_raw} mod {len(UA_ALPHABET)} = {caesar_shift}")

    # --- Текст для тесту ---
    test_text = "Захист інформації – важлива дисципліна"
    print(f"\nТестовий текст:\n{test_text}")

    # --- Цезар ---
    caesar = CaesarCipher(shift_raw)
    caesar_key_info = f"зсув = {caesar.shift} (сума цифр дати = {shift_raw}, mod {len(UA_ALPHABET)})"
    c_enc = caesar.encrypt(test_text)
    c_dec = caesar.decrypt(c_enc)
    rep_caesar = make_report("Шифр Цезаря", caesar_key_info, test_text, c_enc, c_dec)
    print_report(test_text, rep_caesar)

    # --- Віженер ---
    vigenere = UkrainianVigenereCipher(vigenere_key)
    vigenere_key_info = f"ключ = '{vigenere.key}' (прізвище)"
    v_enc = vigenere.encrypt(test_text)
    v_dec = vigenere.decrypt(v_enc)
    rep_vigenere = make_report("Шифр Віженера", vigenere_key_info, test_text, v_enc, v_dec)
    print_report(test_text, rep_vigenere)

    # --- Порівняння + висновки ---
    print_comparison(rep_caesar, rep_vigenere)


if __name__ == "__main__":
    main()