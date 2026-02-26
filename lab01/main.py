import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple


# Мінімальний список поширених слабких слів/патернів (можна розширювати)
WEAK_TOKENS = {
    "password", "pass", "passwd", "admin", "administrator", "qwerty",
    "abc", "abc123", "123456", "111111", "000000", "letmein",
    "welcome", "login", "monkey", "dragon",
    "пароль", "йцукен"
}

KEYBOARD_PATTERNS = ("qwerty", "asdf", "zxcv", "йцукен", "фыва", "ячсм")
ALPHA_SEQ = "abcdefghijklmnopqrstuvwxyz"
DIGIT_SEQ = "0123456789"


@dataclass
class PersonalData:
    name: str
    surname: str
    birthdate: Optional[datetime]


@dataclass
class Result:
    score: int                 # 1..10
    label: str                 # Слабкий/Середній/Сильний
    findings: List[str]        # що знайдено (проблеми/ризики)
    recommendations: List[str] # що зробити
    matches: List[str]         # що саме збіглось із персональними даними


def parse_birthdate(s: str) -> Optional[datetime]:
    s = s.strip()
    if not s:
        return None
    try:
        return datetime.strptime(s, "%d.%m.%Y")
    except ValueError:
        return None


def normalize(text: str) -> str:
    return re.sub(r"\s+", "", text.strip().lower())


def char_classes(password: str) -> Tuple[bool, bool, bool, bool]:
    has_upper = bool(re.search(r"[A-ZА-ЯІЇЄҐ]", password))
    has_lower = bool(re.search(r"[a-zа-яіїєґ]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};:'\",.<>?/\\|`~]", password))
    return has_upper, has_lower, has_digit, has_special


def has_long_repeats(password: str) -> bool:
    # 4+ однакових підряд: aaaa, 1111
    return re.search(r"(.)\1\1\1", password) is not None


def contains_sequence(pwd_norm: str, seq: str, length: int = 4) -> bool:
    if len(pwd_norm) < length:
        return False
    for i in range(len(seq) - length + 1):
        chunk = seq[i:i + length]
        if chunk in pwd_norm or chunk[::-1] in pwd_norm:
            return True
    return False


def personal_tokens(p: PersonalData) -> List[str]:
    tokens = []
    n = normalize(p.name)
    s = normalize(p.surname)
    if n:
        tokens.append(n)
    if s:
        tokens.append(s)

    if p.birthdate:
        dd = f"{p.birthdate.day:02d}"
        mm = f"{p.birthdate.month:02d}"
        yyyy = f"{p.birthdate.year:04d}"
        tokens.extend([
            dd, mm, yyyy,
            dd + mm,
            mm + yyyy,
            dd + mm + yyyy
        ])

    # Унікальні в порядку появи
    out = []
    for t in tokens:
        if t and t not in out:
            out.append(t)
    return out


def find_personal_matches(password: str, tokens: List[str]) -> List[str]:
    pwd_norm = normalize(password)
    matches = []
    for t in tokens:
        # для імені/прізвища: мінімум 3 символи
        if t.isdigit():
            if len(t) >= 2 and t in pwd_norm:
                matches.append(t)
        else:
            if len(t) >= 3 and t in pwd_norm:
                matches.append(t)
    return matches


def score_and_analyze(password: str, personal: PersonalData) -> Result:
    findings: List[str] = []
    recs: List[str] = []
    score = 10

    pwd_norm = normalize(password)

    # 1) Довжина
    L = len(password)
    if L < 8:
        score -= 4
        findings.append("Пароль занадто короткий: менше 8 символів.")
        recs.append("Зроби пароль мінімум 12 символів (краще 16+).")
    elif L < 12:
        score -= 2
        findings.append("Довжина 8–11 символів: нижче рекомендованої.")
        recs.append("Збільш довжину до 12–16+ символів.")

    # 2) Класи символів
    has_upper, has_lower, has_digit, has_special = char_classes(password)
    classes = sum([has_upper, has_lower, has_digit, has_special])

    if classes <= 1:
        score -= 3
        findings.append("Використаний лише один тип символів (низька різноманітність).")
        recs.append("Додай принаймні 3 типи символів: великі/малі, цифри, спецсимволи.")
    elif classes == 2:
        score -= 2
        findings.append("Недостатня різноманітність символів (лише 2 типи).")
        recs.append("Додай ще один тип символів (наприклад, спецсимволи).")
    elif classes == 3:
        score -= 1

    if not has_special:
        score -= 1
        findings.append("Немає спеціальних символів.")
        recs.append("Додай 1–2 спецсимволи: ! @ # $ % ^ & * _ - +")

    # 3) Перевірка персональних даних
    tokens = personal_tokens(personal)
    matches = find_personal_matches(password, tokens)
    if matches:
        # чим більше збігів — тим сильніший штраф
        penalty = min(5, 2 + len(matches))
        score -= penalty
        findings.append("Пароль містить фрагменти персональних даних.")
        recs.append("Прибери з пароля ім’я/прізвище/дату та будь-які їх частини.")

    # 4) Слабкі слова/словник
    # Перевіряємо як точний збіг, так і входження
    for w in WEAK_TOKENS:
        if w in pwd_norm:
            score -= 2
            findings.append(f"Виявлено поширений слабкий шаблон/слово: '{w}'.")
            recs.append("Уникай поширених слів (password/admin/qwerty/123456 тощо).")
            break

    # 5) Послідовності та клавіатурні патерни
    if contains_sequence(pwd_norm, DIGIT_SEQ, 4):
        score -= 2
        findings.append("Є проста числова послідовність (типу 1234).")
        recs.append("Не використовуй послідовності чисел (1234, 9876 тощо).")

    if contains_sequence(pwd_norm, ALPHA_SEQ, 4):
        score -= 2
        findings.append("Є проста буквена послідовність (типу abcd).")
        recs.append("Не використовуй послідовності літер (abcd, wxyz тощо).")

    for pat in KEYBOARD_PATTERNS:
        if pat in pwd_norm:
            score -= 2
            findings.append(f"Є клавіатурний патерн (типу '{pat}').")
            recs.append("Не використовуй клавіатурні патерни (qwerty/asdf/йцукен).")
            break

    # 6) Повтори
    if has_long_repeats(password):
        score -= 2
        findings.append("Є довгі повтори символів (типу aaaa або 1111).")
        recs.append("Прибери повтори (не роби 4+ однакових символів підряд).")

    # Нормалізація оцінки
    score = max(1, min(10, score))

    # Label
    if score >= 8:
        label = "Сильний"
    elif score >= 5:
        label = "Середній"
    else:
        label = "Слабкий"

    # Дедуп рекомендацій / findings
    def dedupe(items: List[str]) -> List[str]:
        out = []
        seen = set()
        for x in items:
            if x not in seen:
                out.append(x)
                seen.add(x)
        return out

    # Загальні рекомендації (додаємо завжди в кінці)
    recs.extend([
        "Використовуй унікальний пароль для кожного сервісу.",
        "Зберігай паролі в менеджері паролів (а не в нотатках).",
        "Увімкни 2FA (двохфакторну автентифікацію), де можливо."
    ])

    return Result(
        score=score,
        label=label,
        findings=dedupe(findings),
        recommendations=dedupe(recs),
        matches=matches
    )


def main() -> None:
    print("=== Аналізатор безпеки паролів (ЛР1) ===")
    print("Примітка: дані не зберігаються, аналіз відбувається лише під час запуску.\n")

    password = input("Введіть пароль: ").strip()
    name = input("Введіть ім'я: ").strip()
    surname = input("Введіть прізвище: ").strip()
    birth_raw = input("Введіть дату народження (ДД.ММ.РРРР): ").strip()

    bdate = parse_birthdate(birth_raw)
    if birth_raw and bdate is None:
        print("⚠️ Дату не розпізнано. Використай формат ДД.ММ.РРРР (наприклад, 15.03.1995).")
        print("   Аналіз продовжиться без урахування дати народження.\n")

    personal = PersonalData(name=name, surname=surname, birthdate=bdate)

    result = score_and_analyze(password, personal)

    print("\n" + "=" * 60)
    print(f"Оцінка безпеки: {result.score}/10")
    print(f"Рівень: {result.label}")
    print("=" * 60)

    if result.matches:
        print("\nЗбіги з персональними даними у паролі:")
        for m in result.matches:
            print(f" - {m}")

    if result.findings:
        print("\nВиявлені ризики/проблеми:")
        for i, item in enumerate(result.findings, 1):
            print(f"{i}. {item}")
    else:
        print("\n✓ Критичних проблем не виявлено за заданими критеріями.")

    print("\nРекомендації:")
    for i, rec in enumerate(result.recommendations, 1):
        print(f"{i}. {rec}")

    print("\nГотово.")


if __name__ == "__main__":
    main()