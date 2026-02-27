import sqlite3
import os
from typing import List, Tuple

# Кольори для терміналу (працює в більшості терміналів)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


class StudentDatabaseDemo:
    def __init__(self, db_name: str = "students_demo.db"):
        self.db_name = db_name
        self._initialize_database()

    def _initialize_database(self):
        """Створює нову базу даних і наповнює її тестовими даними"""
        # Видаляємо стару базу, щоб завжди починати з чистого аркуша
        if os.path.exists(self.db_name):
            os.remove(self.db_name)

        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        # Створюємо таблицю студентів
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT,
                grade REAL,
                password TEXT NOT NULL
            )
        """)

        # Тестові дані (5 студентів)
        test_students = [
            ("Іван Петренко", "ivan@example.com", "+380501234567", 95.5, "pass123"),
            ("Марія Коваленко", "maria@example.com", "+380672345678", 88.0, "secret456"),
            ("Олександр Шевченко", "oleks@example.com", "+380933456789", 92.3, "qwerty789"),
            ("Катерина Бондаренко", "kate@example.com", "+380444567890", 97.8, "admin2024"),
            ("Дмитро Мельник", "dmytro@example.com", "+380505678901", 85.2, "12345678"),
        ]

        cursor.executemany(
            "INSERT INTO students (name, email, phone, grade, password) VALUES (?, ?, ?, ?, ?)",
            test_students
        )

        conn.commit()
        conn.close()
        print(f"{GREEN}[+] База даних '{self.db_name}' створена та заповнена 5 тестовими студентами.{RESET}\n")

    def _print_results(self, results: List[Tuple], title: str):
        """Гарний вивід результатів у вигляді таблиці"""
        if not results:
            print(f"{YELLOW}Записів не знайдено{RESET}")
            return

        print(f"{BLUE}{title}{RESET}")
        print("-" * 80)
        print(f"{'ID':<4} {'Ім’я':<20} {'Email':<25} {'Телефон':<15} {'Оцінка':<8}")
        print("-" * 80)
        for row in results:
            print(f"{row[0]:<4} {row[1]:<20} {row[2]:<25} {row[3]:<15} {row[4]:<8.1f}")
        print("-" * 80)
        print(f"Знайдено записів: {len(results)}\n")

    # ────────────────────────────────────────────────
    # УРАЗЛИВІ МЕТОДИ (SQL Injection можлива)
    # ────────────────────────────────────────────────

    def vulnerable_search(self, search_term: str):
        print(f"\n{GREEN}═══ УРАЗЛИВИЙ ПОШУК (без захисту) ═══{RESET}")
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        # УРАЗЛИВИЙ запит — конкатенація
        query = f"SELECT id, name, email, phone, grade FROM students WHERE name LIKE '%{search_term}%'"
        print(f"{YELLOW}[SQL] {query}{RESET}")

        try:
            cursor.execute(query)
            results = cursor.fetchall()
            self._print_results(results, "Результати уразливого пошуку:")
        except sqlite3.Error as e:
            print(f"{RED}[Помилка SQL] {e}{RESET}")
        finally:
            conn.close()

    def vulnerable_login(self, email: str, password: str):
        print(f"\n{GREEN}═══ УРАЗЛИВА АВТОРИЗАЦІЯ ═══{RESET}")
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        # УРАЗЛИВИЙ запит — конкатенація
        query = f"SELECT id, name, email FROM students WHERE email = '{email}' AND password = '{password}'"
        print(f"{YELLOW}[SQL] {query}{RESET}")

        try:
            cursor.execute(query)
            user = cursor.fetchone()
            if user:
                print(f"{GREEN}[УСПІХ] Авторизація пройшла!{RESET}")
                print(f"ID: {user[0]} | Ім'я: {user[1]} | Email: {user[2]}")
            else:
                print(f"{RED}[ПОМИЛКА] Невірний email або пароль{RESET}")
        except sqlite3.Error as e:
            print(f"{RED}[Помилка SQL] {e}{RESET}")
        finally:
            conn.close()

    # ────────────────────────────────────────────────
    # ЗАХИЩЕНІ МЕТОДИ (Prepared Statements)
    # ────────────────────────────────────────────────

    def secure_search(self, search_term: str):
        print(f"\n{BLUE}═══ ЗАХИЩЕНИЙ ПОШУК (з параметрами) ═══{RESET}")
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        query = "SELECT id, name, email, phone, grade FROM students WHERE name LIKE ?"
        param = f"%{search_term}%"
        print(f"{BLUE}[SQL] {query}{RESET}")
        print(f"{BLUE}[Параметр] {param!r}{RESET}")

        cursor.execute(query, (param,))
        results = cursor.fetchall()
        self._print_results(results, "Результати захищеного пошуку:")

        conn.close()

    def secure_login(self, email: str, password: str):
        print(f"\n{BLUE}═══ ЗАХИЩЕНА АВТОРИЗАЦІЯ ═══{RESET}")
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        query = "SELECT id, name, email FROM students WHERE email = ? AND password = ?"
        print(f"{BLUE}[SQL] {query}{RESET}")
        print(f"{BLUE}[Параметри] {email!r}, {password!r}{RESET}")

        cursor.execute(query, (email, password))
        user = cursor.fetchone()

        if user:
            print(f"{GREEN}[УСПІХ] Авторизація пройшла!{RESET}")
            print(f"ID: {user[0]} | Ім'я: {user[1]} | Email: {user[2]}")
        else:
            print(f"{RED}[ПОМИЛКА] Невірний email або пароль{RESET}")

        conn.close()


# ────────────────────────────────────────────────
# ІНТЕРФЕЙС КОРИСТУВАЧА
# ────────────────────────────────────────────────

def show_menu():
    print(f"\n{YELLOW}═══ ДЕМОНСТРАЦІЯ SQL-ІН'ЄКЦІЙ ═══{RESET}")
    print("1. Пошук студентів (звичайний)")
    print("2. Атака: витік всіх студентів (OR 1=1)")
    print("3. Авторизація (звичайна)")
    print("4. Атака: обхід авторизації")
    print("0. Вихід")
    print("═" * 40)


def main():
    demo = StudentDatabaseDemo()

    while True:
        show_menu()
        choice = input(f"{GREEN}Виберіть дію → {RESET}").strip()

        if choice == "1":
            term = input("Введіть частину імені для пошуку: ")
            demo.vulnerable_search(term)
            input("\nНатисніть Enter → ")
            demo.secure_search(term)

        elif choice == "2":
            injection = "' OR '1'='1"
            print(f"\n{YELLOW}Шкідливий ввід:{RESET} {injection}")
            demo.vulnerable_search(injection)
            input("\nНатисніть Enter → ")
            demo.secure_search(injection)

        elif choice == "3":
            email = input("Email: ")
            pwd = input("Пароль: ")
            demo.vulnerable_login(email, pwd)
            input("\nНатисніть Enter → ")
            demo.secure_login(email, pwd)

        elif choice == "4":
            injection_email = "ivan@example.com' OR '1'='1"
            fake_pwd = "будь-що"
            print(f"\n{YELLOW}Атака обходу:{RESET}")
            print(f"Email : {injection_email}")
            print(f"Пароль: {fake_pwd}")
            demo.vulnerable_login(injection_email, fake_pwd)
            input("\nНатисніть Enter → ")
            demo.secure_login(injection_email, fake_pwd)

        elif choice == "0":
            print(f"\n{GREEN}До побачення!{RESET}")
            break

        else:
            print(f"{RED}[!] Невірний вибір. Спробуйте ще раз.{RESET}")


if __name__ == "__main__":
    main()