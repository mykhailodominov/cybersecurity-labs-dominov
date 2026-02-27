import sqlite3


# ===============================================
# Демонстрація SQL-ін'єкції: уразливий vs безпечний код
# ===============================================

# Уразливий варіант — пряма конкатенація рядків (SQL Injection можлива)
def vulnerable_query(category):
    conn = sqlite3.connect(':memory:')  # використовуємо тимчасову БД в пам'яті
    cursor = conn.cursor()

    # Створюємо тестові таблиці та дані
    cursor.execute('''
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT)
    ''')
    cursor.execute("INSERT INTO products (name, category) VALUES ('Телефон', 'Tech')")
    cursor.execute("INSERT INTO products (name, category) VALUES ('Футболка', 'Clothing')")

    cursor.execute('''
        CREATE TABLE users (username TEXT, password TEXT)
    ''')
    cursor.execute("INSERT INTO users VALUES ('admin', 'secret123')")
    cursor.execute("INSERT INTO users VALUES ('user1', 'pass456')")

    conn.commit()

    # ❌ УРАЗЛИВИЙ КОД: конкатенація введення користувача
    query = f"SELECT * FROM products WHERE category = '{category}'"
    print(f"[УРАЗЛИВИЙ ЗАПИТ] Виконується: {query}")

    try:
        cursor.execute(query)
        results = cursor.fetchall()
        return results
    except sqlite3.Error as e:
        return f"Помилка: {e}"
    finally:
        conn.close()


# Безпечний варіант — використання параметризованого запиту
def safe_query(category):
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Ті самі тестові дані
    cursor.execute('CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT)')
    cursor.execute("INSERT INTO products (name, category) VALUES ('Телефон', 'Tech')")
    cursor.execute("INSERT INTO products (name, category) VALUES ('Футболка', 'Clothing')")

    cursor.execute('CREATE TABLE users (username TEXT, password TEXT)')
    cursor.execute("INSERT INTO users VALUES ('admin', 'secret123')")
    cursor.execute("INSERT INTO users VALUES ('user1', 'pass456')")

    conn.commit()

    # ✅ БЕЗПЕЧНИЙ КОД: плейсхолдер ?
    query = "SELECT * FROM products WHERE category = ?"
    print(f"[БЕЗПЕЧНИЙ ЗАПИТ] Виконується: {query} з параметром: {category!r}")

    cursor.execute(query, (category,))
    results = cursor.fetchall()
    conn.close()
    return results


# ===============================================
# Демонстрація атаки
# ===============================================

malicious_input = "' OR 1=1 --"  # класична атака на витяг всіх записів
union_attack = "' UNION SELECT username, password FROM users --"

print("═" * 70)
print("ДЕМОНСТРАЦІЯ АТАКИ НА УРАЗЛИВИЙ КОД")
print("═" * 70)

print("\nПриклад 1: класична атака OR 1=1")
results_vuln1 = vulnerable_query(malicious_input)
print("Результат:")
for row in results_vuln1:
    print(row)

print("\nПриклад 2: UNION-атака на витяг даних з іншої таблиці")
results_vuln2 = vulnerable_query(union_attack)
print("Результат:")
for row in results_vuln2:
    print(row)

print("\n" + "═" * 70)
print("ДЕМОНСТРАЦІЯ ТОГО Ж ВВОДУ НА БЕЗПЕЧНОМУ КОДІ")
print("═" * 70)

print("\nТой самий шкідливий ввід на безпечному запиті:")
results_safe1 = safe_query(malicious_input)
print("Результат (нічого не знайдено, бо шукаємо категорію з таким ім'ям):")
for row in results_safe1:
    print(row)

print("\nUNION-атака на безпечному запиті:")
results_safe2 = safe_query(union_attack)
print("Результат:")
for row in results_safe2:
    print(row)

print("\nВисновок:")
print("Уразливий код дозволяє виконати довільний SQL → витік даних, обхід авторизації тощо.")
print("Безпечний код (з ?) сприймає весь ввід як звичайний рядок → ін'єкція неможлива.")