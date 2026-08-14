import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash


DATABASE = "passwords.db"


def create_database():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_password(password):

    password_hash = generate_password_hash(password)

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO password_history (password_hash) VALUES (?)",
        (password_hash,)
    )

    connection.commit()
    connection.close()


def is_password_reused(password):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        "SELECT password_hash FROM password_history"
    )

    stored_hashes = cursor.fetchall()

    connection.close()

    for stored_hash in stored_hashes:

        if check_password_hash(stored_hash[0], password):
            return True

    return False