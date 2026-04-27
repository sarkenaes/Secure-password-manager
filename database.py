"""SQLite database layer for encrypted vault entries."""

import sqlite3
from pathlib import Path
from typing import List, Tuple

from crypto_utils import decrypt_text, encrypt_text

DB_FILE = Path(__file__).resolve().parent / "vault.db"


def get_connection() -> sqlite3.Connection:
    return sqlite3.connect(DB_FILE)


def init_db() -> None:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                notes TEXT
            )
            """
        )
        conn.commit()


def add_entry(website: str, username: str, password: str, notes: str = "") -> None:
    encrypted_website = encrypt_text(website)
    encrypted_password = encrypt_text(password)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO vault_entries (website, username, password, notes)
            VALUES (?, ?, ?, ?)
            """,
            (encrypted_website, username, encrypted_password, notes),
        )
        conn.commit()


def view_entries() -> List[Tuple[int, str, str, str, str]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, website, username, password, notes FROM vault_entries ORDER BY id DESC")
        rows = cursor.fetchall()

    decrypted_entries = []
    for entry_id, encrypted_website, username, encrypted_password, notes in rows:
        decrypted_entries.append(
            (
                entry_id,
                decrypt_text(encrypted_website),
                username,
                decrypt_text(encrypted_password),
                notes or "",
            )
        )
    return decrypted_entries


def delete_entry(entry_id: int) -> None:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
        conn.commit()
