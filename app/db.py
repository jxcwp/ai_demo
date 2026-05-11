import os
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_URL = f"sqlite:///{BASE_DIR / 'mvp.db'}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DB_URL)
APP_ENV = os.getenv("APP_ENV", "dev")


def _sqlite_path_from_url(url: str) -> Path:
    if not url.startswith("sqlite:///"):
        raise RuntimeError("This app runtime currently supports sqlite connections directly; use Alembic migrations for non-sqlite backends.")
    return Path(url.replace("sqlite:///", "", 1))


def get_conn() -> sqlite3.Connection:
    db_path = _sqlite_path_from_url(DATABASE_URL)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Development fallback only.

    In production, schema must be managed via Alembic migrations.
    """
    if APP_ENV == "prod":
        with get_conn() as conn:
            try:
                conn.execute("SELECT 1 FROM users LIMIT 1")
            except sqlite3.OperationalError as exc:
                raise RuntimeError("Database schema missing in production. Run Alembic migrations before startup.") from exc
        return

    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                plan TEXT NOT NULL DEFAULT 'free',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS generations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan TEXT NOT NULL,
                amount INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                paid_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS favorites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                generation_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(generation_id) REFERENCES generations(id)
            );

            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                theme TEXT NOT NULL,
                time TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE INDEX IF NOT EXISTS ix_generations_user_created_at ON generations(user_id, created_at);
            CREATE INDEX IF NOT EXISTS ix_orders_status ON orders(status);
            CREATE INDEX IF NOT EXISTS ix_schedules_user_date ON schedules(user_id, date);
            """
        )
