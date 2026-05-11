import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config


ROOT = Path(__file__).resolve().parents[1]


def _cfg(db_file: Path) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_file}")
    return cfg


def test_upgrade_downgrade_roundtrip(tmp_path: Path):
    db = tmp_path / "mig.db"
    cfg = _cfg(db)

    command.upgrade(cfg, "head")
    with sqlite3.connect(db) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert {"users", "tokens", "generations", "orders", "templates", "favorites", "schedules"}.issubset(tables)

    command.downgrade(cfg, "base")
    with sqlite3.connect(db) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "users" not in tables


def test_pre_post_migration_compatibility(tmp_path: Path):
    db = tmp_path / "compat.db"
    with sqlite3.connect(db) as conn:
        conn.executescript(
            """
            CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'free', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE tokens (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(user_id) REFERENCES users(id));
            CREATE TABLE generations (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, created_at TEXT NOT NULL, payload_json TEXT NOT NULL, result_json TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
            CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, plan TEXT NOT NULL, amount INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL, paid_at TEXT, FOREIGN KEY(user_id) REFERENCES users(id));
            """
        )

    cfg = _cfg(db)
    command.stamp(cfg, "head")
    with sqlite3.connect(db) as conn:
        rev = conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        assert rev == "20260511_0001"


def test_indexes_exist(tmp_path: Path):
    db = tmp_path / "idx.db"
    cfg = _cfg(db)
    command.upgrade(cfg, "head")

    with sqlite3.connect(db) as conn:
        idx = {r[1] for r in conn.execute("PRAGMA index_list('generations')").fetchall()}
        assert "ix_generations_user_created_at" in idx
        idx = {r[1] for r in conn.execute("PRAGMA index_list('orders')").fetchall()}
        assert "ix_orders_status" in idx
        idx = {r[1] for r in conn.execute("PRAGMA index_list('schedules')").fetchall()}
        assert "ix_schedules_user_date" in idx
