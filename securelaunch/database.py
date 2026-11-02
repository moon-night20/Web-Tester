import os
import re
import sqlite3
from pathlib import Path


DEFAULT_DB = Path(__file__).resolve().parent.parent / "securelaunch.sqlite3"


def connect():
    path = Path(os.environ.get("SECURELAUNCH_DB", str(DEFAULT_DB)))
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize():
    with connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                csrf_hash TEXT NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sites (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                domain TEXT NOT NULL,
                verification_token TEXT NOT NULL,
                verified_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, domain)
            );
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                target_url TEXT NOT NULL,
                status TEXT NOT NULL,
                error TEXT,
                started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                fingerprint TEXT NOT NULL,
                category TEXT NOT NULL,
                alert_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scans_site_started ON scans(site_id, started_at);
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            """
        )
        columns = {
            row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()
        }
        if "username" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN username TEXT")
        for user in db.execute(
            "SELECT id, email FROM users WHERE username IS NULL OR username = ''"
        ).fetchall():
            base = re.sub(r"[^a-z0-9._-]", "", user["email"].split("@", 1)[0].lower())
            if not re.match(r"[a-z0-9]", base):
                base = "user"
            base = base[:32]
            username = base
            suffix = str(user["id"])
            while db.execute(
                "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE AND id != ?",
                (username, user["id"]),
            ).fetchone():
                username = "{}-{}".format(base[: 32 - len(suffix) - 1], suffix)
            db.execute("UPDATE users SET username = ? WHERE id = ?", (username, user["id"]))
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username COLLATE NOCASE)"
        )
