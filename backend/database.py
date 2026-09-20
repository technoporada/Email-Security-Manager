"""SQLite database — scan history, blacklist, abuse reports."""
import sqlite3
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional
from config import DATABASE_URL


class Database:
    def __init__(self, db_path: str = "email_security.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_type TEXT NOT NULL,
                value TEXT NOT NULL UNIQUE,
                reason TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS abuse_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT NOT NULL,
                target TEXT NOT NULL,
                report_body TEXT NOT NULL,
                contacts TEXT NOT NULL,
                status TEXT DEFAULT 'draft',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type);
            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
            CREATE INDEX IF NOT EXISTS idx_blacklist_value ON blacklist(value);
        """)
        self.conn.commit()

    def save_scan(self, scan_type: str, target: str, result: Dict, risk_score: int = 0) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (scan_type, target, result, risk_score) VALUES (?, ?, ?, ?)",
            (scan_type, target, json.dumps(result), risk_score)
        )
        self.conn.commit()
        return cur.lastrowid

    def get_scans(self, scan_type: Optional[str] = None, limit: int = 50) -> List[Dict]:
        if scan_type:
            rows = self.conn.execute(
                "SELECT * FROM scans WHERE scan_type = ? ORDER BY created_at DESC LIMIT ?",
                (scan_type, limit)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def add_blacklist(self, entry_type: str, value: str, reason: str = "") -> bool:
        try:
            self.conn.execute(
                "INSERT INTO blacklist (entry_type, value, reason) VALUES (?, ?, ?)",
                (entry_type, value, reason)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def is_blacklisted(self, entry_type: str, value: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM blacklist WHERE entry_type = ? AND value = ?",
            (entry_type, value)
        ).fetchone()
        return row is not None

    def get_blacklist(self, entry_type: Optional[str] = None) -> List[Dict]:
        if entry_type:
            rows = self.conn.execute(
                "SELECT * FROM blacklist WHERE entry_type = ? ORDER BY added_at DESC",
                (entry_type,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM blacklist ORDER BY added_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def remove_blacklist(self, value: str) -> bool:
        cur = self.conn.execute("DELETE FROM blacklist WHERE value = ?", (value,))
        self.conn.commit()
        return cur.rowcount > 0

    def save_abuse_report(self, report_type: str, target: str, report_body: str, contacts: List[str]) -> int:
        cur = self.conn.execute(
            "INSERT INTO abuse_reports (report_type, target, report_body, contacts) VALUES (?, ?, ?, ?)",
            (report_type, target, report_body, json.dumps(contacts))
        )
        self.conn.commit()
        return cur.lastrowid

    def get_stats(self) -> Dict:
        total = self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        threats = self.conn.execute(
            "SELECT COUNT(*) FROM scans WHERE risk_score > 0"
        ).fetchone()[0]
        blacklisted = self.conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]
        reports = self.conn.execute("SELECT COUNT(*) FROM abuse_reports").fetchone()[0]

        return {
            "total_scans": total,
            "threats_found": threats,
            "blacklisted": blacklisted,
            "abuse_reports": reports,
        }
