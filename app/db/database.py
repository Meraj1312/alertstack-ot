import os
import sqlite3
from pathlib import Path

DB_PATH = os.getenv(
    "ALERTSTACK_OT_DB_PATH",
    "data/alertstack.db",
)


def get_connection():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ot_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                sensor TEXT NOT NULL,
                event_type TEXT NOT NULL,
                protocol TEXT,
                source_ip TEXT,
                source_port INTEGER,
                destination_ip TEXT,
                destination_port INTEGER,
                severity INTEGER,
                raw_data TEXT NOT NULL,
                normalized_data TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ot_events_timestamp
            ON ot_events(timestamp)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ot_events_type
            ON ot_events(event_type)
        """)

        conn.commit()

    finally:
        conn.close()
