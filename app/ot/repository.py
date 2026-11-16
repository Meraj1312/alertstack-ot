import hashlib
import json
from typing import Optional

from app.db.database import get_connection


def save_ot_event(raw_event: dict, normalized_event: dict) -> bool:
    """
    Store a normalized OT event alongside its original Suricata event.

    Returns True when inserted, False when already present.
    """

    raw_json = json.dumps(
        raw_event,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    event_id = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()

    source = normalized_event.get("source") or {}
    destination = normalized_event.get("destination") or {}
    alert = normalized_event.get("alert") or {}

    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR IGNORE INTO ot_events (
                id,
                timestamp,
                sensor,
                event_type,
                protocol,
                source_ip,
                source_port,
                destination_ip,
                destination_port,
                severity,
                raw_data,
                normalized_data
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                normalized_event.get("timestamp"),
                normalized_event.get("sensor", "unknown"),
                normalized_event.get("event_type", "unknown"),
                normalized_event.get("protocol"),
                source.get("ip"),
                source.get("port"),
                destination.get("ip"),
                destination.get("port"),
                alert.get("severity"),
                raw_json,
                json.dumps(normalized_event, default=str),
            ),
        )

        inserted = cursor.rowcount == 1
        conn.commit()

        return inserted

    finally:
        conn.close()


def fetch_ot_events(
    limit: int = 50,
    offset: int = 0,
    event_type: Optional[str] = None,
) -> list[dict]:
    """Retrieve recent OT events."""

    if limit < 1 or offset < 0:
        raise ValueError("limit must be positive and offset cannot be negative")

    conn = get_connection()

    try:
        cursor = conn.cursor()

        query = "SELECT * FROM ot_events WHERE 1=1"
        params = []

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        query += " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)

        events = []

        for row in cursor.fetchall():
            events.append({
                "event_id": row["id"],
                "timestamp": row["timestamp"],
                "sensor": row["sensor"],
                "event_type": row["event_type"],
                "protocol": row["protocol"],
                "source": {
                    "ip": row["source_ip"],
                    "port": row["source_port"],
                },
                "destination": {
                    "ip": row["destination_ip"],
                    "port": row["destination_port"],
                },
                "severity": row["severity"],
                "raw": json.loads(row["raw_data"]),
                "normalized": json.loads(row["normalized_data"]),
                "created_at": row["created_at"],
            })

        return events

    finally:
        conn.close()


def update_ot_event_normalized(event_id: str, normalized_event: dict) -> bool:
    """
    Update the normalized JSON for an existing OT event.

    Returns True when an event was updated, False when its ID was not found.
    """
    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE ot_events
            SET normalized_data = ?
            WHERE id = ?
            """,
            (
                json.dumps(normalized_event, sort_keys=True, default=str),
                event_id,
            ),
        )

        conn.commit()
        return cursor.rowcount == 1

    finally:
        conn.close()
