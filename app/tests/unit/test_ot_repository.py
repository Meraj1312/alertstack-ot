import pytest

import app.db.database as database
from app.ot.repository import save_ot_event, fetch_ot_events


@pytest.fixture
def ot_db(tmp_path, monkeypatch):
    test_db = tmp_path / "test_ot.db"

    monkeypatch.setattr(database, "DB_PATH", str(test_db))
    database.init_db()


def sample_events():
    raw_event = {
        "timestamp": "2026-11-15T10:00:00+05:30",
        "event_type": "alert",
        "src_ip": "10.10.50.144",
        "dest_ip": "10.10.50.1",
    }

    normalized_event = {
        "schema_version": "1.0",
        "sensor": "suricata",
        "event_category": "ot",
        "event_type": "modbus_write_attempt",
        "timestamp": "2026-11-15T10:00:00+05:30",
        "protocol": "modbus",
        "source": {
            "ip": "10.10.50.144",
            "port": 38290,
        },
        "destination": {
            "ip": "10.10.50.1",
            "port": 502,
        },
        "alert": {
            "severity": 3,
        },
        "transaction": {
            "function_code": 6,
            "operation": "write_single_register",
        },
    }

    return raw_event, normalized_event


def test_save_and_fetch_ot_event(ot_db):
    raw_event, normalized_event = sample_events()

    inserted = save_ot_event(raw_event, normalized_event)

    assert inserted is True

    events = fetch_ot_events()

    assert len(events) == 1
    assert events[0]["event_type"] == "modbus_write_attempt"
    assert events[0]["protocol"] == "modbus"
    assert events[0]["source"]["ip"] == "10.10.50.144"
    assert events[0]["destination"]["port"] == 502
    assert events[0]["severity"] == 3
    assert events[0]["raw"] == raw_event
    assert events[0]["normalized"] == normalized_event


def test_duplicate_ot_event_is_ignored(ot_db):
    raw_event, normalized_event = sample_events()

    first_insert = save_ot_event(raw_event, normalized_event)
    second_insert = save_ot_event(raw_event, normalized_event)

    assert first_insert is True
    assert second_insert is False
    assert len(fetch_ot_events()) == 1


def test_fetch_ot_events_filters_by_event_type(ot_db):
    raw_event, normalized_event = sample_events()

    save_ot_event(raw_event, normalized_event)

    another_raw = {
        **raw_event,
        "timestamp": "2026-11-15T10:01:00+05:30",
    }

    another_normalized = {
        **normalized_event,
        "timestamp": "2026-11-15T10:01:00+05:30",
        "event_type": "modbus_reconnaissance",
    }

    save_ot_event(another_raw, another_normalized)

    write_events = fetch_ot_events(
        event_type="modbus_write_attempt"
    )

    recon_events = fetch_ot_events(
        event_type="modbus_reconnaissance"
    )

    assert len(write_events) == 1
    assert len(recon_events) == 1
    assert write_events[0]["event_type"] == "modbus_write_attempt"
    assert recon_events[0]["event_type"] == "modbus_reconnaissance"


def test_update_ot_event_normalized(ot_db):
    from app.ot.repository import update_ot_event_normalized

    raw_event, normalized_event = sample_events()
    assert save_ot_event(raw_event, normalized_event) is True

    stored = fetch_ot_events()[0]
    event_id = stored["event_id"]

    enriched = {
        **normalized_event,
        "risk": {
            "score_version": "1.0",
            "score": 45,
            "severity": "low",
            "reasons": [],
        },
        "correlation": {
            "repeated_activity": True,
            "is_duplicate_observation": False,
            "duplicate_group_id": None,
        },
    }

    assert update_ot_event_normalized(event_id, enriched) is True

    updated = fetch_ot_events()[0]

    assert len(fetch_ot_events()) == 1
    assert updated["normalized"]["risk"]["score"] == 45
    assert updated["normalized"]["correlation"]["repeated_activity"] is True

    assert update_ot_event_normalized("nonexistent-event", enriched) is False
