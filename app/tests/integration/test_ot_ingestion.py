import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

import app.db.database as database
from app.main import app
from app.ot.repository import fetch_ot_events


@pytest.fixture
def ot_client(tmp_path, monkeypatch):
    test_db = tmp_path / "test_ot_api.db"

    monkeypatch.setattr(database, "DB_PATH", str(test_db))

    with TestClient(app) as client:
        yield client


def sample_modbus_event():
    return {
        "timestamp": "2026-11-15T10:00:00+05:30",
        "event_type": "alert",
        "src_ip": "10.10.50.144",
        "src_port": 38290,
        "dest_ip": "10.10.50.1",
        "dest_port": 502,
        "proto": "TCP",
        "app_proto": "modbus",
        "alert": {
            "signature_id": 2250011,
            "signature": "OT Modbus Write Single Register (FC6)",
            "severity": 3,
        },
        "modbus": {
            "request": {
                "transaction_id": 1,
                "unit_id": 1,
                "function_raw": 6,
                "function_code": "WrSingleReg",
                "write": {
                    "address": 10,
                    "data": 250,
                },
            },
            "response": {
                "function_raw": 6,
                "function_code": "WrSingleReg",
            },
        },
    }


def test_ot_ingestion_stores_modbus_write(ot_client):
    event = sample_modbus_event()

    response = ot_client.post("/ot/ingest", json=event)

    assert response.status_code == 200
    assert response.json()["status"] == "stored"
    assert response.json()["event_type"] == "modbus_write_attempt"
    assert response.json()["protocol"] == "modbus"

    stored_events = fetch_ot_events()

    assert len(stored_events) == 1
    assert stored_events[0]["normalized"]["transaction"]["function_code"] == 6


def test_ot_ingestion_rejects_duplicate(ot_client):
    event = sample_modbus_event()

    first = ot_client.post("/ot/ingest", json=event)
    second = ot_client.post("/ot/ingest", json=event)

    assert first.json()["status"] == "stored"
    assert second.json()["status"] == "duplicate"
    assert len(fetch_ot_events()) == 1


def test_ot_ingestion_ignores_unsupported_event(ot_client):
    event = {
        "event_type": "alert",
        "app_proto": "http",
    }

    response = ot_client.post("/ot/ingest", json=event)

    assert response.status_code == 200
    assert response.json()["status"] == "ignored"
    assert len(fetch_ot_events()) == 0


def test_ot_ingestion_rejects_missing_timestamp(ot_client):
    event = sample_modbus_event()
    event.pop("timestamp")

    response = ot_client.post("/ot/ingest", json=event)

    assert response.status_code == 422
    assert len(fetch_ot_events()) == 0


def test_ot_ingestion_persists_risk_and_correlation(ot_client):
    response = ot_client.post("/ot/ingest", json=sample_modbus_event())

    assert response.status_code == 200
    assert response.json()["status"] == "stored"

    analysis = response.json()["analysis"]
    assert analysis["observation_count"] == 1
    assert analysis["transaction_count"] == 1
    assert analysis["analyzed_event_count"] == 1

    stored = fetch_ot_events()[0]["normalized"]

    assert stored["risk"]["score"] == 30
    assert stored["risk"]["severity"] == "low"
    assert stored["correlation"]["repeated_activity"] is False


def test_three_distinct_writes_trigger_repeated_activity(ot_client):
    for transaction_id in (1, 2, 3):
        event = sample_modbus_event()
        event["timestamp"] = (
            f"2026-11-15T10:00:{transaction_id * 7:02d}+05:30"
        )
        event["modbus"]["request"]["transaction_id"] = transaction_id

        response = ot_client.post("/ot/ingest", json=event)
        assert response.status_code == 200
        assert response.json()["status"] == "stored"

    result = response.json()["analysis"]

    assert result["observation_count"] == 3
    assert result["transaction_count"] == 3
    assert result["repeated_activity_group_count"] == 1
    assert result["analyzed_event_count"] == 3

    stored_events = fetch_ot_events(limit=10)

    assert len(stored_events) == 3

    for stored in stored_events:
        normalized = stored["normalized"]

        assert normalized["correlation"]["repeated_activity"] is True
        assert normalized["risk"]["score"] == 45
        assert normalized["risk"]["severity"] == "low"


def test_duplicate_ingestion_does_not_create_an_extra_observation(ot_client):
    event = sample_modbus_event()

    first = ot_client.post("/ot/ingest", json=event)
    second = ot_client.post("/ot/ingest", json=event)

    assert first.json()["status"] == "stored"
    assert second.json()["status"] == "duplicate"

    assert len(fetch_ot_events()) == 1
    assert fetch_ot_events()[0]["normalized"]["risk"]["score"] == 30


def sample_zeek_event(timestamp="1794760243.292520"):
    return {
        "schema_version": "1.0",
        "sensor": "zeek",
        "event_category": "ot",
        "event_type": "modbus_write_attempt",
        "timestamp": timestamp,
        "source": {"ip": "10.10.50.144", "port": 38290},
        "destination": {"ip": "10.10.50.1", "port": 502},
        "protocol": "modbus",
        "transport": "TCP",
        "transaction": {
            "id": 1,
            "function_code": 6,
            "function_name": "WRITE_SINGLE_REGISTER",
            "operation": "write_single_register",
            "unit_id": 1,
            "connection_uid": "zeek-connection-1",
            "response_status": "response_received",
        },
    }


def test_zeek_ingestion_stores_normalized_modbus_write(ot_client):
    response = ot_client.post("/ot/ingest", json=sample_zeek_event())

    assert response.status_code == 200
    assert response.json()["status"] == "stored"
    assert response.json()["event_type"] == "modbus_write_attempt"

    stored = fetch_ot_events()[0]["normalized"]
    assert stored["sensor"] == "zeek"
    assert stored["transaction"]["function_code"] == 6
    assert stored["risk"]["score"] == 30


def test_zeek_ingestion_rejects_duplicate(ot_client):
    event = sample_zeek_event()

    first = ot_client.post("/ot/ingest", json=event)
    second = ot_client.post("/ot/ingest", json=event)

    assert first.json()["status"] == "stored"
    assert second.json()["status"] == "duplicate"
    assert len(fetch_ot_events()) == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda event: event.update(sensor="unknown"),
        lambda event: event.update(protocol="http"),
        lambda event: event["transaction"].update(function_code=3),
        lambda event: event["transaction"].update(response_status="invalid"),
        lambda event: event.update(timestamp=None),
    ],
)
def test_zeek_ingestion_rejects_invalid_event(ot_client, mutate):
    event = sample_zeek_event()
    mutate(event)

    response = ot_client.post("/ot/ingest", json=event)

    assert response.status_code == 422
    assert len(fetch_ot_events()) == 0


def test_zeek_ingestion_ignores_non_write_event(ot_client):
    event = sample_zeek_event()
    event["event_type"] = "modbus_read_attempt"

    response = ot_client.post("/ot/ingest", json=event)

    assert response.status_code == 200
    assert response.json()["status"] == "ignored"
    assert len(fetch_ot_events()) == 0


def test_suricata_and_zeek_observations_correlate_as_one_transaction(
    ot_client,
):
    epoch_timestamp = "1794760243.292520"

    suricata_timestamp = datetime.fromtimestamp(
        float(epoch_timestamp), timezone.utc
    ).isoformat()

    suricata_event = sample_modbus_event()
    suricata_event["timestamp"] = suricata_timestamp

    zeek_event = sample_zeek_event(timestamp=epoch_timestamp)

    suricata_response = ot_client.post(
        "/ot/ingest", json=suricata_event
    )
    zeek_response = ot_client.post("/ot/ingest", json=zeek_event)

    assert suricata_response.status_code == 200
    assert zeek_response.status_code == 200
    assert suricata_response.json()["status"] == "stored"
    assert zeek_response.json()["status"] == "stored"

    analysis = zeek_response.json()["analysis"]

    assert analysis["observation_count"] == 2
    assert analysis["transaction_count"] == 1
    assert analysis["duplicate_group_count"] == 1
    assert analysis["analyzed_event_count"] == 2

    stored_events = fetch_ot_events(limit=10)
    assert len(stored_events) == 2

    assert {
        stored["normalized"]["correlation"]["is_duplicate_observation"]
        for stored in stored_events
    } == {False, True}
