import json

import pytest

from app.ot.ingestion.eve_reader import (
    INGEST_URL,
    deliver_event,
    parse_eve_line,
    process_line,
)


@pytest.fixture
def modbus_write_event():
    return {
        "timestamp": "2026-11-14T18:40:56.443500+0530",
        "event_type": "alert",
        "src_ip": "10.10.50.144",
        "src_port": 38290,
        "dest_ip": "10.10.50.1",
        "dest_port": 502,
        "proto": "TCP",
        "app_proto": "modbus",
        "alert": {
            "signature_id": 2250010,
            "signature": "OT Modbus write operation detected",
            "severity": 3,
        },
        "modbus": {
            "request": {
                "transaction_id": 1,
                "unit_id": 1,
                "function_raw": 6,
                "function_code": "WrSingleReg",
                "access_type": "WRITE | HOLDING | SINGLE | WRITE_SINGLE",
                "write": {
                    "address": 0,
                    "data": 123,
                },
            },
            "response": {
                "function_raw": 134,
                "function_code": "WrSingleReg",
                "exception": {
                    "raw": 2,
                    "code": "IllegalDataAddr",
                },
            },
        },
    }


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self.payload = payload

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, url, json):
        self.calls.append({
            "url": url,
            "json": json,
        })
        return self.response


# ----------------------------
# EVE JSON parsing
# ----------------------------

def test_parse_valid_eve_json(modbus_write_event):
    raw_line = json.dumps(modbus_write_event).encode()

    result = parse_eve_line(raw_line)

    assert result == modbus_write_event


def test_parse_eve_json_with_leading_null_bytes(modbus_write_event):
    raw_line = b"\x00\x00\x00" + json.dumps(
        modbus_write_event
    ).encode()

    result = parse_eve_line(raw_line)

    assert result == modbus_write_event


def test_parse_malformed_eve_json():
    assert parse_eve_line(b'{"event_type": "alert"') is None


@pytest.mark.parametrize(
    "raw_line",
    [
        b"[]",
        b'"hello"',
        b"123",
        b"true",
        b"null",
    ],
)
def test_parse_non_object_eve_records(raw_line):
    assert parse_eve_line(raw_line) is None


# ----------------------------
# Event filtering and normalization
# ----------------------------

def test_process_valid_modbus_write_alert(modbus_write_event):
    raw_line = json.dumps(modbus_write_event).encode()

    result = process_line(raw_line)

    assert result is not None
    assert result["sensor"] == "suricata"
    assert result["protocol"] == "modbus"
    assert result["event_type"] == "modbus_write_attempt"
    assert result["transaction"]["function_code"] == 6
    assert result["transaction"]["response_status"] == "exception"


def test_process_ignores_modbus_read_alert(modbus_write_event):
    modbus_write_event["modbus"]["request"]["function_raw"] = 3
    modbus_write_event["modbus"]["request"]["function_code"] = (
        "RdHoldingRegisters"
    )
    modbus_write_event["modbus"]["request"]["access_type"] = "READ"

    raw_line = json.dumps(modbus_write_event).encode()

    assert process_line(raw_line) is None


def test_process_ignores_non_modbus_alert(modbus_write_event):
    modbus_write_event["app_proto"] = "http"

    raw_line = json.dumps(modbus_write_event).encode()

    assert process_line(raw_line) is None


def test_process_ignores_non_alert_event(modbus_write_event):
    modbus_write_event["event_type"] = "flow"

    raw_line = json.dumps(modbus_write_event).encode()

    assert process_line(raw_line) is None


# ----------------------------
# HTTP delivery
# ----------------------------

@pytest.mark.parametrize(
    "api_status",
    ["stored", "duplicate", "ignored"],
)
def test_deliver_accepts_successful_api_statuses(
    modbus_write_event,
    api_status,
):
    client = FakeClient(
        FakeResponse(200, {"status": api_status})
    )

    result = deliver_event(client, modbus_write_event)

    assert result is True
    assert len(client.calls) == 1
    assert client.calls[0]["url"] == INGEST_URL
    assert client.calls[0]["json"] == modbus_write_event


def test_deliver_rejects_non_200_response(modbus_write_event):
    client = FakeClient(
        FakeResponse(500, {"detail": "Internal server error"})
    )

    result = deliver_event(client, modbus_write_event)

    assert result is False


def test_deliver_rejects_unexpected_status(modbus_write_event):
    client = FakeClient(
        FakeResponse(200, {"status": "unknown"})
    )

    result = deliver_event(client, modbus_write_event)

    assert result is False


@pytest.mark.parametrize(
    "payload",
    [
        [],
        ["stored"],
        "stored",
        123,
        None,
    ],
)
def test_deliver_rejects_non_object_api_response(
    modbus_write_event,
    payload,
):
    client = FakeClient(FakeResponse(200, payload))

    result = deliver_event(client, modbus_write_event)

    assert result is False


def test_deliver_handles_invalid_json_response(modbus_write_event):
    client = FakeClient(
        FakeResponse(200, ValueError("Invalid JSON"))
    )

    with pytest.raises(ValueError):
        deliver_event(client, modbus_write_event)
