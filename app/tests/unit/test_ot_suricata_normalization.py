from app.ot.normalization.suricata import (
    decode_register_data,
    normalize_suricata_event,
)


def test_normalize_rejected_modbus_write():
    event = {
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

    result = normalize_suricata_event(event)

    assert result is not None
    assert result["event_type"] == "modbus_write_attempt"
    assert result["protocol"] == "modbus"
    assert result["source"]["ip"] == "10.10.50.144"
    assert result["destination"]["ip"] == "10.10.50.1"

    transaction = result["transaction"]
    assert transaction["function_code"] == 6
    assert transaction["operation"] == "write_single_register"
    assert transaction["register_address"] == 0
    assert transaction["requested_value"] == 123
    assert transaction["response_status"] == "exception"
    assert transaction["exception_code"] == 2
    assert transaction["exception_name"] == "IllegalDataAddr"


def test_ignore_non_modbus_event():
    event = {
        "event_type": "alert",
        "app_proto": "http",
    }

    assert normalize_suricata_event(event) is None


def test_ignore_non_alert_event():
    event = {
        "event_type": "flow",
        "app_proto": "modbus",
    }

    assert normalize_suricata_event(event) is None

def test_normalize_write_using_function_name_fallback():
    event = {
        "event_type": "alert",
        "app_proto": "modbus",
        "modbus": {
            "request": {
                "transaction_id": 2,
                "unit_id": 1,
                "function_code": "WrSingleReg",
                "access_type": "WRITE",
            },
            "response": {},
        },
    }

    result = normalize_suricata_event(event)

    assert result is not None
    assert result["transaction"]["operation"] == "write_single_register"

def test_normalize_modbus_write_with_response():
    event = {
        "event_type": "alert",
        "app_proto": "modbus",
        "modbus": {
            "request": {
                "transaction_id": 3,
                "unit_id": 1,
                "function_raw": 6,
                "function_code": "WrSingleReg",
                "access_type": "WRITE",
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

    result = normalize_suricata_event(event)

    assert result is not None
    assert result["transaction"]["response_status"] == "response_received"
    assert result["transaction"]["operation"] == "write_single_register"
    assert result["transaction"]["register_address"] == 10
    assert result["transaction"]["requested_value"] == 250
    assert "exception_code" not in result["transaction"]

def test_ignore_modbus_read_operation():
    event = {
        "event_type": "alert",
        "app_proto": "modbus",
        "modbus": {
            "request": {
                "transaction_id": 4,
                "unit_id": 1,
                "function_raw": 3,
                "function_code": "RdHoldingRegisters",
                "access_type": "READ | HOLDING",
            },
            "response": {},
        },
    }

    assert normalize_suricata_event(event) is None

def test_normalize_modbus_write_multiple_registers():
    event = {
        "event_type": "alert",
        "app_proto": "modbus",
        "modbus": {
            "request": {
                "transaction_id": 5,
                "unit_id": 1,
                "function_raw": 16,
                "function_code": "WrMultRegs",
                "access_type": "WRITE | HOLDING | MULTIPLE",
                "write": {
                    "address": 0,
                    "quantity": 2,
                    "data": "\x00{\x01\\xc8",
                },
            },
            "response": {
                "exception": {
                    "raw": 2,
                    "code": "IllegalDataAddr",
                },
            },
        },
    }

    result = normalize_suricata_event(event)

    assert result is not None

    transaction = result["transaction"]
    assert transaction["operation"] == "write_multiple_registers"
    assert transaction["register_address"] == 0
    assert transaction["register_count"] == 2
    assert transaction["register_values"] == [123, 456]
    assert transaction["response_status"] == "exception"



def test_decode_register_data_valid_bytes():
    assert decode_register_data(bytes([0x00, 0x7B, 0x01, 0xC8])) == [123, 456]


def test_decode_register_data_odd_length():
    assert decode_register_data(b"\x00\x7B\x01") is None


def test_decode_register_data_invalid_escape():
    assert decode_register_data(r"\x0G") is None


def test_decode_register_data_unsupported_type():
    assert decode_register_data(123) is None


def test_fc16_rejects_register_count_mismatch():
    event = {
        "event_type": "alert",
        "app_proto": "modbus",
        "modbus": {
            "request": {
                "transaction_id": 6,
                "unit_id": 1,
                "function_raw": 16,
                "function_code": "WrMultRegs",
                "access_type": "WRITE | HOLDING | MULTIPLE",
                "write": {
                    "address": 0,
                    "quantity": 3,
                    "data": "\x00{\x01\\xc8",
                },
            },
            "response": {
                "exception": {
                    "raw": 2,
                    "code": "IllegalDataAddr",
                },
            },
        },
    }

    result = normalize_suricata_event(event)

    assert result is not None

    transaction = result["transaction"]
    assert transaction["register_count"] == 3
    assert transaction["register_values"] is None
    assert transaction["register_data"] == "\x00{\x01\\xc8"


def test_ignore_modbus_function_code_23():
    event = {
        "event_type": "alert",
        "app_proto": "modbus",
        "modbus": {
            "request": {
                "transaction_id": 7,
                "unit_id": 1,
                "function_raw": 23,
                "function_code": "ReadWriteMultipleRegs",
                "access_type": "READ | WRITE",
            },
            "response": {},
        },
    }

    assert normalize_suricata_event(event) is None


def test_ignore_unknown_function_with_write_access():
    event = {
        "event_type": "alert",
        "app_proto": "modbus",
        "modbus": {
            "request": {
                "transaction_id": 8,
                "unit_id": 1,
                "function_raw": 99,
                "function_code": "Unknown",
                "access_type": "WRITE",
            },
            "response": {},
        },
    }

    assert normalize_suricata_event(event) is None


def test_fc16_preserves_quantity_without_data():
    event = {
        "event_type": "alert",
        "app_proto": "modbus",
        "modbus": {
            "request": {
                "transaction_id": 9,
                "unit_id": 1,
                "function_raw": 16,
                "function_code": "WrMultRegs",
                "access_type": "WRITE | HOLDING | MULTIPLE",
                "write": {
                    "address": 10,
                    "quantity": 3,
                },
            },
            "response": {},
        },
    }

    result = normalize_suricata_event(event)

    assert result is not None

    transaction = result["transaction"]
    assert transaction["register_address"] == 10
    assert transaction["register_count"] == 3
    assert "register_data" not in transaction
    assert "register_values" not in transaction
