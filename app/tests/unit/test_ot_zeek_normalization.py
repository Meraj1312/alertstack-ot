import pytest

from app.ot.normalization.zeek import parse_zeek_tsv


TAB = "\t"

SAMPLE_LOG = (
    "#separator \\x09\n"
    "#set_separator ,\n"
    "#empty_field (empty)\n"
    "#unset_field -\n"
    "#path modbus\n"
    "#open 2026-11-15-09-05-48\n"
    "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p "
    "tid unit func pdu_type exception\n"
    "#types time string addr port addr port count count string string string\n"
    + TAB.join([
        "1794713693.304187",
        "CnfjbO2pWjJ08tT6o9",
        "10.10.50.144",
        "58438",
        "10.10.50.1",
        "502",
        "1",
        "2",
        "WRITE_SINGLE_REGISTER",
        "REQ",
        "-",
    ]) + "\n"
    + TAB.join([
        "1794713693.305016",
        "CnfjbO2pWjJ08tT6o9",
        "10.10.50.144",
        "58438",
        "10.10.50.1",
        "502",
        "1",
        "2",
        "WRITE_SINGLE_REGISTER",
        "RESP",
        "-",
    ]) + "\n"
)


def test_parse_zeek_tsv_records():
    records = parse_zeek_tsv(SAMPLE_LOG)

    assert len(records) == 2
    assert records[0]["func"] == "WRITE_SINGLE_REGISTER"
    assert records[0]["pdu_type"] == "REQ"
    assert records[1]["pdu_type"] == "RESP"


def test_unset_field_becomes_none():
    records = parse_zeek_tsv(SAMPLE_LOG)

    assert records[0]["exception"] is None


def test_preserves_non_unset_values_as_strings():
    records = parse_zeek_tsv(SAMPLE_LOG)

    assert records[0]["tid"] == "1"
    assert records[0]["id.orig_p"] == "58438"


def test_custom_unset_marker():
    log = (
        "#separator \\x09\n"
        "#unset_field N/A\n"
        "#fields ts exception\n"
        + TAB.join(["123.45", "N/A"]) + "\n"
    )

    records = parse_zeek_tsv(log)

    assert records[0]["exception"] is None


def test_rejects_data_before_fields():
    log = "#separator \\x09\n123.45 value\n"

    with pytest.raises(ValueError, match="before #fields"):
        parse_zeek_tsv(log)


def test_rejects_field_count_mismatch():
    log = (
        "#separator \\x09\n"
        "#fields ts uid\n"
        "123.45\n"
    )

    with pytest.raises(ValueError, match="Field count mismatch"):
        parse_zeek_tsv(log)


def test_rejects_non_string_input():
    with pytest.raises(TypeError, match="must be a string"):
        parse_zeek_tsv(None)


from app.ot.normalization.zeek import normalize_zeek_modbus_log


def make_zeek_log(records):
    header = (
        "#separator \\x09\n"
        "#unset_field -\n"
        "#path modbus\n"
        "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p "
        "tid unit func pdu_type exception\n"
        "#types time string addr port addr port count count "
        "string string string\n"
    )

    return header + "".join(TAB.join(record) + "\n" for record in records)


def make_record(
    *,
    tid="1",
    uid="connection-1",
    function="WRITE_SINGLE_REGISTER",
    pdu_type="REQ",
    exception="-",
):
    return [
        "1794713693.304187",
        uid,
        "10.10.50.144",
        "58438",
        "10.10.50.1",
        "502",
        tid,
        "2",
        function,
        pdu_type,
        exception,
    ]


def test_normalize_zeek_modbus_fc6_write_with_response():
    content = make_zeek_log([
        make_record(),
        make_record(pdu_type="RESP"),
        make_record(tid="2", function="READ_HOLDING_REGISTERS"),
        make_record(
            tid="2",
            function="READ_HOLDING_REGISTERS",
            pdu_type="RESP",
        ),
    ])

    events = normalize_zeek_modbus_log(content)

    assert len(events) == 1

    event = events[0]
    transaction = event["transaction"]

    assert event["sensor"] == "zeek"
    assert event["event_type"] == "modbus_write_attempt"
    assert event["protocol"] == "modbus"
    assert event["transport"] == "TCP"
    assert event["source"] == {
        "ip": "10.10.50.144",
        "port": 58438,
    }
    assert event["destination"] == {
        "ip": "10.10.50.1",
        "port": 502,
    }
    assert transaction["id"] == 1
    assert transaction["function_code"] == 6
    assert transaction["operation"] == "write_single_register"
    assert transaction["unit_id"] == 2
    assert transaction["connection_uid"] == "connection-1"
    assert transaction["response_status"] == "response_received"
    assert "register_address" not in transaction
    assert "requested_value" not in transaction


def test_normalize_zeek_fc16_write():
    content = make_zeek_log([
        make_record(function="WRITE_MULTIPLE_REGISTERS"),
        make_record(function="WRITE_MULTIPLE_REGISTERS", pdu_type="RESP"),
    ])

    events = normalize_zeek_modbus_log(content)

    assert len(events) == 1
    assert events[0]["transaction"]["function_code"] == 16
    assert events[0]["transaction"]["operation"] == "write_multiple_registers"
    assert events[0]["transaction"]["response_status"] == "response_received"


def test_normalize_zeek_exception_response():
    content = make_zeek_log([
        make_record(),
        make_record(pdu_type="RESP", exception="ILLEGAL_FUNCTION"),
    ])

    events = normalize_zeek_modbus_log(content)

    assert len(events) == 1
    transaction = events[0]["transaction"]

    assert transaction["response_status"] == "exception"
    assert transaction["exception_name"] == "ILLEGAL_FUNCTION"


def test_normalize_zeek_missing_response():
    content = make_zeek_log([
        make_record(),
    ])

    events = normalize_zeek_modbus_log(content)

    assert len(events) == 1
    assert events[0]["transaction"]["response_status"] == "unknown"


def test_normalize_zeek_ignores_read_operations():
    content = make_zeek_log([
        make_record(function="READ_HOLDING_REGISTERS"),
        make_record(
            function="READ_HOLDING_REGISTERS",
            pdu_type="RESP",
        ),
    ])

    assert normalize_zeek_modbus_log(content) == []


def test_normalize_zeek_ignores_unsupported_functions():
    content = make_zeek_log([
        make_record(function="DIAGNOSTICS"),
        make_record(function="DIAGNOSTICS", pdu_type="RESP"),
    ])

    assert normalize_zeek_modbus_log(content) == []


def test_normalize_zeek_correlates_using_uid_and_tid():
    content = make_zeek_log([
        make_record(uid="connection-1", tid="1"),
        make_record(uid="connection-2", tid="1"),
        make_record(
            uid="connection-2",
            tid="1",
            pdu_type="RESP",
            exception="ILLEGAL_FUNCTION",
        ),
    ])

    events = normalize_zeek_modbus_log(content)

    assert len(events) == 2

    statuses = {
        event["transaction"]["connection_uid"]:
        event["transaction"]["response_status"]
        for event in events
    }

    assert statuses == {
        "connection-1": "unknown",
        "connection-2": "exception",
    }


def test_normalize_zeek_maps_all_supported_write_functions():
    functions = {
        "WRITE_SINGLE_COIL": (5, "write_single_coil"),
        "WRITE_SINGLE_REGISTER": (6, "write_single_register"),
        "WRITE_MULTIPLE_COILS": (15, "write_multiple_coils"),
        "WRITE_MULTIPLE_REGISTERS": (16, "write_multiple_registers"),
        "MASK_WRITE_REGISTER": (22, "mask_write_register"),
    }

    records = []

    for index, function in enumerate(functions, start=1):
        records.append(make_record(tid=str(index), function=function))
        records.append(make_record(
            tid=str(index),
            function=function,
            pdu_type="RESP",
        ))

    events = normalize_zeek_modbus_log(make_zeek_log(records))

    assert len(events) == len(functions)

    actual = {
        event["transaction"]["function_name"]: (
            event["transaction"]["function_code"],
            event["transaction"]["operation"],
        )
        for event in events
    }

    assert actual == functions
