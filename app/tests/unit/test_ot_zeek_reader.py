import pytest

from app.ot.ingestion.zeek_reader import ZeekModbusPairer


HEADER = (
    "#separator \\x09\n"
    "#unset_field -\n"
    "#path modbus\n"
    "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p "
    "tid unit func pdu_type exception\n"
    "#types time string addr port addr port count count "
    "string string string\n"
)


def make_record(
    *,
    tid="1",
    uid="connection-1",
    function="WRITE_SINGLE_REGISTER",
    pdu_type="REQ",
    exception="-",
):
    return "\t".join([
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
    ])


def test_request_waits_for_matching_response():
    pairer = ZeekModbusPairer(HEADER)

    events = pairer.process_line(make_record(), now=10.0)

    assert events == []
    assert pairer.pending_count == 1


def test_matching_response_completes_write_transaction():
    pairer = ZeekModbusPairer(HEADER)

    pairer.process_line(make_record(), now=10.0)
    events = pairer.process_line(
        make_record(pdu_type="RESP"),
        now=10.1,
    )

    assert len(events) == 1
    assert events[0]["sensor"] == "zeek"
    assert events[0]["transaction"]["function_code"] == 6
    assert events[0]["transaction"]["response_status"] == "response_received"
    assert pairer.pending_count == 0


def test_response_with_exception_is_preserved():
    pairer = ZeekModbusPairer(HEADER)

    pairer.process_line(make_record(), now=10.0)
    events = pairer.process_line(
        make_record(pdu_type="RESP", exception="ILLEGAL_FUNCTION"),
        now=10.1,
    )

    assert len(events) == 1
    assert events[0]["transaction"]["response_status"] == "exception"
    assert events[0]["transaction"]["exception_name"] == "ILLEGAL_FUNCTION"


def test_unmatched_response_is_ignored():
    pairer = ZeekModbusPairer(HEADER)

    events = pairer.process_line(
        make_record(pdu_type="RESP"),
        now=10.0,
    )

    assert events == []


def test_read_transaction_is_ignored():
    pairer = ZeekModbusPairer(HEADER)

    pairer.process_line(
        make_record(function="READ_HOLDING_REGISTERS"),
        now=10.0,
    )
    events = pairer.process_line(
        make_record(
            function="READ_HOLDING_REGISTERS",
            pdu_type="RESP",
        ),
        now=10.1,
    )

    assert events == []
    assert pairer.pending_count == 0


def test_request_expires_as_unknown_when_response_is_missing():
    pairer = ZeekModbusPairer(HEADER, response_timeout=5.0)

    pairer.process_line(make_record(), now=10.0)

    assert pairer.expire(now=14.9) == []

    events = pairer.expire(now=15.0)

    assert len(events) == 1
    assert events[0]["transaction"]["response_status"] == "unknown"
    assert pairer.pending_count == 0


def test_requests_are_matched_using_uid_and_transaction_id():
    pairer = ZeekModbusPairer(HEADER)

    pairer.process_line(
        make_record(uid="connection-a", tid="1"),
        now=10.0,
    )
    pairer.process_line(
        make_record(uid="connection-b", tid="1"),
        now=10.1,
    )

    events = pairer.process_line(
        make_record(
            uid="connection-b",
            tid="1",
            pdu_type="RESP",
        ),
        now=10.2,
    )

    assert len(events) == 1
    assert events[0]["transaction"]["connection_uid"] == "connection-b"
    assert pairer.pending_count == 1


def test_pending_request_limit_is_enforced():
    pairer = ZeekModbusPairer(HEADER, max_pending=1)

    pairer.process_line(make_record(tid="1"), now=10.0)
    events = pairer.process_line(
        make_record(tid="2"),
        now=11.0,
    )

    assert len(events) == 1
    assert events[0]["transaction"]["id"] == 1
    assert events[0]["transaction"]["response_status"] == "unknown"
    assert pairer.pending_count == 1


def test_invalid_configuration_is_rejected():
    with pytest.raises(ValueError):
        ZeekModbusPairer("invalid header")

    with pytest.raises(ValueError):
        ZeekModbusPairer(HEADER, response_timeout=0)

    with pytest.raises(ValueError):
        ZeekModbusPairer(HEADER, max_pending=0)


def test_pending_request_state_survives_export_and_restore():
    original = ZeekModbusPairer(HEADER, response_timeout=5.0)

    original.process_line(make_record(), now=1000.0)

    checkpoint = original.export_state()

    restored = ZeekModbusPairer(HEADER, response_timeout=5.0)
    restored.restore_state(checkpoint)

    assert restored.pending_count == 1

    events = restored.process_line(
        make_record(pdu_type="RESP"),
        now=1001.0,
    )

    assert len(events) == 1
    assert events[0]["transaction"]["response_status"] == "response_received"


def test_restored_request_can_expire():
    original = ZeekModbusPairer(HEADER, response_timeout=5.0)
    original.process_line(make_record(), now=1000.0)

    restored = ZeekModbusPairer(HEADER, response_timeout=5.0)
    restored.restore_state(original.export_state())

    events = restored.expire(now=1005.0)

    assert len(events) == 1
    assert events[0]["transaction"]["response_status"] == "unknown"


def test_restore_rejects_incompatible_header():
    original = ZeekModbusPairer(HEADER)
    checkpoint = original.export_state()

    restored = ZeekModbusPairer(HEADER + "#extra metadata\n")

    with pytest.raises(ValueError, match="header does not match"):
        restored.restore_state(checkpoint)


def test_restore_rejects_invalid_pending_state():
    pairer = ZeekModbusPairer(HEADER)

    with pytest.raises(ValueError, match="Invalid connection UID"):
        pairer.restore_state({
            "header": HEADER,
            "pending": [{
                "uid": "",
                "tid": "1",
                "raw_line": make_record(),
                "received_at": 1000.0,
            }],
        })
