import pytest

from app.ot.correlation.engine import correlate_ot_events


def make_event(
    event_id,
    timestamp,
    transaction_id=1,
    signature_id=2250010,
    sensor="suricata",
    register_address=40001,
    requested_value=789,
):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "sensor": sensor,
        "event_type": "modbus_write_attempt",
        "protocol": "modbus",
        "source": {"ip": "10.10.50.144", "port": 51128},
        "destination": {"ip": "10.10.50.1", "port": 502},
        "transaction": {
            "id": transaction_id,
            "function_code": 6,
            "unit_id": 2,
            "operation": "write_single_register",
            "register_address": register_address,
            "requested_value": requested_value,
        },
        "alert": {"signature_id": signature_id},
    }


def test_different_suricata_signatures_group_as_one_transaction():
    events = [
        make_event("alert-a", "2026-11-15T13:08:48.379284+0530", 1, 2250010),
        make_event("alert-b", "2026-11-15T13:08:48.379284+0530", 1, 2250011),
    ]

    result = correlate_ot_events(events)

    assert result["transaction_count"] == 1
    assert len(result["duplicate_groups"]) == 1
    assert result["duplicate_groups"][0]["observation_count"] == 2


def test_same_transaction_can_be_observed_by_zeek():
    suricata = make_event("suricata-1", "2026-11-15T13:08:48+0530")
    zeek = make_event(
        "zeek-1",
        "2026-11-15T13:08:49+0530",
        sensor="zeek",
        register_address=None,
        requested_value=None,
    )

    result = correlate_ot_events([suricata, zeek])

    assert result["transaction_count"] == 1
    assert len(result["duplicate_groups"]) == 1


def test_different_transaction_ids_are_not_duplicates():
    events = [
        make_event("write-1", "2026-11-15T13:08:48+0530", 1),
        make_event("write-2", "2026-11-15T13:08:49+0530", 2),
    ]

    result = correlate_ot_events(events)

    assert result["transaction_count"] == 2
    assert result["duplicate_groups"] == []


def test_different_register_values_are_not_duplicates():
    events = [
        make_event("write-1", "2026-11-15T13:08:48+0530", 1, requested_value=789),
        make_event("write-2", "2026-11-15T13:08:49+0530", 1, requested_value=900),
    ]

    result = correlate_ot_events(events)

    assert result["transaction_count"] == 2


def test_events_outside_duplicate_window_are_not_duplicates():
    events = [
        make_event("write-1", "2026-11-15T13:08:48+0530"),
        make_event("write-2", "2026-11-15T13:08:52+0530"),
    ]

    result = correlate_ot_events(events)

    assert result["transaction_count"] == 2
    assert result["duplicate_groups"] == []


def test_three_distinct_writes_trigger_repeated_activity():
    events = [
        make_event("write-1", "2026-11-15T13:08:48+0530", 1),
        make_event("write-2", "2026-11-15T13:08:55+0530", 2),
        make_event("write-3", "2026-11-15T13:09:02+0530", 3),
    ]

    result = correlate_ot_events(events)

    assert result["transaction_count"] == 3
    assert len(result["repeated_activity_groups"]) == 1

    for event_id in ("write-1", "write-2", "write-3"):
        assert result["event_results"][event_id]["repeated_activity"] is True


def test_two_distinct_writes_do_not_trigger_repeated_activity():
    events = [
        make_event("write-1", "2026-11-15T13:08:48+0530", 1),
        make_event("write-2", "2026-11-15T13:08:55+0530", 2),
    ]

    result = correlate_ot_events(events)

    assert result["repeated_activity_groups"] == []
    assert result["event_results"]["write-1"]["repeated_activity"] is False


def test_non_write_events_are_ignored():
    event = make_event("read-1", "2026-11-15T13:08:48+0530")
    event["event_type"] = "modbus_read"

    result = correlate_ot_events([event])

    assert result["observation_count"] == 0
    assert result["transaction_count"] == 0


def test_repository_wrapped_events_are_supported():
    normalized = make_event("wrapped-1", "2026-11-15T13:08:48+0530")
    wrapped = {
        "event_id": "wrapped-1",
        "normalized": normalized,
    }

    result = correlate_ot_events([wrapped])

    assert result["observation_count"] == 1
    assert result["transaction_count"] == 1


def test_invalid_inputs_are_rejected():
    with pytest.raises(TypeError):
        correlate_ot_events("not a list")

    with pytest.raises(TypeError):
        correlate_ot_events(["not an event"])


def test_invalid_threshold_is_rejected():
    with pytest.raises(ValueError):
        correlate_ot_events([], repeated_threshold=1)

def test_four_writes_create_one_repeated_activity_group():
    events = [
        make_event("write-1", "2026-11-15T13:08:48+0530", 1),
        make_event("write-2", "2026-11-15T13:08:58+0530", 2),
        make_event("write-3", "2026-11-15T13:09:08+0530", 3),
        make_event("write-4", "2026-11-15T13:09:18+0530", 4),
    ]

    result = correlate_ot_events(events)

    assert result["transaction_count"] == 4
    assert len(result["repeated_activity_groups"]) == 1

    group = result["repeated_activity_groups"][0]

    assert group["transaction_count"] == 4
    assert len(group["cluster_indexes"]) == 4

    for event_id in ("write-1", "write-2", "write-3", "write-4"):
        assert result["event_results"][event_id]["repeated_activity"] is True

def test_only_subsequent_cross_sensor_observations_are_duplicates():
    suricata = make_event(
        "suricata-1",
        "2026-11-15T13:08:48+0530",
    )
    zeek = make_event(
        "zeek-1",
        "2026-11-15T13:08:49+0530",
        sensor="zeek",
        register_address=None,
        requested_value=None,
    )

    result = correlate_ot_events([suricata, zeek])

    assert result["transaction_count"] == 1
    assert result["event_results"]["suricata-1"][
        "is_duplicate_observation"
    ] is False
    assert result["event_results"]["zeek-1"][
        "is_duplicate_observation"
    ] is True
