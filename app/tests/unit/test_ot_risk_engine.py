import pytest

from app.ot.risk.engine import evaluate_ot_risk


def make_event(response_status="response_received"):
    return {
        "event_category": "ot",
        "event_type": "modbus_write_attempt",
        "protocol": "modbus",
        "transaction": {
            "function_code": 6,
            "operation": "write_single_register",
            "response_status": response_status,
        },
    }


def test_modbus_write_with_response_scores_30():
    result = evaluate_ot_risk(make_event())

    assert result["risk"]["score"] == 30
    assert result["risk"]["severity"] == "low"


def test_unknown_response_scores_35():
    result = evaluate_ot_risk(make_event("unknown"))

    assert result["risk"]["score"] == 35
    assert result["risk"]["severity"] == "low"


def test_protocol_exception_adds_no_response_points():
    result = evaluate_ot_risk(make_event("exception"))

    assert result["risk"]["score"] == 25
    assert result["risk"]["severity"] == "low"


def test_repeated_activity_adds_15_points():
    result = evaluate_ot_risk(
        make_event(),
        context={"repeated_activity": True},
    )

    assert result["risk"]["score"] == 45
    assert result["risk"]["severity"] == "low"


def test_non_write_event_receives_zero_score():
    event = {"event_type": "modbus_read", "protocol": "modbus"}

    result = evaluate_ot_risk(event)

    assert result["risk"]["score"] == 0
    assert result["risk"]["severity"] == "informational"


def test_score_is_capped_at_100():
    result = evaluate_ot_risk(
        make_event("unknown"),
        context={"repeated_activity": True},
    )

    assert result["risk"]["score"] <= 100


def test_original_event_is_not_modified():
    event = make_event()
    original = {
        **event,
        "transaction": dict(event["transaction"]),
    }

    evaluate_ot_risk(event)

    assert event == original


def test_invalid_event_is_rejected():
    with pytest.raises(TypeError):
        evaluate_ot_risk("not an event")


def test_invalid_context_is_rejected():
    with pytest.raises(TypeError):
        evaluate_ot_risk(make_event(), context="invalid")
