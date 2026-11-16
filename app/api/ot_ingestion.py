from fastapi import APIRouter, HTTPException

from app.ot.analysis import analyze_recent_ot_events
from app.ot.normalization.suricata import normalize_suricata_event
from app.ot.repository import save_ot_event

router = APIRouter()


SUPPORTED_ZEEK_WRITE_FUNCTIONS = {5, 6, 15, 16, 22}
VALID_RESPONSE_STATUSES = {"unknown", "response_received", "exception"}


def validate_zeek_event(event: dict) -> dict | None:
    """
    Validate an already-normalized Zeek OT event.

    Zeek events are normalized by the Zeek reader before delivery.
    This function validates their schema without normalizing them again.
    """

    if event.get("event_type") != "modbus_write_attempt":
        return None

    if (
        event.get("event_category") != "ot"
        or event.get("protocol") != "modbus"
        or event.get("sensor") != "zeek"
    ):
        raise HTTPException(
            status_code=422,
            detail="Invalid Zeek OT event metadata",
        )

    if not event.get("timestamp"):
        raise HTTPException(
            status_code=422,
            detail="Supported OT events must contain a timestamp",
        )

    for endpoint_name in ("source", "destination"):
        endpoint = event.get(endpoint_name)

        if not isinstance(endpoint, dict):
            raise HTTPException(
                status_code=422,
                detail=f"Zeek event must contain a valid {endpoint_name}",
            )

        if not isinstance(endpoint.get("ip"), str) or not endpoint["ip"]:
            raise HTTPException(
                status_code=422,
                detail=f"Zeek event has an invalid {endpoint_name} IP",
            )

        port = endpoint.get("port")

        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise HTTPException(
                status_code=422,
                detail=f"Zeek event has an invalid {endpoint_name} port",
            )

    transaction = event.get("transaction")

    if not isinstance(transaction, dict):
        raise HTTPException(
            status_code=422,
            detail="Zeek event must contain transaction details",
        )

    function_code = transaction.get("function_code")

    if function_code not in SUPPORTED_ZEEK_WRITE_FUNCTIONS:
        raise HTTPException(
            status_code=422,
            detail="Unsupported Zeek Modbus write function",
        )

    if not isinstance(transaction.get("operation"), str):
        raise HTTPException(
            status_code=422,
            detail="Zeek event must contain a transaction operation",
        )

    if transaction.get("response_status") not in VALID_RESPONSE_STATUSES:
        raise HTTPException(
            status_code=422,
            detail="Zeek event has an invalid response status",
        )

    return event


@router.post("/ot/ingest")
def ingest_ot_event(event: dict):
    """
    Accept Suricata EVE events or normalized Zeek OT events,
    store supported Modbus writes, and analyze recent OT activity.
    """

    sensor = event.get("sensor")

    if sensor not in (None, "suricata", "zeek"):
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported OT sensor: {sensor}",
        )

    if sensor == "zeek":
        normalized_event = validate_zeek_event(event)

        if normalized_event is None:
            return {
                "status": "ignored",
                "reason": "unsupported_or_non_write_event",
            }
    else:
        # Preserve the existing Suricata EVE ingestion path.
        normalized_event = normalize_suricata_event(event)

        if normalized_event is None:
            return {
                "status": "ignored",
                "reason": "unsupported_or_non_write_event",
            }

    if not normalized_event.get("timestamp"):
        raise HTTPException(
            status_code=422,
            detail="Supported OT events must contain a timestamp",
        )

    inserted = save_ot_event(event, normalized_event)

    if not inserted:
        return {
            "status": "duplicate",
            "event_type": normalized_event["event_type"],
        }

    analysis = analyze_recent_ot_events()

    return {
        "status": "stored",
        "event_type": normalized_event["event_type"],
        "protocol": normalized_event["protocol"],
        "analysis": {
            "observation_count": analysis["observation_count"],
            "transaction_count": analysis["transaction_count"],
            "duplicate_group_count": analysis["duplicate_group_count"],
            "repeated_activity_group_count": analysis[
                "repeated_activity_group_count"
            ],
            "analyzed_event_count": analysis["analyzed_event_count"],
        },
    }
