from copy import deepcopy


SCORE_VERSION = "1.0"
MAX_SCORE = 100


def _severity_for_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 25:
        return "low"
    return "informational"


def evaluate_ot_risk(
    event: dict,
    context: dict | None = None,
) -> dict:
    """
    Enrich a normalized OT event with an explainable risk assessment.

    This is an initial heuristic model. It does not establish
    whether a physical process was affected.
    """
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    if context is not None and not isinstance(context, dict):
        raise TypeError("context must be a dictionary or None")

    context = context or {}
    score = 0
    reasons = []

    def add_reason(code: str, points: int, description: str) -> None:
        nonlocal score
        score += points
        reasons.append({
            "code": code,
            "points": points,
            "description": description,
        })

    if event.get("event_type") == "modbus_write_attempt":
        add_reason(
            "MODBUS_WRITE_ATTEMPT",
            25,
            "A Modbus write operation was detected.",
        )

        transaction = event.get("transaction") or {}
        response_status = transaction.get("response_status")

        if response_status == "response_received":
            add_reason(
                "PROTOCOL_RESPONSE_RECEIVED",
                5,
                "A protocol response was observed; physical impact is unconfirmed.",
            )
        elif response_status == "unknown":
            add_reason(
                "PROTOCOL_RESPONSE_UNKNOWN",
                10,
                "The protocol response status is unknown.",
            )
        elif response_status == "exception":
            reasons.append({
                "code": "PROTOCOL_EXCEPTION",
                "points": 0,
                "description": "The protocol response indicates an exception.",
            })

    if context.get("repeated_activity") is True:
        add_reason(
            "REPEATED_ACTIVITY",
            15,
            "Correlation identified repeated activity.",
        )

    score = min(score, MAX_SCORE)

    enriched_event = deepcopy(event)
    enriched_event["risk"] = {
        "score_version": SCORE_VERSION,
        "score": score,
        "severity": _severity_for_score(score),
        "reasons": reasons,
    }

    return enriched_event
