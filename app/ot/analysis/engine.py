from app.ot.correlation import correlate_ot_events
from app.ot.repository import (
    fetch_ot_events,
    update_ot_event_normalized,
)
from app.ot.risk import evaluate_ot_risk


def analyze_recent_ot_events(limit: int = 500) -> dict:
    """
    Correlate recent stored OT events, calculate risk, and persist
    the analysis inside each event's normalized data.

    Correlation runs across multiple stored events so repeated
    Modbus writes can be identified over time.
    """
    events = fetch_ot_events(limit=limit)

    correlation = correlate_ot_events(events)
    event_results = {}
    analyzed_event_count = 0

    for stored_event in events:
        event_id = stored_event["event_id"]
        correlation_result = correlation["event_results"].get(event_id)

        # The correlation engine currently analyzes Modbus write attempts.
        if correlation_result is None:
            continue

        normalized_event = stored_event["normalized"]

        context = {
            "repeated_activity": correlation_result["repeated_activity"],
        }

        enriched_event = evaluate_ot_risk(
            normalized_event,
            context=context,
        )

        event_correlation = {
            "duplicate_group_id": correlation_result["duplicate_group_id"],
            "is_duplicate_observation": correlation_result[
                "is_duplicate_observation"
            ],
            "repeated_activity": correlation_result["repeated_activity"],
        }

        enriched_event["correlation"] = event_correlation

        updated = update_ot_event_normalized(
            event_id,
            enriched_event,
        )

        if not updated:
            continue

        event_results[event_id] = {
            **event_correlation,
            "risk": enriched_event["risk"],
        }

        analyzed_event_count += 1

    return {
        "observation_count": correlation["observation_count"],
        "transaction_count": correlation["transaction_count"],
        "duplicate_group_count": len(correlation["duplicate_groups"]),
        "repeated_activity_group_count": len(
            correlation["repeated_activity_groups"]
        ),
        "analyzed_event_count": analyzed_event_count,
        "event_results": event_results,
    }
