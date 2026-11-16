
from datetime import datetime


def _get_normalized(event):
    """Accept either a normalized event or an OT repository record."""
    normalized = event.get("normalized")
    return normalized if isinstance(normalized, dict) else event


def _parse_timestamp(value):
    if value is None:
        return None

    try:
        if isinstance(value, (int, float)):
            return float(value)

        if not isinstance(value, str):
            return None

        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            ).timestamp()
        except ValueError:
            return float(value)

    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _transaction_identity(event):
    """
    Fields required to identify a Modbus transaction.

    Alert signature and sensor are deliberately excluded:
    different sensors/signatures may observe the same operation.
    """
    transaction = event.get("transaction") or {}
    source = event.get("source") or {}
    destination = event.get("destination") or {}

    required = (
        source.get("ip"),
        source.get("port"),
        destination.get("ip"),
        destination.get("port"),
        transaction.get("id"),
        transaction.get("function_code"),
        transaction.get("unit_id"),
        transaction.get("operation"),
    )

    if any(value is None for value in required):
        return None

    return required


def _optional_details_compatible(first, second):
    """
    Missing optional details are treated as unknown.
    Conflicting known register details prevent a match.
    """
    first_tx = first.get("transaction") or {}
    second_tx = second.get("transaction") or {}

    for field in ("register_address", "requested_value", "register_data"):
        first_value = first_tx.get(field)
        second_value = second_tx.get(field)

        if (
            first_value is not None
            and second_value is not None
            and first_value != second_value
        ):
            return False

    return True


def correlate_ot_events(
    events: list[dict],
    duplicate_window_seconds: float = 2.0,
    repeated_window_seconds: float = 60.0,
    repeated_threshold: int = 3,
) -> dict:
    """
    Group duplicate OT observations and identify repeated Modbus writes.

    Duplicate observations are grouped by transaction identity and
    timestamp proximity. Repeated activity counts distinct transaction
    groups, not individual IDS alerts.

    This is an initial heuristic correlation engine.
    """
    if not isinstance(events, list):
        raise TypeError("events must be a list")

    if duplicate_window_seconds < 0 or repeated_window_seconds < 0:
        raise ValueError("time windows cannot be negative")

    if (
        isinstance(repeated_threshold, bool)
        or not isinstance(repeated_threshold, int)
        or repeated_threshold < 2
    ):
        raise ValueError("repeated_threshold must be an integer >= 2")

    prepared = []

    for index, original in enumerate(events):
        if not isinstance(original, dict):
            raise TypeError("each event must be a dictionary")

        event = _get_normalized(original)

        if event.get("event_type") != "modbus_write_attempt":
            continue

        identity = _transaction_identity(event)
        timestamp = _parse_timestamp(event.get("timestamp"))

        prepared.append({
            "index": index,
            "event_id": original.get("event_id", f"event-{index}"),
            "event": event,
            "identity": identity,
            "timestamp": timestamp,
        })

    # Sort chronologically; unknown timestamps are handled separately.
    prepared.sort(
        key=lambda item: (
            item["timestamp"] is None,
            item["timestamp"] if item["timestamp"] is not None else 0,
            item["index"],
        )
    )

    # Each cluster represents one underlying transaction.
    clusters = []

    for item in prepared:
        matched_cluster = None

        if item["identity"] is not None and item["timestamp"] is not None:
            for cluster in reversed(clusters):
                representative = cluster[0]

                if representative["timestamp"] is None:
                    continue

                age = item["timestamp"] - representative["timestamp"]

                if age > duplicate_window_seconds:
                    break

                if age < 0:
                    continue

                if representative["identity"] != item["identity"]:
                    continue

                if not _optional_details_compatible(
                    representative["event"],
                    item["event"],
                ):
                    continue

                matched_cluster = cluster
                break

        if matched_cluster is None:
            clusters.append([item])
        else:
            matched_cluster.append(item)

    # Detect repeated activity using distinct transaction clusters.
    activity_groups = {}

    for cluster_index, cluster in enumerate(clusters):
        representative = cluster[0]
        identity = representative["identity"]
        timestamp = representative["timestamp"]

        if identity is None or timestamp is None:
            continue

        source_ip, _, destination_ip, destination_port, _, _, unit_id, _ = identity

        activity_key = (
            source_ip,
            destination_ip,
            destination_port,
            unit_id,
        )

        activity_groups.setdefault(activity_key, []).append({
            "cluster_index": cluster_index,
            "timestamp": timestamp,
        })

    repeated_cluster_indexes = set()
    repeated_groups = []

    for activity_key, observations in activity_groups.items():
        observations.sort(key=lambda item: item["timestamp"])

        # Find all qualifying repeated-activity windows.
        candidate_groups = []

        for observation in observations:
            nearby = [
                candidate
                for candidate in observations
                if 0 <= candidate["timestamp"] - observation["timestamp"]
                <= repeated_window_seconds
            ]

            if len(nearby) >= repeated_threshold:
                indexes = {
                    candidate["cluster_index"]
                    for candidate in nearby
                }
                candidate_groups.append(indexes)

        # Merge overlapping windows into single activity groups.
        merged_groups = []

        for candidate in candidate_groups:
            overlapping = [
                group
                for group in merged_groups
                if group.intersection(candidate)
            ]

            if not overlapping:
                merged_groups.append(set(candidate))
                continue

            merged = set(candidate)

            for group in overlapping:
                merged.update(group)
                merged_groups.remove(group)

            merged_groups.append(merged)

        # Build the final groups.
        for indexes in merged_groups:
            indexes = sorted(indexes)
            repeated_cluster_indexes.update(indexes)

            repeated_groups.append({
                "group_id": f"repeated-{indexes[0]}",
                "source_ip": activity_key[0],
                "destination_ip": activity_key[1],
                "destination_port": activity_key[2],
                "unit_id": activity_key[3],
                "transaction_count": len(indexes),
                "window_seconds": repeated_window_seconds,
                "cluster_indexes": indexes,
            })

    # Build duplicate groups and per-event results.
    duplicate_groups = []
    event_results = {}

    for cluster_index, cluster in enumerate(clusters):
        is_duplicate_group = len(cluster) > 1
        group_id = f"transaction-{cluster_index}"

        if is_duplicate_group:
            duplicate_groups.append({
                "group_id": group_id,
                "event_ids": [item["event_id"] for item in cluster],
                "observation_count": len(cluster),
                "sensors": sorted({
                    item["event"].get("sensor", "unknown")
                    for item in cluster
                }),
            })

        repeated = cluster_index in repeated_cluster_indexes

        for observation_index, item in enumerate(cluster):
            event_results[item["event_id"]] = {
                "duplicate_group_id": group_id if is_duplicate_group else None,
                "is_duplicate_observation": observation_index > 0,
                "repeated_activity": repeated,
            }

    return {
        "duplicate_groups": duplicate_groups,
        "repeated_activity_groups": repeated_groups,
        "event_results": event_results,
        "transaction_count": len(clusters),
        "observation_count": len(prepared),
    }
