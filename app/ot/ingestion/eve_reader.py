import json
import logging
import os
import time
from collections import deque
from pathlib import Path

import httpx

from app.ot.normalization.suricata import normalize_suricata_event


EVE_PATH = Path(
    os.getenv("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
).expanduser()

INGEST_URL = os.getenv(
    "ALERTSTACK_OT_INGEST_URL",
    "http://127.0.0.1:8000/ot/ingest",
)

POLL_INTERVAL = float(os.getenv("ALERTSTACK_OT_POLL_INTERVAL", "0.5"))
HTTP_TIMEOUT = float(os.getenv("ALERTSTACK_OT_HTTP_TIMEOUT", "5.0"))
MAX_RETRIES = int(os.getenv("ALERTSTACK_OT_MAX_RETRIES", "5"))
RETRY_INTERVAL = float(os.getenv("ALERTSTACK_OT_RETRY_INTERVAL", "2.0"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("ot-eve-reader")


def parse_eve_line(raw_line: bytes) -> dict | None:
    """Parse one EVE JSON line without modifying the source file."""

    try:
        event = json.loads(raw_line.lstrip(b"\x00"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.warning("Skipping malformed EVE JSON record")
        return None

    if not isinstance(event, dict):
        logger.warning("Skipping EVE record that is not a JSON object")
        return None

    return event


def process_line(raw_line: bytes) -> dict | None:
    """Parse an EVE record and normalize supported OT write alerts."""

    event = parse_eve_line(raw_line)

    if event is None:
        return None

    return normalize_suricata_event(event)


def deliver_event(client: httpx.Client, event: dict) -> bool:
    """Send a normalized OT event's original EVE record to AlertStack."""

    response = client.post(INGEST_URL, json=event)

    if response.status_code != 200:
        logger.error(
            "AlertStack rejected event: HTTP %s",
            response.status_code,
        )
        return False

    result = response.json()

    if not isinstance(result, dict):
        logger.error("AlertStack returned an unexpected response format")
        return False

    status = result.get("status")

    if status in {"stored", "duplicate", "ignored"}:
        logger.info(
            "Event delivery result: %s | %s",
            status,
            result.get("event_type", "unknown"),
        )
        return True

    logger.error("Unexpected AlertStack response: %s", result)
    return False


def run() -> None:
    """Follow new EVE records and deliver supported OT events."""

    if not EVE_PATH.is_file():
        raise FileNotFoundError(f"Suricata EVE file not found: {EVE_PATH}")

    pending = deque()

    logger.info("Starting Suricata EVE reader")
    logger.info("EVE file: %s", EVE_PATH)
    logger.info("AlertStack endpoint: %s", INGEST_URL)

    with EVE_PATH.open("rb") as eve_file:
        eve_file.seek(0, 2)
        logger.info("Starting at end of existing EVE file")

        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            while True:
                # Retry queued events before reading more records.
                if pending:
                    raw_event, attempts = pending[0]

                    try:
                        delivered = deliver_event(client, raw_event)
                    except (httpx.HTTPError, ValueError) as exc:
                        delivered = False
                        logger.warning("Delivery error: %s", exc)

                    if delivered:
                        pending.popleft()
                        continue

                    attempts += 1

                    if attempts == MAX_RETRIES:
                        logger.error(
                            "Event reached retry limit; continuing to retry "
                            "without consuming new EVE records"
                        )

                    pending[0] = (raw_event, attempts)
                    time.sleep(RETRY_INTERVAL)
                    continue

                raw_line = eve_file.readline()

                if not raw_line:
                    time.sleep(POLL_INTERVAL)
                    continue

                normalized = process_line(raw_line)

                if normalized is None:
                    continue

                # Keep the original EVE event for the API endpoint.
                event = parse_eve_line(raw_line)

                if event is None:
                    continue

                pending.append((event, 0))


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        logger.info("Reader stopped by user")
