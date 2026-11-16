import json
import logging
import os
import time
from collections import deque
from pathlib import Path

import httpx

from app.ot.normalization.zeek import (
    normalize_zeek_modbus_log,
    parse_zeek_tsv,
)


logger = logging.getLogger("ot-zeek-reader")

DEFAULT_RESPONSE_TIMEOUT = 5.0
MAX_PENDING_REQUESTS = 10_000


class ZeekModbusPairer:
    """
    Pair Zeek Modbus request and response records.

    A transaction is identified by its connection UID and Modbus
    transaction ID. Requests without a response are emitted as
    unknown after the configured timeout.
    """

    def __init__(
        self,
        header: str,
        response_timeout: float = DEFAULT_RESPONSE_TIMEOUT,
        max_pending: int = MAX_PENDING_REQUESTS,
    ):
        if not isinstance(header, str) or "#fields" not in header:
            raise ValueError("A valid Zeek header containing #fields is required")

        if response_timeout <= 0:
            raise ValueError("response_timeout must be greater than zero")

        if max_pending < 1:
            raise ValueError("max_pending must be at least 1")

        self.header = header
        self.response_timeout = response_timeout
        self.max_pending = max_pending
        self.pending = {}

    @property
    def pending_count(self) -> int:
        return len(self.pending)

    def export_state(self) -> dict:
        """Return JSON-serializable state for checkpoint persistence."""

        return {
            "header": self.header,
            "pending": [
                {
                    "uid": key[0],
                    "tid": key[1],
                    "raw_line": request["raw_line"],
                    "received_at": request["received_at"],
                }
                for key, request in self.pending.items()
            ],
        }

    def restore_state(self, state: dict) -> None:
        """Restore pending requests from a previously saved checkpoint."""

        if not isinstance(state, dict):
            raise ValueError("Pairer checkpoint must be an object")

        if state.get("header") != self.header:
            raise ValueError("Checkpoint Zeek header does not match active log")

        pending = state.get("pending")

        if not isinstance(pending, list):
            raise ValueError("Checkpoint pending state must be a list")

        if len(pending) > self.max_pending:
            raise ValueError("Checkpoint contains too many pending requests")

        restored = {}

        for request in pending:
            if not isinstance(request, dict):
                raise ValueError("Invalid pending request in checkpoint")

            uid = request.get("uid")
            tid = request.get("tid")
            raw_line = request.get("raw_line")
            received_at = request.get("received_at")

            if not isinstance(uid, str) or not uid:
                raise ValueError("Invalid connection UID in checkpoint")

            if not isinstance(tid, str) or not tid:
                raise ValueError("Invalid transaction ID in checkpoint")

            if not isinstance(raw_line, str) or not raw_line:
                raise ValueError("Invalid raw request in checkpoint")

            if (
                isinstance(received_at, bool)
                or not isinstance(received_at, (int, float))
            ):
                raise ValueError("Invalid request timestamp in checkpoint")

            key = (uid, tid)

            if key in restored:
                raise ValueError("Duplicate pending transaction in checkpoint")

            restored[key] = {
                "raw_line": raw_line,
                "received_at": float(received_at),
            }

        self.pending = restored

    def _normalize(self, *raw_records: str) -> list[dict]:
        content = self.header + "".join(
            record.rstrip("\r\n") + "\n"
            for record in raw_records
        )
        return normalize_zeek_modbus_log(content)

    def process_line(
        self,
        raw_line: str,
        now: float | None = None,
    ) -> list[dict]:
        """Process one Zeek TSV record and return completed write events."""

        if not isinstance(raw_line, str):
            raise TypeError("Zeek record must be a string")

        if now is None:
            now = time.time()

        line = raw_line.rstrip("\r\n")

        if not line or line.startswith("#"):
            return []

        records = parse_zeek_tsv(self.header + line + "\n")

        if len(records) != 1:
            raise ValueError("Expected exactly one Zeek record")

        record = records[0]
        pdu_type = record.get("pdu_type")
        uid = record.get("uid")
        tid = record.get("tid")

        if pdu_type not in {"REQ", "RESP"}:
            return []

        if not uid or tid is None:
            logger.warning("Ignoring Modbus record without UID or transaction ID")
            return []

        key = (uid, tid)

        if pdu_type == "REQ":
            events = []

            # If a transaction ID is reused before its previous
            # response arrives, preserve the previous request as unknown.
            previous = self.pending.pop(key, None)

            if previous is not None:
                events.extend(self._normalize(previous["raw_line"]))

            # Keep memory bounded if a sensor produces too many
            # unanswered requests.
            if len(self.pending) >= self.max_pending:
                oldest_key = min(
                    self.pending,
                    key=lambda item: self.pending[item]["received_at"],
                )
                oldest = self.pending.pop(oldest_key)
                events.extend(self._normalize(oldest["raw_line"]))
                logger.warning("Pending request limit reached; expiring oldest request")

            self.pending[key] = {
                "raw_line": line,
                "received_at": now,
            }

            return events

        # A response without a matching request cannot form a transaction.
        request = self.pending.pop(key, None)

        if request is None:
            return []

        return self._normalize(request["raw_line"], line)

    def expire(self, now: float | None = None) -> list[dict]:
        """Emit requests that have exceeded the response timeout."""

        if now is None:
            now = time.time()

        expired_keys = [
            key
            for key, request in self.pending.items()
            if now - request["received_at"] >= self.response_timeout
        ]

        events = []

        for key in expired_keys:
            request = self.pending.pop(key)
            events.extend(self._normalize(request["raw_line"]))

        return events


# Live reader configuration
DEFAULT_CHECKPOINT_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "zeek_reader_checkpoint.json"
)

ZEEK_PATH = Path(
    os.getenv(
        "ZEEK_MODBUS_LOG_PATH",
        "/opt/zeek/logs/current/modbus.log",
    )
).expanduser()

INGEST_URL = os.getenv(
    "ALERTSTACK_OT_INGEST_URL",
    "http://127.0.0.1:8000/ot/ingest",
)

CHECKPOINT_PATH = Path(
    os.getenv("ZEEK_CHECKPOINT_PATH", str(DEFAULT_CHECKPOINT_PATH))
).expanduser()

POLL_INTERVAL = float(os.getenv("ALERTSTACK_OT_POLL_INTERVAL", "0.5"))
HTTP_TIMEOUT = float(os.getenv("ALERTSTACK_OT_HTTP_TIMEOUT", "5.0"))
RETRY_INTERVAL = float(os.getenv("ALERTSTACK_OT_RETRY_INTERVAL", "2.0"))


def read_zeek_header(file_handle) -> tuple[str, int]:
    """Read Zeek metadata and return its header and first data offset."""

    header_lines = []

    while True:
        line_start = file_handle.tell()
        raw_line = file_handle.readline()

        if not raw_line:
            break

        line = raw_line.decode("utf-8").rstrip("\r\n")

        if line.startswith("#"):
            header_lines.append(line + "\n")
            continue

        file_handle.seek(line_start)
        break

    header = "".join(header_lines)

    if "#fields" not in header or "#types" not in header:
        raise ValueError("Zeek log header is missing #fields or #types")

    return header, file_handle.tell()


def load_checkpoint() -> dict | None:
    """Load the reader checkpoint, failing safely if it is corrupted."""

    if not CHECKPOINT_PATH.exists():
        return None

    try:
        checkpoint = json.loads(CHECKPOINT_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Cannot safely load Zeek checkpoint: {exc}"
        ) from exc

    if not isinstance(checkpoint, dict):
        raise RuntimeError("Zeek checkpoint must contain a JSON object")

    if not isinstance(checkpoint.get("delivery_queue", []), list):
        raise RuntimeError("Invalid delivery queue in Zeek checkpoint")

    return checkpoint


def save_checkpoint(
    file_stat,
    offset: int,
    pairer: ZeekModbusPairer,
    delivery_queue,
) -> None:
    """Atomically persist file position, pairing state, and queued events."""

    CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)

    checkpoint = {
        "device": file_stat.st_dev,
        "inode": file_stat.st_ino,
        "offset": offset,
        "pairer": pairer.export_state(),
        "delivery_queue": list(delivery_queue),
        "saved_at": time.time(),
    }

    temporary_path = CHECKPOINT_PATH.with_suffix(".tmp")

    with temporary_path.open("w", encoding="utf-8") as handle:
        json.dump(checkpoint, handle, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())

    os.replace(temporary_path, CHECKPOINT_PATH)


def deliver_zeek_event(client: httpx.Client, event: dict) -> bool:
    """Deliver one normalized Zeek event to AlertStack."""

    response = client.post(INGEST_URL, json=event)

    if response.status_code != 200:
        logger.error(
            "AlertStack rejected Zeek event: HTTP %s",
            response.status_code,
        )
        return False

    try:
        result = response.json()
    except ValueError:
        logger.error("AlertStack returned invalid JSON")
        return False

    if not isinstance(result, dict):
        logger.error("AlertStack returned an unexpected response")
        return False

    status = result.get("status")

    if status in {"stored", "duplicate", "ignored"}:
        logger.info(
            "Zeek event delivery: %s | %s",
            status,
            result.get("event_type", "unknown"),
        )
        return True

    logger.error("Unexpected AlertStack response: %s", result)
    return False


def run_zeek_reader() -> None:
    """Follow Zeek Modbus logs and reliably deliver normalized OT events."""

    if not ZEEK_PATH.is_file():
        raise FileNotFoundError(f"Zeek Modbus log not found: {ZEEK_PATH}")

    logger.info("Starting Zeek Modbus reader")
    logger.info("Zeek log: %s", ZEEK_PATH)
    logger.info("AlertStack endpoint: %s", INGEST_URL)
    logger.info("Checkpoint: %s", CHECKPOINT_PATH)

    checkpoint = load_checkpoint()

    with ZEEK_PATH.open("rb") as log_file:
        file_stat = os.fstat(log_file.fileno())
        header, data_start = read_zeek_header(log_file)

        pairer = ZeekModbusPairer(header)
        delivery_queue = deque()

        same_file = (
            checkpoint is not None
            and checkpoint.get("device") == file_stat.st_dev
            and checkpoint.get("inode") == file_stat.st_ino
        )

        if checkpoint is not None:
            delivery_queue.extend(checkpoint.get("delivery_queue", []))

        if same_file:
            if checkpoint.get("pairer", {}).get("header") != header:
                raise RuntimeError(
                    "Checkpoint header differs from the active Zeek log"
                )

            offset = checkpoint.get("offset")

            if (
                isinstance(offset, bool)
                or not isinstance(offset, int)
                or offset < data_start
                or offset > file_stat.st_size
            ):
                raise RuntimeError("Invalid Zeek checkpoint file offset")

            pairer.restore_state(checkpoint["pairer"])
            log_file.seek(offset)

            logger.info(
                "Resuming Zeek log at byte %s with %s pending requests "
                "and %s queued deliveries",
                offset,
                pairer.pending_count,
                len(delivery_queue),
            )
        else:
            # A new reader starts at the current end of the existing log.
            # A replacement log after rotation starts after its header.
            if checkpoint is None:
                log_file.seek(0, os.SEEK_END)
                logger.info("First start: skipping existing Zeek log records")
            else:
                old_state = checkpoint.get("pairer")

                # Preserve old unanswered requests as unknown events.
                if isinstance(old_state, dict) and isinstance(
                    old_state.get("header"), str
                ):
                    old_pairer = ZeekModbusPairer(old_state["header"])
                    old_pairer.restore_state(old_state)
                    delivery_queue.extend(
                        old_pairer.expire(
                            now=time.time() + old_pairer.response_timeout
                        )
                    )

                log_file.seek(data_start)
                logger.info("Zeek log identity changed; reading new log")

            save_checkpoint(
                file_stat,
                log_file.tell(),
                pairer,
                delivery_queue,
            )

        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            while True:
                # Do not consume more log records while delivery is failing.
                if delivery_queue:
                    event = delivery_queue[0]

                    try:
                        delivered = deliver_zeek_event(client, event)
                    except (httpx.HTTPError, ValueError) as exc:
                        delivered = False
                        logger.warning("Zeek delivery error: %s", exc)

                    if delivered:
                        delivery_queue.popleft()
                        save_checkpoint(
                            file_stat,
                            log_file.tell(),
                            pairer,
                            delivery_queue,
                        )
                        continue

                    time.sleep(RETRY_INTERVAL)
                    continue

                # Expire requests that never received a response.
                expired = pairer.expire()

                if expired:
                    delivery_queue.extend(expired)
                    save_checkpoint(
                        file_stat,
                        log_file.tell(),
                        pairer,
                        delivery_queue,
                    )
                    continue

                line_start = log_file.tell()
                raw_line = log_file.readline()

                if raw_line:
                    # Do not advance past an incomplete line at EOF.
                    if not raw_line.endswith(b"\n"):
                        log_file.seek(line_start)
                        time.sleep(POLL_INTERVAL)
                        continue

                    try:
                        line = raw_line.decode("utf-8").rstrip("\r\n")
                        events = pairer.process_line(line)
                    except (UnicodeDecodeError, ValueError) as exc:
                        logger.warning("Skipping invalid Zeek record: %s", exc)
                        events = []

                    delivery_queue.extend(events)

                    # Persist the new offset and any generated events together.
                    save_checkpoint(
                        file_stat,
                        log_file.tell(),
                        pairer,
                        delivery_queue,
                    )
                    continue

                # At EOF, check whether Zeek rotated/replaced its active log.
                try:
                    current_stat = ZEEK_PATH.stat()
                except FileNotFoundError:
                    time.sleep(POLL_INTERVAL)
                    continue

                if (
                    current_stat.st_dev != file_stat.st_dev
                    or current_stat.st_ino != file_stat.st_ino
                ):
                    # The old file has been drained. Flush its unanswered
                    # requests before switching to the new file.
                    delivery_queue.extend(
                        pairer.expire(
                            now=time.time() + pairer.response_timeout
                        )
                    )

                    if delivery_queue:
                        save_checkpoint(
                            file_stat,
                            log_file.tell(),
                            pairer,
                            delivery_queue,
                        )
                        continue

                    log_file.close()
                    new_file = ZEEK_PATH.open("rb")
                    new_stat = os.fstat(new_file.fileno())
                    new_header, new_data_start = read_zeek_header(new_file)

                    log_file = new_file
                    file_stat = new_stat
                    pairer = ZeekModbusPairer(new_header)
                    log_file.seek(new_data_start)

                    save_checkpoint(
                        file_stat,
                        log_file.tell(),
                        pairer,
                        delivery_queue,
                    )

                    logger.info("Switched to rotated Zeek Modbus log")
                    continue

                time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        run_zeek_reader()
    except KeyboardInterrupt:
        logger.info("Zeek reader stopped by user")
