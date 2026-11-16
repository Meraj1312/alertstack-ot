import csv
import re


def parse_zeek_tsv(content: str) -> list[dict]:
    """
    Parse a Zeek TSV log into dictionaries.

    Reads the field names from Zeek's #fields metadata and converts
    the configured unset marker to None. Other values remain strings.
    """

    if not isinstance(content, str):
        raise TypeError("Zeek log content must be a string")

    separator = "\t"
    unset_field = "-"
    fields = []
    records = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        if not line:
            continue

        if line.startswith("#separator "):
            encoded_separator = line[len("#separator "):]

            match = re.fullmatch(
                r"\\x([0-9a-fA-F]{2})",
                encoded_separator,
            )

            if match:
                separator = chr(int(match.group(1), 16))
            elif len(encoded_separator) == 1:
                separator = encoded_separator
            else:
                raise ValueError(
                    f"Unsupported Zeek separator on line {line_number}"
                )

            continue

        if line.startswith("#unset_field "):
            unset_field = line[len("#unset_field "):]
            continue

        if line.startswith("#fields"):
            fields = line[len("#fields"):].split()

            if not fields:
                raise ValueError(
                    f"Invalid Zeek field declaration on line {line_number}"
                )

            continue

        if line.startswith("#"):
            continue

        if not fields:
            raise ValueError(
                f"Zeek data encountered before #fields on line {line_number}"
            )

        values = next(
            csv.reader([line], delimiter=separator)
        )

        if len(values) != len(fields):
            raise ValueError(
                f"Field count mismatch on line {line_number}: "
                f"expected {len(fields)}, received {len(values)}"
            )

        record = {
            field: None if value == unset_field else value
            for field, value in zip(fields, values)
        }

        records.append(record)

    return records


def normalize_zeek_modbus_log(content: str) -> list[dict]:
    """
    Normalize Zeek modbus.log records into AlertStack OT events.

    Only supported Modbus write requests are returned.
    Request/response correlation uses Zeek connection UID and
    Modbus transaction ID.

    Zeek's standard modbus.log does not expose register addresses
    or written values, so those fields are intentionally omitted.
    """

    records = parse_zeek_tsv(content)

    write_functions = {
        "WRITE_SINGLE_COIL": (5, "write_single_coil"),
        "WRITE_SINGLE_REGISTER": (6, "write_single_register"),
        "WRITE_MULTIPLE_COILS": (15, "write_multiple_coils"),
        "WRITE_MULTIPLE_REGISTERS": (16, "write_multiple_registers"),
        "MASK_WRITE_REGISTER": (22, "mask_write_register"),
    }

    def to_int(value):
        if value is None:
            return None

        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    responses = {}

    for record in records:
        if record.get("pdu_type") != "RESP":
            continue

        key = (record.get("uid"), record.get("tid"))

        if None not in key:
            responses[key] = record

    normalized = []

    for record in records:
        if record.get("pdu_type") != "REQ":
            continue

        function_name = record.get("func")

        if function_name not in write_functions:
            continue

        function_code, operation = write_functions[function_name]

        uid = record.get("uid")
        tid = record.get("tid")
        response = responses.get((uid, tid))

        if response is None:
            response_status = "unknown"
        elif response.get("exception") is not None:
            response_status = "exception"
        else:
            response_status = "response_received"

        transaction = {
            "id": to_int(tid),
            "function_code": function_code,
            "function_name": function_name,
            "operation": operation,
            "unit_id": to_int(record.get("unit")),
            "connection_uid": uid,
            "response_status": response_status,
        }

        if response is not None and response.get("exception") is not None:
            transaction["exception_name"] = response["exception"]

        normalized.append({
            "schema_version": "1.0",
            "sensor": "zeek",
            "event_category": "ot",
            "event_type": "modbus_write_attempt",
            "timestamp": record.get("ts"),
            "source": {
                "ip": record.get("id.orig_h"),
                "port": to_int(record.get("id.orig_p")),
            },
            "destination": {
                "ip": record.get("id.resp_h"),
                "port": to_int(record.get("id.resp_p")),
            },
            "protocol": "modbus",
            "transport": "TCP",
            "transaction": transaction,
        })

    return normalized
