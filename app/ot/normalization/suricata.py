
import re


def decode_register_data(data):
    """Decode Suricata's mixed byte/escaped-hex representation."""

    if isinstance(data, bytes):
        raw = data

    elif isinstance(data, str):
        decoded = bytearray()
        i = 0

        while i < len(data):
            if data[i] == "\\":
                # Accept one or more backslashes before xHH.
                j = i
                while j < len(data) and data[j] == "\\":
                    j += 1

                if j + 2 >= len(data) or data[j] != "x":
                    return None

                hex_value = data[j + 1:j + 3]

                if re.fullmatch(r"[0-9a-fA-F]{2}", hex_value) is None:
                    return None

                decoded.append(int(hex_value, 16))
                i = j + 3
                continue

            value = ord(data[i])

            if value > 255:
                return None

            decoded.append(value)
            i += 1

        raw = bytes(decoded)

    else:
        return None

    if not raw or len(raw) % 2 != 0:
        return None

    return [
        int.from_bytes(raw[i:i + 2], byteorder="big")
        for i in range(0, len(raw), 2)
    ]


def normalize_suricata_event(event: dict) -> dict | None:
    """
    Normalize a Suricata EVE Modbus write alert.

    Returns None for unsupported or non-write Modbus events.
    """

    if not isinstance(event, dict):
        return None

    if event.get("event_type") != "alert":
        return None

    if event.get("app_proto") != "modbus":
        return None

    modbus = event.get("modbus")

    if not isinstance(modbus, dict):
        return None

    request = modbus.get("request") or {}
    response = modbus.get("response") or {}

    if not isinstance(request, dict) or not isinstance(response, dict):
        return None

    function_name = request.get("function_code")

    function_names = {
        "WRSINGLECOIL": 5,
        "WRSINGLEREG": 6,
        "WRMULTICOILS": 15,
        "WRMULTIREGS": 16,
        "MASKWRITEREG": 22,
        "READWRITEMULTIPLEREGS": 23,
    }

    function_code = request.get("function_raw")

    if function_code is None:
        if isinstance(function_name, int):
            function_code = function_name
        elif isinstance(function_name, str):
            function_code = function_names.get(function_name.upper())

    # FC23 combines read and write operations.
    # It is intentionally excluded from this write-only normalizer.
    operations = {
        5: "write_single_coil",
        6: "write_single_register",
        15: "write_multiple_coils",
        16: "write_multiple_registers",
        22: "mask_write_register",
    }

    # Only explicitly supported write function codes are accepted.
    if (
        isinstance(function_code, bool)
        or not isinstance(function_code, int)
        or function_code not in operations
    ):
        return None

    exception = response.get("exception")

    if isinstance(exception, dict):
        response_status = "exception"
    elif response:
        response_status = "response_received"
    else:
        response_status = "unknown"

    alert = event.get("alert")

    if not isinstance(alert, dict):
        alert = {}

    transaction = {
        "id": request.get("transaction_id"),
        "function_code": function_code,
        "function_name": function_name,
        "operation": operations[function_code],
        "unit_id": request.get("unit_id"),
        "response_status": response_status,
    }

    write_data = request.get("write")

    if isinstance(write_data, dict):
        if "address" in write_data:
            transaction["register_address"] = write_data["address"]

        if function_code == 16:
            # Quantity is independent of the data field.
            if "quantity" in write_data:
                transaction["register_count"] = write_data["quantity"]

            if "data" in write_data:
                transaction["register_data"] = write_data["data"]

                register_count = transaction.get("register_count")
                decoded_values = decode_register_data(write_data["data"])

                # FC16 writes exactly two bytes per register.
                if (
                    isinstance(register_count, int)
                    and not isinstance(register_count, bool)
                    and register_count > 0
                    and decoded_values is not None
                    and len(decoded_values) == register_count
                ):
                    transaction["register_values"] = decoded_values
                else:
                    transaction["register_values"] = None

        elif "data" in write_data:
            transaction["requested_value"] = write_data["data"]

    if isinstance(exception, dict):
        transaction["exception_code"] = exception.get("raw")
        transaction["exception_name"] = exception.get("code")

    return {
        "schema_version": "1.0",
        "sensor": "suricata",
        "event_category": "ot",
        "event_type": "modbus_write_attempt",
        "timestamp": event.get("timestamp"),
        "source": {
            "ip": event.get("src_ip"),
            "port": event.get("src_port"),
        },
        "destination": {
            "ip": event.get("dest_ip"),
            "port": event.get("dest_port"),
        },
        "protocol": "modbus",
        "transport": event.get("proto"),
        "alert": {
            "signature_id": alert.get("signature_id"),
            "signature": alert.get("signature"),
            "severity": alert.get("severity"),
        },
        "transaction": transaction,
    }
