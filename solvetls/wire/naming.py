from enum import IntEnum

# RFC 8701 reserves these GREASE identifiers to exercise extension points.
GREASE_VALUES = frozenset((i << 12) | 0x0A00 | (i << 4) | 0x0A for i in range(16))


def describe(value: int, enum_type: type[IntEnum] | None = None) -> dict:
    """Pair a raw wire value with its name, marking GREASE as such."""
    entry = {
        "value": value,
        "hex": f"0x{value:04x}",
        "name": enum_name(value, enum_type) if enum_type else None,
    }
    if value in GREASE_VALUES:
        entry["grease"] = True
    return entry


def enum_name(value: int, enum_type: type[IntEnum]) -> str | None:
    try:
        return enum_type(value).name
    except ValueError:
        return None
