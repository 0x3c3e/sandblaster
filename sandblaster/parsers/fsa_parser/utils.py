def escape_char(c):
    if 32 <= c <= 126 and chr(c) not in {"\\", "[", "]", "^", "-"}:
        return chr(c)
    else:
        return f"\\x{c:02x}"


def ranges_to_regex(ranges, mode):
    parts = []
    for start, end in ranges:
        start_char = escape_char(start)
        end_char = escape_char(end)
        parts.append(f"{start_char}-{end_char}")

    char_class = "".join(parts)
    return f"[^{char_class}]" if mode == "RANGE_EXCLUSIVE" else f"[{char_class}]"
