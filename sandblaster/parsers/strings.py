from collections import deque
from typing import Any, Dict, List, Mapping, Sequence, Tuple, Union

Operation = Union[str, Tuple[str, Any]]
Path = List[int]


class Opcode:
    ASSERT_EOS = 0x00
    CALLBACK_EXT = 0x01
    MATCH_BYTE = 0x02
    MATCH_SEQ = 0x03
    LITERAL_EXT = 0x04
    RESTORE_POS = 0x05
    PUSH_STATE = 0x06
    POP_STATE = 0x07
    JNE_EXT = 0x08
    SUCCESS = 0x0A
    RANGE = 0x0B
    MATCH = 0x0F

    CALLBACK_SHORT = slice(0x10, 0x1F)
    LITERAL_SHORT = slice(0x40, 0x7F)
    JNE_SHORT = slice(0x80, 0xFF)


def parse_fsa_pattern_bytecode(fsa: bytes, debug: bool = True) -> Dict[int, Operation]:
    i = 0
    ops: Dict[int, Operation] = {}
    n = len(fsa)

    while i < n:
        opcode = fsa[i]
        start = i

        match opcode:
            case Opcode.CALLBACK_EXT:
                cb = int.from_bytes(fsa[i + 1 : i + 3], "little")
                op, i = ("CALLBACK", cb), i + 3

            case Opcode.ASSERT_EOS:
                op, i = "ASSERT_EOS", i + 1

            case Opcode.MATCH_BYTE:
                op, i = ("MATCH_BYTE", fsa[i + 1]), i + 2

            case Opcode.MATCH_SEQ:
                op, i = ("MATCH_SEQ", fsa[i + 1]), i + 2

            case Opcode.LITERAL_EXT:
                length = fsa[i + 1] + 0x41
                lit = fsa[i + 2 : i + 2 + length].decode("utf-8", errors="replace")
                op, i = ("LITERAL", lit), i + 2 + length

            case Opcode.RESTORE_POS:
                op, i = "RESTORE_POS", i + 1

            case Opcode.PUSH_STATE:
                op, i = "PUSH_STATE", i + 1

            case Opcode.POP_STATE:
                op, i = "POP_STATE", i + 1

            case Opcode.SUCCESS:
                op, i = "SUCCESS", i + 1

            case Opcode.RANGE:
                flags = fsa[i + 1]
                cnt = (flags & 0x7F) + 1
                rngs = [(fsa[i + 2 + 2 * j], fsa[i + 3 + 2 * j]) for j in range(cnt)]
                mode = "RANGE_EXCLUSIVE" if (flags & 0x80) else "RANGE_INCLUSIVE"
                op, i = (mode, rngs), i + 2 + cnt * 2

            case Opcode.MATCH:
                op, i = "MATCH", i + 1

            case Opcode.JNE_EXT:
                off = int.from_bytes(fsa[i + 1 : i + 3], "little") + 0x81
                target = start + 3 + off
                op, i = ("JNE", target), i + 3

            case _ if Opcode.LITERAL_SHORT.start <= opcode <= Opcode.LITERAL_SHORT.stop:
                length = (opcode & 0x3F) + 1
                lit = fsa[i + 1 : i + 1 + length].decode("utf-8", errors="replace")
                op, i = ("LITERAL", lit), i + 1 + length
            case _ if Opcode.JNE_SHORT.start <= opcode <= Opcode.JNE_SHORT.stop:
                off = (opcode & 0x7F) + 1
                target = start + 1 + off
                op, i = ("JNE", target), i + 1
            case (
                _
            ) if Opcode.CALLBACK_SHORT.start <= opcode <= Opcode.CALLBACK_SHORT.stop:
                op, i = ("CALLBACK", opcode & 0xF), i + 1

            case _:
                raise KeyError(f"Unknown opcode 0x{opcode:02x} at offset {start}")

        ops[start] = op

    return ops


def convert_operations(ops: Dict[int, Operation]) -> Dict[int, Operation]:
    """Reindex operations and adjust JNE targets using match/case."""
    sorted_pcs = sorted(ops)
    idx_map = {pc: idx for idx, pc in enumerate(sorted_pcs)}

    new_ops: Dict[int, Operation] = {}
    for pc, val in ops.items():
        idx = idx_map[pc]
        match val:
            case ("JNE", tgt):
                new_ops[idx] = ("JNE", idx_map[tgt])
            case other:
                new_ops[idx] = other
    return new_ops


def generate_paths(operations: Dict[int, Operation]) -> List[Path]:
    def truncate(path: Path) -> Path:
        for j, idx in enumerate(path):
            if operations[idx] == "PUSH_STATE":
                return path[:j]
        return path

    queue = deque([(0, [])])
    result: List[Path] = []

    while queue:
        pc, path = queue.pop()
        op = operations.get(pc)
        if op is None:
            continue

        match op:
            case "SUCCESS":
                result.append(path)

            case ("JNE", tgt):
                queue.append((pc + 1, path + [pc]))
                queue.append((tgt, path[:-1] + [pc]))

            case "RESTORE_POS":
                queue.append((pc + 1, truncate(path)))

            case _:
                queue.append((pc + 1, path + [pc]))

    return result


def ranges_to_regex(ranges, mode):
    def escape_char(c):
        if 32 <= c <= 126 and chr(c) not in {"\\", "[", "]", "^", "-"}:
            return chr(c)
        else:
            return f"\\x{c:02x}"

    parts = []
    for start, end in ranges:
        start_char = escape_char(start)
        end_char = escape_char(end)
        parts.append(f"{start_char}-{end_char}")

    char_class = "".join(parts)
    return f"[^{char_class}]" if mode == "RANGE_EXCLUSIVE" else f"[{char_class}]"


def convert_paths_to_strings(
    paths: List[Path], operations: Dict[int, Operation], callback_map: Mapping[int, str]
) -> List[str]:
    results: set[str] = set()
    for path in paths:
        parts: List[str] = []
        for idx in path:
            match operations[idx]:
                case ("LITERAL", text):
                    parts.append(text)
                case ("CALLBACK", cb):
                    parts.append(callback_map[cb])
                case (("MATCH_SEQ" | "MATCH_BYTE"), arg):
                    parts.append(f".+{chr(arg)}")
                case ("RANGE_EXCLUSIVE", ranges):
                    parts.append(ranges_to_regex(ranges, "RANGE_EXCLUSIVE"))
                case ("RANGE_INCLUSIVE", ranges):
                    parts.append(ranges_to_regex(ranges, "RANGE_INCLUSIVE"))
                case _:
                    pass
        results.add("".join(parts))

    return sorted(results)


def parse_fsm_string(fsm_bytes: bytes, global_vars: Sequence[str]) -> List[str]:
    callback_map = {i: f"${{{name.upper()}}}" for i, name in enumerate(global_vars)}
    ops = parse_fsa_pattern_bytecode(fsm_bytes, debug=False)
    indexed = convert_operations(ops)
    paths = generate_paths(indexed)
    return convert_paths_to_strings(paths, indexed, callback_map)
