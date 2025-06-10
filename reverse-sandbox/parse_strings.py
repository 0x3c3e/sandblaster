from collections import deque
from typing import Any, Dict, List, Mapping, Sequence, Tuple, Union

# Type aliases for clarity
Operation = Union[str, Tuple[str, Any]]
Path = List[int]


def parse_fsa_pattern_bytecode(fsa: bytes, debug: bool = True) -> Dict[int, Operation]:
    """Parse FSA bytecode into a mapping of byte offsets to operations using match/case."""
    i = 0
    ops: Dict[int, Operation] = {}
    n = len(fsa)

    while i < n:
        opcode = fsa[i]
        start = i

        match opcode:
            case _ if 0x10 <= opcode <= 0x1F:
                op = ("CALLBACK", opcode & 0xF)
                i += 1

            case 0x00:
                op = "ASSERT_EOS"
                i += 1

            case 0x01:
                callback_id = int.from_bytes(fsa[i+1:i+3], "little")
                op = ("CALLBACK", callback_id)
                i += 3

            case 0x02:
                op = ("MATCH_BYTE", fsa[i+1])
                i += 2

            case 0x03:
                op = ("MATCH_SEQ", fsa[i+1])
                i += 2

            case 0x04:
                length_ = fsa[i+1] + 0x41
                literal = fsa[i+2:i+2+length_].decode("utf-8", errors="replace")
                op = ("LITERAL", literal)
                i += 2 + length_

            case _ if 0x40 <= opcode <= 0x7F:
                length_ = (opcode & 0x3F) + 1
                literal = fsa[i+1:i+1+length_].decode("utf-8", errors="replace")
                op = ("LITERAL", literal)
                i += 1 + length_

            case 0x05:
                op = "RESTORE_POS"
                i += 1

            case 0x06:
                op = "PUSH_STATE"
                i += 1

            case 0x07:
                op = "POP_STATE"
                i += 1

            case 0x0A:
                op = "SUCCESS"
                i += 1

            case 0x0B:
                flags = fsa[i+1]
                count = (flags & 0x7F) + 1
                ranges = [(fsa[i+2+j*2], fsa[i+3+j*2]) for j in range(count)]
                mode = "RANGE_EXCLUSIVE" if (flags & 0x80) else "RANGE_INCLUSIVE"
                op = (mode, ranges)
                i += 2 + count*2

            case 0x0F:
                op = "MATCH"
                i += 1

            case 0x08:
                offset = int.from_bytes(fsa[i+1:i+3], "little") + 0x81
                target = start + 3 + offset
                op = ("JNE", target)
                i += 3

            case 0x11:
                start_b, end_b = fsa[i+1], fsa[i+2]
                op = ("MATCH_BYTESET", (start_b, end_b))
                i += 3

            case _ if 0x80 <= opcode <= 0xFF:
                offset = (opcode & 0x7F) + 1
                target = start + 1 + offset
                op = ("JNE", target)
                i += 1

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
    """Traverse operations with match/case to collect successful paths."""
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
                queue.append((pc+1, path + [pc]))
                queue.append((tgt, path[:-1] + [pc]))

            case "RESTORE_POS":
                queue.append((pc+1, truncate(path)))

            case _:
                queue.append((pc+1, path + [pc]))

    return result


def ranges_to_regex(ranges, mode):
    def escape_char(c):
        if 32 <= c <= 126 and chr(c) not in {'\\', '[', ']', '^', '-'}:
            return chr(c)
        else:
            return f"\\x{c:02x}"

    parts = []
    for start, end in ranges:
        start_char = escape_char(start)
        end_char = escape_char(end)
        parts.append(f'{start_char}-{end_char}')

    char_class = ''.join(parts)
    return f'[^{char_class}]' if mode == "RANGE_EXCLUSIVE" else f'[{char_class}]'
    
def convert_paths_to_strings(
    paths: List[Path],
    operations: Dict[int, Operation],
    callback_map: Mapping[int, str]
) -> List[str]:
    """Convert index paths into string patterns."""
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
    print(fsm_bytes)
    """End-to-end parsing: use match/case throughout."""
    callback_map = {i: f"[{name}]" for i, name in enumerate(global_vars)}
    ops = parse_fsa_pattern_bytecode(fsm_bytes, debug=False)
    indexed = convert_operations(ops)
    print(indexed)
    paths = generate_paths(indexed)
    return convert_paths_to_strings(paths, indexed, callback_map)


if __name__ == "__main__":
    inp = b'I/.trashes/\x0f\x0b\x810\xff\x00.\x00\x0f\n'

    print(parse_fsm_string(inp, ["a", "b", "c"]))