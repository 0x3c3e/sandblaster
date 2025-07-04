from collections import deque
from typing import Any, Dict, List, Mapping, Sequence, Tuple, Union

from sandblaster.parsers.fsa_parser.decoder import parse_fsa_pattern_bytecode
from sandblaster.parsers.fsa_parser.utils import ranges_to_regex

Operation = Union[str, Tuple[str, Any]]
Path = List[int]


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
    ops = parse_fsa_pattern_bytecode(fsm_bytes)
    indexed = convert_operations(ops)
    paths = generate_paths(indexed)
    return convert_paths_to_strings(paths, indexed, callback_map)
