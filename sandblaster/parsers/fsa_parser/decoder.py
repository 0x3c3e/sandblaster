from typing import Any, Dict, List, Tuple, Union

from sandblaster.parsers.fsa_parser.opcode import Opcode
from sandblaster.parsers.fsa_parser.state import State

Operation = Union[str, Tuple[str, Any]]
Path = List[int]


def _read_u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _read_literal(data: bytes, offset: int, length: int) -> Tuple[str, int]:
    lit = data[offset : offset + length].decode("utf-8", errors="replace")
    return lit, offset + length


def parse_fsa_pattern_bytecode(fsa: bytes) -> Dict[int, Operation]:
    i = 0
    ops: Dict[int, Operation] = {}
    n = len(fsa)

    while i < n:
        start = i
        opcode = fsa[i]

        match opcode:
            case Opcode.CALLBACK_EXT:
                op = (State.CALLBACK, _read_u16(fsa, i + 1))
                i += 3

            case Opcode.ASSERT_EOS:
                op, i = State.ASSERT, i + 1

            case Opcode.MATCH_BYTE:
                op = (State.MATCH_BYTE, fsa[i + 1])
                i += 2

            case Opcode.MATCH_SEQ:
                op = (State.MATCH_SEQ, fsa[i + 1])
                i += 2

            case Opcode.LITERAL_EXT:
                length = fsa[i + 1] + 0x41
                lit, end = _read_literal(fsa, i + 2, length)
                op, i = (State.LITERAL, lit), end

            case Opcode.RESTORE_POS:
                op, i = State.RESTORE_POS, i + 1

            case Opcode.PUSH_STATE:
                op, i = State.PUSH_STATE, i + 1

            case Opcode.POP_STATE:
                op, i = State.POP_STATE, i + 1

            case Opcode.SUCCESS:
                op, i = State.SUCCESS, i + 1

            case Opcode.RANGE:
                offset = i + 1
                flags = fsa[offset]
                count = (flags & 0x7F) + 1
                ranges = [
                    (fsa[offset + 1 + 2 * j], fsa[offset + 2 + 2 * j])
                    for j in range(count)
                ]
                mode = State.RANGE_EXCLUSIVE if flags & 0x80 else State.RANGE_INCLUSIVE
                op, i = (mode, ranges), offset + 1 + count * 2
                i += 1

            case Opcode.MATCH:
                op, i = State.MATCH, i + 1

            case Opcode.JNE_EXT:
                offset = _read_u16(fsa, i + 1) + 0x84
                op = (State.JNE, i + offset)
                i += 3

            case _ if Opcode.LITERAL_SHORT.start <= opcode <= Opcode.LITERAL_SHORT.stop:
                length = (opcode & 0x3F) + 1
                lit, end = _read_literal(fsa, i + 1, length)
                op, i = (State.LITERAL, lit), end

            case _ if Opcode.JNE_SHORT.start <= opcode <= Opcode.JNE_SHORT.stop:
                offset = (opcode & 0x7F) + 1
                op = (State.JNE, i + 1 + offset)
                i += 1

            case _ if Opcode.CALLBACK_SHORT.start <= opcode <= Opcode.CALLBACK_SHORT.stop:
                op = (State.CALLBACK, opcode & 0xF)
                i += 1

            case _:
                raise KeyError(f"Unknown opcode 0x{opcode:02x} at offset {start}")

        ops[start] = op

    return ops
