import re
from typing import Any, Dict, Tuple

from sandblaster.parsers.regex_parser.opcode import OpCode
from sandblaster.parsers.regex_parser.state import State

Op = Tuple[str, Any]


MAGIC_NUMBER = 0x3000000
HEADER_MAGIC_SIZE = 4
HEADER_LENGTH_SIZE = 2


class RegexBytecodeParser:
    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode
        self.instructions: Dict[int, Op] = {}

    def parse(self) -> Dict[int, Op]:
        data = self.bytecode
        if int.from_bytes(data[:HEADER_MAGIC_SIZE], "little") != MAGIC_NUMBER:
            raise ValueError("Invalid bytecode magic number")
        length = int.from_bytes(
            data[HEADER_MAGIC_SIZE : HEADER_MAGIC_SIZE + HEADER_LENGTH_SIZE], "little"
        )
        if len(data) != HEADER_MAGIC_SIZE + HEADER_LENGTH_SIZE + length:
            raise ValueError("Bytecode length mismatch")

        i = HEADER_MAGIC_SIZE + HEADER_LENGTH_SIZE
        while i < len(data):
            idx = i - (HEADER_MAGIC_SIZE + HEADER_LENGTH_SIZE)
            raw = data[i]

            match raw:
                case OpCode.CHAR:
                    char = chr(data[i + 1])
                    self.instructions[idx] = (State.CHR, re.escape(char))
                    i += 2
                case OpCode.START:
                    self.instructions[idx] = (State.CHR, "^")
                    i += 1
                case OpCode.END:
                    self.instructions[idx] = (State.CHR, "$")
                    i += 1
                case OpCode.ANY:
                    self.instructions[idx] = (State.CHR, ".")
                    i += 1
                case x if (x & 0xF) == OpCode.MATCH:
                    self.instructions[idx] = (State.MATCH, None)
                    i += 1
                case x if x == OpCode.JMP_AHEAD or (x & 0xF) == OpCode.JMP_BEHIND:
                    offset = data[i + 1] | (data[i + 2] << 8)
                    self.instructions[idx] = (State.JMP, offset)
                    i += 3
                case x if (x & 0xF) == OpCode.CLASS:
                    count = x >> 4
                    values = []
                    start = i + 1
                    for j in range(count):
                        values.append(data[start + 2 * j])
                        values.append(data[start + 2 * j + 1])

                    first = values[0]
                    last = values[-1]
                    value = "["

                    if first > last:
                        value += "^"
                        values = [last] + values[:-1]
                        for j in range(len(values)):
                            if j % 2 == 0:
                                values[j] += 1
                            else:
                                values[j] -= 1

                    for j in range(0, len(values), 2):
                        lo = values[j]
                        hi = values[j + 1]
                        if lo < hi:
                            value += f"{chr(lo)}-{chr(hi)}"
                        else:
                            value += f"{chr(lo)}"

                    value += "]"
                    self.instructions[idx] = (State.CHR, value)
                    i += 1 + 2 * count
                case _:
                    i += 1

        return self.instructions

    def remap(self) -> Dict[int, Op]:
        orig_indices = sorted(self.instructions.keys())
        index_map = {orig: new for new, orig in enumerate(orig_indices)}

        remapped: Dict[int, Op] = {}
        for orig in orig_indices:
            new_idx = index_map[orig]
            op, arg = self.instructions[orig]
            match (op, arg):
                case State.JMP, offset if isinstance(offset, int):
                    remapped[new_idx] = (State.JMP, index_map.get(offset, offset))
                case other_op, other_arg:
                    remapped[new_idx] = (other_op, other_arg)
        self.instructions = remapped
        return remapped
