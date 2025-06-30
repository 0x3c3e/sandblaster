import re
from collections import defaultdict
from typing import Dict, Tuple, Any, Sequence
from enum import IntEnum

from automata.fa.nfa import NFA
from automata.fa.dfa import DFA
from automata.fa.gnfa import GNFA

Op = Tuple[str, Any]

MAGIC_NUMBER = 0x3000000
HEADER_MAGIC_SIZE = 4
HEADER_LENGTH_SIZE = 2


class OpCode(IntEnum):
    CHAR = 0x02
    START = 0x19
    END = 0x29
    ANY = 0x09
    MATCH = 0x05
    JMP_BEHIND = 0x0A
    JMP_AHEAD = 0x2F
    CLASS = 0x0B


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
                    self.instructions[idx] = ("chr", re.escape(char))
                    i += 2
                case OpCode.START:
                    self.instructions[idx] = ("chr", "^")
                    i += 1
                case OpCode.END:
                    self.instructions[idx] = ("chr", "$")
                    i += 1
                case OpCode.ANY:
                    self.instructions[idx] = ("chr", ".")
                    i += 1
                case x if (x & 0xF) == OpCode.MATCH:
                    self.instructions[idx] = ("match", None)
                    i += 1
                case x if x == OpCode.JMP_AHEAD or (x & 0xF) == OpCode.JMP_BEHIND:
                    offset = data[i + 1] | (data[i + 2] << 8)
                    self.instructions[idx] = ("jmp", offset)
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
                    self.instructions[idx] = ("chr", value)
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
                case "jmp", offset if isinstance(offset, int):
                    remapped[new_idx] = ("jmp", index_map.get(offset, offset))
                case other_op, other_arg:
                    remapped[new_idx] = (other_op, other_arg)
        self.instructions = remapped
        return remapped


def bytecode_to_nfa(instructions: Dict[int, Op]) -> Tuple[NFA, Dict[str, str]]:
    transitions = defaultdict(lambda: defaultdict(set))
    start_state = "q0"
    state_map: Dict[int, str] = {}
    final_states = set()
    symbol_map: Dict[str, str] = {}
    epsilon = ""

    # Helper to generate new states
    def new_state(idx: int) -> str:
        return f"q{idx + 1}"

    for idx in instructions:
        state_map[idx] = new_state(idx)

    for idx, instr in instructions.items():
        curr = state_map[idx]
        next_idx = idx + 1
        match instr:
            case "chr", pattern:
                placeholder = chr(0xE000 + idx)
                symbol_map[placeholder] = pattern
                if pattern == "$":
                    final_states.add(curr)
                elif next_idx in state_map:
                    transitions[curr][placeholder].add(state_map[next_idx])
            case "jmp", target if isinstance(target, int):
                if target in state_map:
                    transitions[curr][epsilon].add(state_map[target])
                if next_idx in state_map:
                    transitions[curr][epsilon].add(state_map[next_idx])
            case "match", None:
                final_states.add(curr)
            case _:
                continue

    if instructions:
        first = min(instructions.keys())
        transitions[start_state][epsilon].add(state_map[first])

    nfa = NFA(
        states=set(state_map.values()) | {start_state},
        input_symbols={
            s for trans in transitions.values() for s in trans if s != epsilon
        },
        transitions={state: dict(edges) for state, edges in transitions.items()},
        initial_state=start_state,
        final_states=final_states,
    )
    return nfa, symbol_map


def analyze(bytecode: Sequence[int]) -> str:
    parser = RegexBytecodeParser(bytes(bytecode))
    parser.parse()
    remapped = parser.remap()
    nfa, symmap = bytecode_to_nfa(remapped)
    dfa = DFA.from_nfa(nfa, minify=True)
    gnfa = GNFA.from_dfa(dfa)
    regex = gnfa.to_regex()

    for placeholder, literal in symmap.items():
        escaped = literal.encode("unicode_escape").decode("utf-8")
        regex = regex.replace(placeholder, escaped)
    return regex
