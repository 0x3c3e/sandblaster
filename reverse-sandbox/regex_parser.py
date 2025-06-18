import re
from collections import defaultdict
from typing import Dict, Tuple, Any, Sequence
from enum import IntEnum

from automata.fa.nfa import NFA
from automata.fa.dfa import DFA
from automata.fa.gnfa import GNFA

Op = Tuple[str, Any]

# Header constants
MAGIC_NUMBER = 0x3000000
HEADER_MAGIC_SIZE = 4
HEADER_LENGTH_SIZE = 2


class OpCode(IntEnum):
    CHAR = 0x02
    LINE_START = 0x19
    LINE_END = 0x29
    ANY = 0x09
    MATCH_LOW_NIBBLE = 0x05
    JMP_LOW_NIBBLE = 0x0A
    JMP_EXACT = 0x2F
    SET_BASE_LOW_NIBBLE = 0x0B


class RegexBytecodeParser:
    """
    Parses and normalizes regex bytecode into a linear instruction map.
    """

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
                case OpCode.LINE_START:
                    self.instructions[idx] = ("chr", "^")
                    i += 1
                case OpCode.LINE_END:
                    self.instructions[idx] = ("chr", "$")
                    i += 1
                case OpCode.ANY:
                    self.instructions[idx] = ("chr", ".")
                    i += 1
                case x if (x & 0xF) == OpCode.MATCH_LOW_NIBBLE:
                    self.instructions[idx] = ("match", None)
                    i += 1
                case x if x == OpCode.JMP_EXACT or (x & 0xF) == OpCode.JMP_LOW_NIBBLE:
                    offset = data[i + 1] | (data[i + 2] << 8)
                    self.instructions[idx] = ("jmp", offset)
                    i += 3
                case x if (x & 0xF) == OpCode.SET_BASE_LOW_NIBBLE:
                    count = x >> 4
                    ranges = []
                    start = i + 1
                    for j in range(count):
                        lo = data[start + 2 * j]
                        hi = data[start + 2 * j + 1]
                        ranges.append(f"{chr(lo)}-{chr(hi)}" if lo < hi else chr(lo))
                    self.instructions[idx] = ("chr", f"[{''.join(ranges)}]")
                    i += 1 + 2 * count
                case _:
                    i += 1

        return self.instructions

    def remap(self) -> Dict[int, Op]:
        """
        Reassigns instruction indices to a contiguous range and adjusts jumps.
        """
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
        input_symbols={s for trans in transitions.values() for s in trans if s != epsilon},
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
