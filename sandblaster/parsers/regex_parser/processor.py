from collections import defaultdict
from typing import Any, Dict, Sequence, Tuple

from automata.fa.dfa import DFA
from automata.fa.gnfa import GNFA
from automata.fa.nfa import NFA

from sandblaster.parsers.regex_parser.parser import RegexBytecodeParser

Op = Tuple[str, Any]


def bytecode_to_nfa(instructions: Dict[int, Op]) -> Tuple[NFA, Dict[str, str]]:
    transitions = defaultdict(lambda: defaultdict(set))
    start_state = "q0"
    state_map: Dict[int, str] = {}
    final_states = set()
    symbol_map: Dict[str, str] = {}
    epsilon = ""

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
