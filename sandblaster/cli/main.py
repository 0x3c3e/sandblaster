import argparse
import mmap
from importlib.resources import files

from sandblaster.configs.filters import Filters
from sandblaster.filters.filter_resolver import FilterResolver
from sandblaster.filters.modifier_resolver import ModifierResolver
from sandblaster.filters.terminal_resolver import TerminalResolver
from sandblaster.parsers.analysis.bool_expressions import process_profile
from sandblaster.parsers.core.header import SandboxHeader
from sandblaster.parsers.core.sandbox import SandboxParser


def read_sandbox_operations(path: str) -> None:
    with open(path, "r") as f:
        ops = [line.strip() for line in f if line.strip()]
    return ops


def parse_args():
    parser = argparse.ArgumentParser(description="Apple Sandbox Profiles Decompiler")
    parser.add_argument("filename")
    parser.add_argument(
        "--operations",
        required=True,
    )
    parser.add_argument("--filter", nargs="+")
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    filters = Filters(files("sandblaster.misc") / "filters.json")
    modifiers = Filters(files("sandblaster.misc") / "modifiers.json")
    sandbox_operations = read_sandbox_operations(args.operations)
    with open(args.filename, "rb") as infile:
        mm = mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ)
        sandbox_data = SandboxHeader(mm)
        sandbox_parser = SandboxParser(infile=mm, base_addr=sandbox_data.base_addr)
        sandbox_payload = sandbox_parser.parse(
            sandbox_data, sandbox_operations, args.filter
        )
        sandbox_parser.create_operation_nodes(
            sandbox_data.header.op_nodes_count,
            sandbox_data.operation_nodes_offset,
        )
        filter_resolver = FilterResolver(
            mm,
            sandbox_data.base_addr,
            sandbox_parser.payload.regex_list,
            sandbox_parser.payload.global_vars,
            filters,
        )
        modifier_resolver = ModifierResolver(
            mm,
            sandbox_data.base_addr,
            sandbox_parser.payload.regex_list,
            sandbox_parser.payload.global_vars,
            modifiers,
        )
        terminal_resolver = TerminalResolver(modifiers, sandbox_parser.flags)
        process_profile(
            sandbox_payload, filter_resolver, modifier_resolver, terminal_resolver
        )
        mm.close()
    return 0
