import argparse
import mmap
from importlib.resources import files

from sandblaster.configs.filters import Filters
from sandblaster.filters.filter_resolver import FilterResolver
from sandblaster.filters.modifier_resolver import ModifierResolver
from sandblaster.parsers.bool_expressions import process_profile
from sandblaster.parsers.header import SandboxHeader
from sandblaster.parsers.sandbox import SandboxParser


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
    with open(args.filename, "rb") as infile:
        mm = mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ)
        sandbox_data = SandboxHeader(mm)
        sandbox_parser = SandboxParser(infile=mm, base_addr=sandbox_data.base_addr)
        sandbox_payload = sandbox_parser.parse(
            sandbox_data, args.operations, args.filter
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
        process_profile(sandbox_payload, filter_resolver, modifier_resolver)
        mm.close()
    return 0
