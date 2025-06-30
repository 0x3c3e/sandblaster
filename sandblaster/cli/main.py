import argparse
from sandblaster.parsers.header import SandboxHeader
from sandblaster.parsers.sandbox import SandboxParser
from sandblaster.configs.filters import Filters
from sandblaster.parsers.bool_expressions import process_profile
from importlib.resources import files


def main() -> int:
    parser = argparse.ArgumentParser(description="Apple Sandbox Profiles Decompiler")
    parser.add_argument("filename")
    parser.add_argument(
        "--operations",
        required=True,
    )
    parser.add_argument("--filter", nargs="+")
    parser.add_argument("--output", required=True)

    args = parser.parse_args()

    filters = Filters(files("sandblaster.misc") / "filters.json")
    modifiers = Filters(files("sandblaster.misc") / "modifiers.json")
    with open(args.filename, "rb") as infile:
        sandbox_data = SandboxHeader.from_file(infile)
        sandbox_parser = SandboxParser(infile=infile, base_addr=sandbox_data.base_addr)
        sandbox_payload = sandbox_parser.parse(
            sandbox_data, args.operations, args.filter
        )
        sandbox_parser.create_operation_nodes(
            sandbox_data.op_nodes_count,
            sandbox_data.operation_nodes_offset,
            filters,
            modifiers,
        )

    process_profile(sandbox_payload)
    return 0
