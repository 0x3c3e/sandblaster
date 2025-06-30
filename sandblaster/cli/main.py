import argparse
from sandblaster.parsers.header import SandboxHeader
from sandblaster.parsers.profile import SandboxPayload
from sandblaster.parsers.sandbox import SandboxParser
from sandblaster.configs.filters import Filters
from importlib.resources import files
from sandblaster.graphs.graph import get_nnf_forms
import pprint


def process_profile(payload: SandboxPayload) -> None:
    for idx in payload.ops_to_reverse:
        print(payload.sb_ops[idx])
        offset = payload.op_table[idx]

        node = payload.operation_nodes.find_operation_node_by_offset(offset)
        if not node:
            continue
        nnf_forms = get_nnf_forms(node)
        pprint.pprint(nnf_forms)


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
