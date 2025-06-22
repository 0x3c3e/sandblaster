from dataclasses import dataclass, field
from typing import List, Tuple, Optional
import struct
import sys
import parsers.regex as regex
from nodes import operation_node_parser


@dataclass(slots=True)
class SandboxPayload:
    op_table: Optional[int] = None
    regex_list: List[str] = field(default_factory=list)
    global_vars: List[str] = field(default_factory=list)
    policies: Optional[Tuple[int]] = None
    sb_ops: List[str] = field(default_factory=list)
    operation_nodes: Optional[List[object]] = None
    ops_to_reverse: List[str] = field(default_factory=list)

    def create_operation_nodes(
        self, infile: object, op_nodes_count, sandbox_data
    ) -> List[object]:
        self.operation_nodes = operation_node_parser.OperionNodeParser()
        self.operation_nodes.build_operation_nodes(infile, op_nodes_count, sandbox_data)

    def parse_global_vars(
        self, f: object, vars_offset, vars_count, base_addr
    ) -> List[str]:
        next_var_pointer = vars_offset

        for _ in range(vars_count):
            f.seek(next_var_pointer)
            var_offset = struct.unpack("<H", f.read(2))[0]
            f.seek(base_addr + (var_offset * 8))
            string_len = struct.unpack("H", f.read(2))[0]
            var_string = f.read(string_len - 1).decode("utf-8")
            self.global_vars.append(var_string)
            next_var_pointer += 2

    def parse_policies(
        self, f: object, entitlements_offset, entitlements_count
    ) -> Tuple[int]:
        f.seek(entitlements_offset)
        self.policies = struct.unpack(
            f"<{entitlements_count}H",
            f.read(2 * entitlements_count),
        )

    def read_sandbox_operations(self, operations_file):
        with open(operations_file) as file:
            self.sb_ops = [line.strip() for line in file.readlines()]

    def filter_sandbox_operations(self, operation):
        for op in operation:
            if op not in self.sb_ops:
                sys.exit(1)
            self.ops_to_reverse.append(op)

    def parse_regex_list(
        self, infile: object, regex_count, regex_table_offset, base_addr
    ):
        if not regex_count:
            return

        infile.seek(regex_table_offset)
        offsets_table = struct.unpack(
            f"<{regex_count}H",
            infile.read(2 * regex_count),
        )

        for offset in offsets_table:
            infile.seek(offset * 8 + base_addr)
            re_length = struct.unpack("<H", infile.read(2))[0]
            data = infile.read(re_length)
            self.regex_list.append(regex.analyze(data))

    def parse_op_table(self, infile: object, sb_ops_count):
        self.op_table = struct.unpack(
            f"<{sb_ops_count}H",
            infile.read(2 * sb_ops_count),
        )
