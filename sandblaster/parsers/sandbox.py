import logging
import struct
from typing import BinaryIO, List, Optional

from sandblaster.parsers.node.graph import NodeGraph
from sandblaster.parsers.node.node import NodeParser
from sandblaster.parsers.profile import SandboxPayload
from sandblaster.parsers.specialized.globals_parser import GlobalVarsParser
from sandblaster.parsers.specialized.regex_parser import RegexListParser


class SandboxParser:
    def __init__(self, infile: BinaryIO, base_addr: int):
        self.infile = infile
        self.base_addr = base_addr
        self.payload = SandboxPayload(infile=infile, base_addr=base_addr)

    def parse(
        self,
        sandbox_data: object,
        operations_file: str,
        operation_filter: Optional[List[str]],
    ) -> SandboxPayload:
        self._read_sandbox_operations(operations_file)
        self.payload.regex_list = RegexListParser.parse(
            self.infile,
            self.base_addr,
            sandbox_data.regex_count,
            sandbox_data.regex_table_offset,
        )
        self.payload.global_vars = GlobalVarsParser.parse(
            self.infile,
            self.base_addr,
            sandbox_data.vars_count,
            sandbox_data.vars_offset,
        )
        self._parse_policies(
            sandbox_data.entitlements_offset, sandbox_data.entitlements_count
        )
        self._parse_op_table(sandbox_data.sb_ops_count, sandbox_data.profiles_offset)
        self._filter_operations(operation_filter)
        return self.payload

    def _read_sandbox_operations(self, path: str) -> None:
        with open(path, "r") as f:
            self.payload.sb_ops = [line.strip() for line in f if line.strip()]
        logging.info(f"Read {len(self.payload.sb_ops)} sandbox operations")

    def _filter_operations(self, ops: List[str]) -> None:
        if not ops:
            self.payload.ops_to_reverse = list(range(0, len(self.payload.op_table)))
            return
        missing = [op for op in ops if op not in self.payload.sb_ops]
        if missing:
            logging.error(f"Invalid operations requested: {missing}")
            raise ValueError
        self.payload.ops_to_reverse = [self.payload.sb_ops.index(op) for op in ops]
        logging.info(f"Filtered operations: {ops}")

    def _parse_policies(self, offset: int, count: int) -> None:
        self.infile.seek(offset)
        self.payload.policies = struct.unpack(f"<{count}H", self.infile.read(2 * count))

    def create_operation_nodes(self, count: int, offset: int) -> None:
        self.infile.seek(offset)
        parser = NodeParser()
        nodes, flags = parser.parse(
            self.infile,
            count,
        )
        graph = NodeGraph(nodes)
        graph.link()
        self.payload.operation_nodes = graph
        logging.info(f"Parsed {count} operation nodes")

    def _parse_op_table(self, count: int, offset: int) -> None:
        self.infile.seek(offset)
        self.payload.op_table = struct.unpack(f"<{count}H", self.infile.read(2 * count))
