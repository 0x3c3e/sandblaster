from dataclasses import dataclass, field
from typing import List, Tuple, Optional, BinaryIO
import struct
import sys
import logging

from parsers.specialized.globals_parser import GlobalVarsParser
from parsers.specialized.regex_parser import RegexListParser
from parsers.node.node import NodeParser
from parsers.node.graph import NodeGraph
from filters.filter_resolver import FilterResolver
from filters.modifier_resolver import ModifierResolver
from filters.terminal_resolver import TerminalResolver


@dataclass(slots=True)
class SandboxPayload:
    infile: BinaryIO
    base_addr: int

    op_table: Optional[Tuple[int, ...]] = None
    regex_list: List[str] = field(default_factory=list)
    global_vars: List[str] = field(default_factory=list)
    policies: Optional[Tuple[int, ...]] = None
    sb_ops: List[str] = field(default_factory=list)
    operation_nodes: Optional[object] = None
    ops_to_reverse: List[str] = field(default_factory=list)

    def parse(
        self,
        sandbox_data: object,
        operations_file: str,
        operation_filter: Optional[List[str]],
        filters,
        modifiers,
        terminals,
    ) -> None:
        self._read_sandbox_operations(operations_file)
        if operation_filter:
            self._filter_operations(operation_filter)

        self.regex_list = RegexListParser.parse(
            self.infile,
            self.base_addr,
            sandbox_data.regex_count,
            sandbox_data.regex_table_offset,
        )
        self.global_vars = GlobalVarsParser.parse(
            self.infile,
            self.base_addr,
            sandbox_data.vars_count,
            sandbox_data.vars_offset,
        )
        self._parse_policies(
            sandbox_data.entitlements_offset, sandbox_data.entitlements_count
        )
        self._create_operation_nodes(
            sandbox_data.op_nodes_count,
            sandbox_data.operation_nodes_offset,
            filters,
            modifiers,
            terminals,
        )
        self._parse_op_table(sandbox_data.sb_ops_count, sandbox_data.profiles_offset)

    def _read_sandbox_operations(self, path: str) -> None:
        with open(path, "r") as f:
            self.sb_ops = [line.strip() for line in f if line.strip()]
        logging.info(f"Read {len(self.sb_ops)} sandbox operations")

    def _filter_operations(self, ops: List[str]) -> None:
        missing = [op for op in ops if op not in self.sb_ops]
        if missing:
            logging.error(f"Invalid operations requested: {missing}")
            sys.exit(1)
        self.ops_to_reverse = ops
        logging.info(f"Filtered operations: {ops}")

    def _parse_policies(self, offset: int, count: int) -> None:
        self.infile.seek(offset)
        self.policies = struct.unpack(f"<{count}H", self.infile.read(2 * count))

    def _create_operation_nodes(
        self, count: int, offset: int, filters, modifiers, terminals
    ) -> None:
        filter_resolver = FilterResolver(
            self.infile, self.base_addr, self.regex_list, self.global_vars, filters
        )
        modifier_resolver = ModifierResolver(
            self.infile, self.base_addr, self.regex_list, self.global_vars, modifiers
        )
        self.infile.seek(offset)
        parser = NodeParser()
        nodes, flags = parser.parse(
            self.infile,
            count,
        )
        graph = NodeGraph(nodes)
        terminal_resolver = TerminalResolver(terminals, flags)
        graph.link()
        graph.convert(
            self,
            filter_resolver,
            modifier_resolver,
            terminal_resolver,
        )
        self.operation_nodes = graph
        logging.info(f"Parsed {count} operation nodes")

    def _parse_op_table(self, count: int, offset: int) -> None:
        self.infile.seek(offset)
        self.op_table = struct.unpack(f"<{count}H", self.infile.read(2 * count))
