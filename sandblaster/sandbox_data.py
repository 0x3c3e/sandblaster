from dataclasses import dataclass, field
from typing import List, Optional, Tuple
import struct

REGEX_TABLE_OFFSET = 2
REGEX_COUNT_OFFSET = 4
VARS_TABLE_OFFSET = 6
VARS_COUNT_OFFSET = 8
NUM_PROFILES_OFFSET = 10
PROFILE_OPS_OFFSET = 4
OPERATION_NODE_SIZE = 8
INDEX_SIZE = 2


# split it into several classes?
@dataclass
class SandboxData:
    header_size: int
    type: int
    op_nodes_count: int
    sb_ops_count: int
    vars_count: int
    regex_count: int
    states_count: int = field(default=0)
    num_profiles: int = field(default=0)
    entitlements_count: int = field(default=0)
    instructions_count: int = field(default=0)
    op_table: int = field(default=None)
    builder: int = field(default=None)

    regex_table_offset: int = field(init=False)
    vars_offset: int = field(init=False)
    states_offset: int = field(init=False)
    entitlements_offset: int = field(init=False)
    profiles_offset: int = field(init=False)
    profiles_end_offset: int = field(init=False)
    operation_nodes_size: int = field(init=False)
    operation_nodes_offset: int = field(init=False)
    base_addr: int = field(init=False)

    regex_list: Optional[List[str]] = field(default_factory=list)
    global_vars: Optional[List[str]] = field(default_factory=list)
    policies: Optional[Tuple[int]] = field(default=None)
    sb_ops: Optional[List[str]] = field(default_factory=list)
    operation_nodes: Optional[List[object]] = field(default=None)
    ops_to_reverse: Optional[List[str]] = field(default_factory=list)

    def __post_init__(self):
        self.regex_table_offset = self.header_size
        self.vars_offset = self.regex_table_offset + (self.regex_count * INDEX_SIZE)
        self.states_offset = self.vars_offset + (self.vars_count * INDEX_SIZE)
        self.entitlements_offset = self.states_offset + (self.states_count * INDEX_SIZE)
        self.profiles_offset = self.entitlements_offset + (
            self.entitlements_count * INDEX_SIZE
        )
        self.profiles_end_offset = self.profiles_offset + (
            self.num_profiles * (self.sb_ops_count * INDEX_SIZE + PROFILE_OPS_OFFSET)
        )
        self.operation_nodes_size = self.op_nodes_count * OPERATION_NODE_SIZE
        self.operation_nodes_offset = self.profiles_end_offset
        self.operation_nodes_offset += self.sb_ops_count * INDEX_SIZE
        align_delta = self.operation_nodes_offset & 7
        if align_delta != 0:
            self.operation_nodes_offset += 8 - align_delta
        self.base_addr = self.operation_nodes_offset + self.operation_nodes_size

    @classmethod
    def from_file(cls, infile: object) -> "SandboxData":
        macos15_2_struct = struct.Struct("<HHBB6xHH")
        values = macos15_2_struct.unpack(infile.read(macos15_2_struct.size))
        return cls(
            header_size=macos15_2_struct.size,
            type=values[0],
            op_nodes_count=values[1],
            sb_ops_count=values[2],
            vars_count=values[3],
            regex_count=values[4],
        )
