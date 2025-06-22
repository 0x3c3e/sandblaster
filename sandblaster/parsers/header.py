from dataclasses import dataclass
from typing import BinaryIO
import struct

# ─── Low‑level constants ────────────────────────────────────────────────────────
INDEX_SIZE = 2
OPERATION_NODE_SIZE = 8
PROFILE_OPS_OFFSET = 4  # per‑profile fixed header

# ─── Helper functions ───────────────────────────────────────────────────────────
def align_up(value: int, alignment: int = 8) -> int:
    mask = alignment - 1
    return (value + mask) & ~mask


# ─── Main data model ────────────────────────────────────────────────────────────
@dataclass(slots=True)
class SandboxHeader:
    # • Raw header fields •
    header_size: int
    type: int
    op_nodes_count: int
    sb_ops_count: int
    vars_count: int
    regex_count: int
    states_count: int = 0
    num_profiles: int = 0
    entitlements_count: int = 0

    # ── Offset & size properties ────────────────────────────────────────────────
    @property
    def regex_table_offset(self) -> int:
        return self.header_size

    @property
    def vars_offset(self) -> int:
        return self.regex_table_offset + self.regex_count * INDEX_SIZE

    @property
    def states_offset(self) -> int:
        return self.vars_offset + self.vars_count * INDEX_SIZE

    @property
    def entitlements_offset(self) -> int:
        return self.states_offset + self.states_count * INDEX_SIZE

    @property
    def profiles_offset(self) -> int:
        return self.entitlements_offset + self.entitlements_count * INDEX_SIZE

    @property
    def profile_record_size(self) -> int:
        return self.sb_ops_count * INDEX_SIZE + PROFILE_OPS_OFFSET

    @property
    def profiles_end_offset(self) -> int:
        return self.profiles_offset + self.num_profiles * self.profile_record_size

    @property
    def operation_nodes_size(self) -> int:
        return self.op_nodes_count * OPERATION_NODE_SIZE

    @property
    def operation_nodes_offset(self) -> int:
        return align_up(self.profiles_end_offset + self.sb_ops_count * INDEX_SIZE)

    @property
    def base_addr(self) -> int:
        return self.operation_nodes_offset + self.operation_nodes_size

    # ── Factory method ──────────────────────────────────────────────────────────
    @classmethod
    def from_file(cls, infile: BinaryIO) -> "SandboxHeader":
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
