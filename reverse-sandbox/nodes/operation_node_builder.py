import logging
from nodes.operation_node import OperationNode
import struct

logger = logging.getLogger(__name__)


class OperationNodeGraphBuilder:
    def __init__(self):
        self.processed_nodes = []
        self.paths = []
        self.current_path = []
        self.nodes_traversed_for_removal = []
        self.terminals = set()

    def has_been_processed(self, node):
        return node in self.processed_nodes

    def build_operation_node(self, raw, index):
        node = OperationNode(index, raw)
        node.parse_raw()
        return node

    def build_operation_nodes(self, f, num_operation_nodes):
        operation_nodes = []
        cache = {}

        for i in range(num_operation_nodes):
            raw = struct.unpack("<8B", f.read(8))
            node = self.build_operation_node(raw, i)
            operation_nodes.append(node)
            cache[node.offset] = node

        # Fill match and unmatch fields for each node in operation_nodes.
        for op_node in operation_nodes:
            if op_node.is_non_terminal():
                if op_node.non_terminal.match_offset in cache:
                    op_node.non_terminal.match = cache[
                        op_node.non_terminal.match_offset
                    ]

                if op_node.non_terminal.unmatch_offset in cache:
                    op_node.non_terminal.unmatch = cache[
                        op_node.non_terminal.unmatch_offset
                    ]

        return operation_nodes

    def find_operation_node_by_offset(self, operation_nodes, offset):
        for node in operation_nodes:
            if node.offset == offset:
                return node
        raise Exception(f"node.offset: {offset}")

    def ong_mark_not(self, g, node, parent_node):
        g[node]["not"] = True
        tmp = node.non_terminal.match
        node.non_terminal.match = node.non_terminal.unmatch
        node.non_terminal.unmatch = tmp
        tmp_offset = node.non_terminal.match_offset
        node.non_terminal.match_offset = node.non_terminal.unmatch_offset
        node.non_terminal.unmatch_offset = tmp_offset

    def ong_end_path(self, g, node, parent_node):
        # Here, we store the node’s matched terminal in "decision" for reference
        g[node]["decision"] = str(node.non_terminal.match.terminal)
        g[node]["type"].add("final")

    def ong_add_to_path(self, g, node, parent_node, nodes_to_process):
        if node.non_terminal.match and not self.has_been_processed(
            node.non_terminal.match
        ):
            g[node]["list"].add(node.non_terminal.match)
            nodes_to_process.add((node, node.non_terminal.match))

    def ong_add_to_parent_path(self, g, node, parent_node, nodes_to_process):
        if node.non_terminal.unmatch and not self.has_been_processed(
            node.non_terminal.unmatch
        ):
            if parent_node:
                g[parent_node]["list"].add(node.non_terminal.unmatch)
            nodes_to_process.add((parent_node, node.non_terminal.unmatch))

    def build_operation_node_graph(self, node, default_node):
        """
        Build the operation node graph starting from `node`, considering
        `default_node` to figure out whether it's an allow or deny scenario.
        """
        if node.is_terminal():
            return None

        # If node is non-terminal and has already been processed, then it's a jump rule.
        if self.has_been_processed(node):
            return None

        g = {}
        nodes_to_process = set()
        nodes_to_process.add((None, node))

        while nodes_to_process:
            (parent_node, current_node) = nodes_to_process.pop()

            if current_node not in g:
                g[current_node] = {
                    "list": set(),
                    "decision": None,
                    "type": {"normal"},
                    "reduce": None,
                    "not": False,
                }
            if not parent_node:
                g[current_node]["type"].add("start")

            # Switch on the default_node's action (deny or allow)
            if default_node.terminal.is_deny():
                # In case of non-terminal match and deny as unmatch, add match to path.
                if current_node.non_terminal.is_non_terminal_deny():
                    self.ong_add_to_path(g, current_node, parent_node, nodes_to_process)
                elif current_node.non_terminal.is_non_terminal_allow():
                    # Mark not (reverse), end path, add unmatch to parent path
                    self.ong_mark_not(g, current_node, parent_node)
                    self.ong_end_path(g, current_node, parent_node)
                    self.ong_add_to_parent_path(
                        g, current_node, parent_node, nodes_to_process
                    )
                elif current_node.non_terminal.is_non_terminal_non_terminal():
                    self.ong_add_to_path(g, current_node, parent_node, nodes_to_process)
                    self.ong_add_to_parent_path(
                        g, current_node, parent_node, nodes_to_process
                    )
                elif current_node.non_terminal.is_allow_non_terminal():
                    self.ong_end_path(g, current_node, parent_node)
                    self.ong_add_to_parent_path(
                        g, current_node, parent_node, nodes_to_process
                    )
                elif current_node.non_terminal.is_deny_non_terminal():
                    self.ong_mark_not(g, current_node, parent_node)
                    self.ong_add_to_path(g, current_node, parent_node, nodes_to_process)
                elif current_node.non_terminal.is_deny_allow():
                    self.ong_mark_not(g, current_node, parent_node)
                    self.ong_end_path(g, current_node, parent_node)
                elif current_node.non_terminal.is_allow_deny():
                    self.ong_end_path(g, current_node, parent_node)
            elif default_node.terminal.is_allow():
                if current_node.non_terminal.is_non_terminal_deny():
                    self.ong_mark_not(g, current_node, parent_node)
                    self.ong_end_path(g, current_node, parent_node)
                    self.ong_add_to_parent_path(
                        g, current_node, parent_node, nodes_to_process
                    )
                elif current_node.non_terminal.is_non_terminal_allow():
                    self.ong_add_to_path(g, current_node, parent_node, nodes_to_process)
                elif current_node.non_terminal.is_non_terminal_non_terminal():
                    self.ong_add_to_path(g, current_node, parent_node, nodes_to_process)
                    self.ong_add_to_parent_path(
                        g, current_node, parent_node, nodes_to_process
                    )
                elif current_node.non_terminal.is_allow_non_terminal():
                    self.ong_mark_not(g, current_node, parent_node)
                    self.ong_add_to_path(g, current_node, parent_node, nodes_to_process)
                elif current_node.non_terminal.is_deny_non_terminal():
                    self.ong_end_path(g, current_node, parent_node)
                    self.ong_add_to_parent_path(
                        g, current_node, parent_node, nodes_to_process
                    )
                elif current_node.non_terminal.is_deny_allow():
                    self.ong_end_path(g, current_node, parent_node)
                elif current_node.non_terminal.is_allow_deny():
                    self.ong_mark_not(g, current_node, parent_node)
                    self.ong_end_path(g, current_node, parent_node)
                else:
                    if current_node.non_terminal.unmatch.is_terminal():
                        self.terminals.add(current_node.non_terminal.unmatch)
            else:
                raise RuntimeError("terminal is neither deny or allow")

        self.processed_nodes.append(node)
        self.print_operation_node_graph(g)
        g = self.clean_edges_in_operation_node_graph(g)

        logger.debug("*** after cleaning nodes:")
        self.print_operation_node_graph(g)

        return g

    def print_operation_node_graph(self, g):
        if not g:
            return
        message = ""
        for node_iter in g.keys():
            message += "0x%x (%s) (%s) (decision: %s not: %d): [ " % (
                node_iter.offset,
                str(node_iter),
                g[node_iter]["type"],
                g[node_iter]["decision"],
                g[node_iter]["not"]
            )
            for edge in g[node_iter]["list"]:
                message += "\n0x%x (%s) " % (edge.offset, str(edge))
            message += "]\n"
        logger.debug(message)

    def remove_edge_in_operation_node_graph(self, g, node_start, node_end):
        if node_end in g[node_start]["list"]:
            g[node_start]["list"].remove(node_end)
        return g

    def remove_node_in_operation_node_graph(self, g, node_to_remove):
        for n in g[node_to_remove]["list"]:
            g = self.remove_edge_in_operation_node_graph(g, node_to_remove, n)
        node_list = list(g.keys())
        for n in node_list:
            if node_to_remove in g[n]["list"]:
                g = self.remove_edge_in_operation_node_graph(g, n, node_to_remove)
        del g[node_to_remove]
        return g

    def _get_operation_node_graph_paths(self, g, node):
        """
        Helper method that does a DFS from node and collects paths
        in self.paths, using self.current_path as the stack.
        """
        self.current_path.append(node)

        if "final" in g[node]["type"]:
            copy_path = list(self.current_path)
            self.paths.append(copy_path)
        else:
            for next_node in g[node]["list"]:
                self._get_operation_node_graph_paths(g, next_node)

        self.current_path.pop()

    def get_operation_node_graph_paths(self, g, start_node):
        """
        Public method that resets self.paths/self.current_path,
        then collects them via _get_operation_node_graph_paths.
        """
        self.paths = []
        self.current_path = []
        self._get_operation_node_graph_paths(g, start_node)
        return self.paths

    def _remove_duplicate_node_edges(self, g, node, start_list):
        self.nodes_traversed_for_removal.append(node)

        nexts = list(g[node]["list"])
        for n in nexts:
            # If n is one of the start nodes, remove the edge
            if n in start_list:
                g = self.remove_edge_in_operation_node_graph(g, node, n)
            else:
                if n not in self.nodes_traversed_for_removal:
                    self._remove_duplicate_node_edges(g, n, start_list)

    def remove_duplicate_node_edges(self, g, start_list):
        """
        Removes edges that lead back to start nodes or otherwise
        produce cycles. Uses _remove_duplicate_node_edges internally.
        """
        for n in start_list:
            self._remove_duplicate_node_edges(g, n, start_list)

    def clean_edges_in_operation_node_graph(self, g):
        """
        From the initial graph remove edges that are redundant.
        Then, do a path-based clean to remove superfluous edges
        from repeated final states, etc.
        """
        start_nodes = []
        final_nodes = []

        for node_iter in g.keys():
            if "start" in g[node_iter]["type"]:
                start_nodes.append(node_iter)
            if "final" in g[node_iter]["type"]:
                final_nodes.append(node_iter)

        # Remove edges pointing back to start nodes
        for snode in start_nodes:
            for node_iter in list(g.keys()):
                g = self.remove_edge_in_operation_node_graph(g, node_iter, snode)

        # Remove duplicate edges
        for snode in start_nodes:
            nodes_bag = [snode]
            while nodes_bag:
                node = nodes_bag.pop()
                self.nodes_traversed_for_removal = []
                self.remove_duplicate_node_edges(g, g[node]["list"])
                nodes_bag.extend(g[node]["list"])

        # Build paths for each start node; compare them; if final nodes are same,
        # remove extra edges in the longer path, etc.
        for snode in start_nodes:
            paths = self.get_operation_node_graph_paths(g, snode)

            for i in range(0, len(paths)):
                for j in range(i + 1, len(paths)):
                    # Compare path lengths
                    if len(paths[i]) == len(paths[j]):
                        continue
                    elif len(paths[i]) < len(paths[j]):
                        p = paths[i]
                        q = paths[j]
                    else:
                        p = paths[j]
                        q = paths[i]

                    # If final nodes are the same, remove the extra edge in the longer path
                    if p[-1] == q[-1]:
                        # Step backwards until a divergence
                        for k in range(len(p)):
                            if p[len(p) - 1 - k] == q[len(q) - 1 - k]:
                                continue
                            else:
                                g = self.remove_edge_in_operation_node_graph(
                                    g, q[len(q) - 1 - k], q[len(q) - k]
                                )
                                break

        return g

    def clean_nodes_in_operation_node_graph(self, g):
        """
        Removes nodes with no edges (that are not final).
        Returns (g, made_change) so we can iterate until no more changes.
        """
        made_change = False
        node_list = list(g.keys())
        for node_iter in node_list:
            if "final" in g[node_iter]["type"]:
                continue
            if g[node_iter]["list"]:
                continue
            logger.warning("Removing node: %s", node_iter)
            made_change = True
            g = self.remove_node_in_operation_node_graph(g, node_iter)
        return (g, made_change)
