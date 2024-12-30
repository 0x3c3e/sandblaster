import logging

logger = logging.getLogger(__name__)


class OperationNodeGraphBuilder:
    def __init__(self):
        self.paths = []
        self.current_path = []
        self.nodes_traversed_for_removal = []
        self.terminals = set()

    def ong_mark_not(self, g, node):
        g[node]["not"] = True
        tmp = node.non_terminal.match
        node.non_terminal.match = node.non_terminal.unmatch
        node.non_terminal.unmatch = tmp
        tmp_offset = node.non_terminal.match_offset
        node.non_terminal.match_offset = node.non_terminal.unmatch_offset
        node.non_terminal.unmatch_offset = tmp_offset

    def ong_end_path(self, g, node):
        g[node]["decision"] = str(node.non_terminal.match.terminal)
        g[node]["type"].add("final")

    def ong_add_to_path(self, g, node, nodes_to_process):
        if node.non_terminal.match and not node.non_terminal.match.processed:
            g[node]["list"].add(node.non_terminal.match)
            nodes_to_process.add((node, node.non_terminal.match))

    def ong_add_to_parent_path(self, g, node, parent_node, nodes_to_process):
        if node.non_terminal.unmatch and not node.non_terminal.unmatch.processed:
            if parent_node:
                g[parent_node]["list"].add(node.non_terminal.unmatch)
            nodes_to_process.add((parent_node, node.non_terminal.unmatch))

    def _initialize_graph(self, node):
        g = {
            node: {
                "list": set(),
                "decision": None,
                "type": {"normal", "start"},
                "reduce": None,
                "not": False,
            }
        }
        nodes_to_process = set()
        nodes_to_process.add((None, node))
        return g, nodes_to_process

    def process_current_node(self, g, parent_node, current_node, nodes_to_process, allow_mode):
        def add_to_path():
            self.ong_add_to_path(g, current_node, nodes_to_process)

        def mark_not():
            self.ong_mark_not(g, current_node)

        def end_path():
            self.ong_end_path(g, current_node)

        def add_to_parent_path():
            self.ong_add_to_parent_path(g, current_node, parent_node, nodes_to_process)

        non_terminal = current_node.non_terminal

        match_is_terminal = non_terminal.match.is_terminal()
        unmatch_is_terminal = non_terminal.unmatch.is_terminal()

        if not match_is_terminal and not unmatch_is_terminal:
            add_to_path()
            add_to_parent_path()
        elif not match_is_terminal and unmatch_is_terminal:
            if allow_mode == non_terminal.unmatch.terminal.is_allow():
                add_to_path()
            else:
                mark_not()
                end_path()
                add_to_parent_path()
        elif match_is_terminal and not unmatch_is_terminal:
            if allow_mode == non_terminal.match.terminal.is_allow():
                mark_not()
                add_to_path()
            else:
                end_path()
                add_to_parent_path()
        elif match_is_terminal and unmatch_is_terminal:
            print(non_terminal, non_terminal.unmatch.terminal)
            if allow_mode == non_terminal.match.terminal.is_allow():
                mark_not()
            end_path()


    def _process_current_node(
        self, g, parent_node, current_node, nodes_to_process, default_node
    ):
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

        self.process_current_node(
            g,
            parent_node,
            current_node,
            nodes_to_process,
            default_node.terminal.is_allow(),
        )

    def _process_all_nodes(self, g, nodes_to_process, default_node):
        while nodes_to_process:
            parent_node, current_node = nodes_to_process.pop()
            self._process_current_node(
                g, parent_node, current_node, nodes_to_process, default_node
            )

    def build_operation_node_graph(self, node, default_node):
        if node.is_terminal() or node.processed:
            return None

        g, nodes_to_process = self._initialize_graph(node)
        self._process_all_nodes(g, nodes_to_process, default_node)
        node.processed = True
        # g = self.clean_edges_in_operation_node_graph(g)
        return g

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
        self.current_path.append(node)
        if "final" in g[node]["type"]:
            copy_path = list(self.current_path)
            self.paths.append(copy_path)
        else:
            for next_node in g[node]["list"]:
                self._get_operation_node_graph_paths(g, next_node)
        self.current_path.pop()

    def get_operation_node_graph_paths(self, g, start_node):
        self.paths = []
        self.current_path = []
        self._get_operation_node_graph_paths(g, start_node)
        return self.paths

    def _remove_duplicate_node_edges(self, g, node, start_list):
        self.nodes_traversed_for_removal.append(node)
        nexts = list(g[node]["list"])
        for n in nexts:
            if n in start_list:
                g = self.remove_edge_in_operation_node_graph(g, node, n)
            else:
                if n not in self.nodes_traversed_for_removal:
                    self._remove_duplicate_node_edges(g, n, start_list)

    def remove_duplicate_node_edges(self, g, start_list):
        for n in start_list:
            self._remove_duplicate_node_edges(g, n, start_list)

    def clean_edges_in_operation_node_graph(self, g):
        start_nodes = []
        final_nodes = []
        for node_iter in g.keys():
            if "start" in g[node_iter]["type"]:
                start_nodes.append(node_iter)
            if "final" in g[node_iter]["type"]:
                final_nodes.append(node_iter)
        for snode in start_nodes:
            for node_iter in list(g.keys()):
                g = self.remove_edge_in_operation_node_graph(g, node_iter, snode)
        for snode in start_nodes:
            nodes_bag = [snode]
            while nodes_bag:
                node = nodes_bag.pop()
                self.nodes_traversed_for_removal = []
                self.remove_duplicate_node_edges(g, g[node]["list"])
                nodes_bag.extend(g[node]["list"])
        for snode in start_nodes:
            paths = self.get_operation_node_graph_paths(g, snode)
            for i in range(len(paths)):
                for j in range(i + 1, len(paths)):
                    if len(paths[i]) == len(paths[j]):
                        continue
                    elif len(paths[i]) < len(paths[j]):
                        p, q = paths[i], paths[j]
                    else:
                        p, q = paths[j], paths[i]
                    if p[-1] == q[-1]:
                        for k in range(len(p)):
                            if p[len(p) - 1 - k] == q[len(q) - 1 - k]:
                                continue
                            else:
                                g = self.remove_edge_in_operation_node_graph(
                                    g, q[len(q) - 1 - k], q[len(q) - k]
                                )
                                break
        return g
