import re
import logging

logger = logging.getLogger(__name__)


INDENT = " " * 2


class ReducedVertice:
    TYPE_SINGLE = "single"
    TYPE_START = "start"
    TYPE_REQUIRE_ANY = "require-any"
    TYPE_REQUIRE_ALL = "require-all"
    TYPE_REQUIRE_ENTITLEMENT = "require-entitlement"

    def __init__(self, type=TYPE_SINGLE, value=None, decision=None, is_not=False):
        self.type = type
        self.value = value
        self.decision = decision
        self.is_not = is_not

    def set_value(self, value):
        self.value = value

    def set_type(self, type):
        self.type = type

    def _replace_in_list(self, lst, old, new):
        global replace_occurred
        tmp_list = list(lst)
        for i, v in enumerate(tmp_list):
            if isinstance(v.value, list):
                self._replace_in_list(v.value, old, new)
            else:
                if v == old:
                    lst[i] = new
                    replace_occurred = True
                    return

    def replace_in_list(self, old, new):
        if isinstance(self.value, list):
            self._replace_in_list(self.value, old, new)

    def _replace_sublist_in_list(self, lst, old, new):
        global replace_occurred
        all_found = True
        for v in old:
            if v not in lst:
                all_found = False
                break
        if all_found:
            for v in old:
                lst.remove(v)
            lst.append(new)
            replace_occurred = True
            return

        for i, v in enumerate(lst):
            if isinstance(v.value, list):
                self._replace_sublist_in_list(v.value, old, new)
            else:
                return

    def replace_sublist_in_list(self, old, new):
        if isinstance(self.value, list):
            self._replace_sublist_in_list(self.value, old, new)

    def set_decision(self, decision):
        self.decision = decision

    def set_type_single(self):
        self.type = self.TYPE_SINGLE

    def set_type_start(self):
        self.type = self.TYPE_START

    def set_type_require_entitlement(self):
        self.type = self.TYPE_REQUIRE_ENTITLEMENT

    def set_type_require_any(self):
        self.type = self.TYPE_REQUIRE_ANY

    def set_type_require_all(self):
        self.type = self.TYPE_REQUIRE_ALL

    def set_integrated_vertice(self, integrated_vertice):
        (n, i) = self.value
        self.value = (n, integrated_vertice)

    def is_type_single(self):
        return self.type == self.TYPE_SINGLE

    def is_type_start(self):
        return self.type == self.TYPE_START

    def is_type_require_entitlement(self):
        return self.type == self.TYPE_REQUIRE_ENTITLEMENT

    def is_type_require_all(self):
        return self.type == self.TYPE_REQUIRE_ALL

    def is_type_require_any(self):
        return self.type == self.TYPE_REQUIRE_ANY

    def recursive_str(self, level, recursive_is_not):
        result_str = ""
        if self.is_type_single():
            if self.is_not and not recursive_is_not:
                result_str += "(require-not" + str(self.value) + "\n)"
            else:
                result_str += str(self.value)
        elif self.is_type_require_entitlement():
            ent_str = ""
            (n, i) = self.value
            if i == None:
                ent_str += str(n.value)
            else:
                ent_str += str(n.value)[:-1] + " "
                ent_str += i.recursive_str(level, self.is_not)
                ent_str += "\n)"
            if self.is_not:
                result_str += "(require-not" + ent_str + "\n)"
            else:
                result_str += ent_str
        else:
            if level == 1:
                result_str += "\n" + level * " "
            result_str += "(" + self.type
            level += 1
            for i, v in enumerate(self.value):
                if i == 0:
                    result_str += " " + v.recursive_str(level, recursive_is_not)
                else:
                    result_str += (
                        "\n" + level * " " + v.recursive_str(level, recursive_is_not)
                    )
            result_str += "\n)"
        return result_str

    def __str__(self):
        return self.recursive_str(1, False)

    def str_print(self):
        if self.is_type_single():
            return (str(self.value), None)
        elif self.is_type_require_any():
            return ("(require-any", "\n)")
        elif self.is_type_require_all():
            return ("(require-all", "\n)")
        elif self.is_type_require_entitlement():
            return (str(self.value)[:-1], "\n)")
        elif self.is_type_start():
            return (None, None)
        else:
            return ("unknown-type", None)


class ReducedEdge:
    def __init__(self, start=None, end=None):
        self.start = start
        self.end = end

    def __str__(self):
        return str(self.start) + " -> " + str(self.end)


class ReducedGraph:
    def __init__(self):
        self.vertices = []
        self.edges = []
        self.final_vertices = []
        self.reduce_changes_occurred = False

    def add_vertice(self, v):
        self.vertices.append(v)

    def add_edge(self, e):
        self.edges.append(e)

    def add_edge_by_vertices(self, v_start, v_end):
        e = ReducedEdge(v_start, v_end)
        self.edges.append(e)

    def set_final_vertices(self):
        self.final_vertices = []
        for v in self.vertices:
            is_final = True
            for e in self.edges:
                if v == e.start:
                    is_final = False
                    break
            if is_final:
                self.final_vertices.append(v)

    def contains_vertice(self, v):
        return v in self.vertices

    def contains_edge(self, e):
        return e in self.edges

    def contains_edge_by_vertices(self, v_start, v_end):
        for e in self.edges:
            if e.start == v_start and e.end == v_end:
                return True
        return False

    def get_vertice_by_value(self, value):
        for v in self.vertices:
            if v.is_type_single():
                if v.value == value:
                    return v

    def get_edge_by_vertices(self, v_start, v_end):
        for e in self.edges:
            if e.start == v_start and e.end == v_end:
                return e
        return None

    def remove_vertice(self, v):
        edges_copy = list(self.edges)
        for e in edges_copy:
            if e.start == v or e.end == v:
                self.edges.remove(e)
        if v in self.vertices:
            self.vertices.remove(v)

    def remove_vertice_update_decision(self, v):
        edges_copy = list(self.edges)
        for e in edges_copy:
            if e.start == v:
                self.edges.remove(e)
            if e.end == v:
                e.start.decision = v.decision
                self.edges.remove(e)
        if v in self.vertices:
            self.vertices.remove(v)

    def remove_edge(self, e):
        if e in self.edges:
            self.edges.remove(e)

    def remove_edge_by_vertices(self, v_start, v_end):
        e = self.get_edge_by_vertices(v_start, v_end)
        if e:
            self.edges.remove(e)

    def replace_vertice_in_edge_start(self, old, new):
        global replace_occurred
        for e in self.edges:
            if e.start == old:
                e.start = new
                replace_occurred = True
            else:
                if isinstance(e.start.value, list):
                    e.start.replace_in_list(old, new)
                    if replace_occurred:
                        e.start.decision = new.decision

    def replace_vertice_in_edge_end(self, old, new):
        global replace_occurred
        for e in self.edges:
            if e.end == old:
                e.end = new
                replace_occurred = True
            else:
                if isinstance(e.end.value, list):
                    e.end.replace_in_list(old, new)
                    if replace_occurred:
                        e.end.decision = new.decision

    def replace_vertice_in_single_vertices(self, old, new):
        for v in self.vertices:
            if (
                len(self.get_next_vertices(v)) == 0
                and len(self.get_prev_vertices(v)) == 0
            ):
                if isinstance(v.value, list):
                    v.replace_in_list(old, new)

    def replace_vertice_list(self, old, new):
        for v in self.vertices:
            if isinstance(v.value, list):
                v.replace_sublist_in_list(old, new)
            if set(self.get_next_vertices(v)) == set(old):
                for n in old:
                    self.remove_edge_by_vertices(v, n)
                self.add_edge_by_vertices(v, new)
            if set(self.get_prev_vertices(v)) == set(old):
                for n in old:
                    self.remove_edge_by_vertices(n, v)
                self.add_edge_by_vertices(new, v)

    def get_next_vertices(self, v):
        next_vertices = []
        for e in self.edges:
            if e.start == v:
                next_vertices.append(e.end)
        return next_vertices

    def get_prev_vertices(self, v):
        prev_vertices = []
        for e in self.edges:
            if e.end == v:
                prev_vertices.append(e.start)
        return prev_vertices

    def get_start_vertices(self):
        start_vertices = []
        for v in self.vertices:
            if not self.get_prev_vertices(v):
                start_vertices.append(v)
        return start_vertices

    def get_end_vertices(self):
        end_vertices = []
        for v in self.vertices:
            if not self.get_next_vertices(v):
                end_vertices.append(v)
        return end_vertices

    def reduce_next_vertices(self, v):
        next_vertices = self.get_next_vertices(v)
        if len(next_vertices) <= 1:
            return
        self.reduce_changes_occurred = True
        new_vertice = ReducedVertice(
            "require-any", next_vertices, next_vertices[0].decision
        )
        add_to_final = False
        for n in next_vertices:
            self.remove_edge_by_vertices(v, n)
        self.replace_vertice_list(next_vertices, new_vertice)
        for n in next_vertices:
            if n in self.final_vertices:
                self.final_vertices.remove(n)
                add_to_final = True
            # If no more next vertices, remove vertice.
            if not self.get_next_vertices(n):
                if n in self.vertices:
                    self.vertices.remove(n)
        self.add_edge_by_vertices(v, new_vertice)
        self.add_vertice(new_vertice)
        if add_to_final:
            self.final_vertices.append(new_vertice)

    def reduce_prev_vertices(self, v):
        prev_vertices = self.get_prev_vertices(v)
        if len(prev_vertices) <= 1:
            return
        self.reduce_changes_occurred = True
        new_vertice = ReducedVertice("require-any", prev_vertices, v.decision)
        for p in prev_vertices:
            self.remove_edge_by_vertices(p, v)
        self.replace_vertice_list(prev_vertices, new_vertice)
        for p in prev_vertices:
            # If no more prev vertices, remove vertice.
            if not self.get_prev_vertices(p):
                if p in self.vertices:
                    self.vertices.remove(p)
        self.add_vertice(new_vertice)
        self.add_edge_by_vertices(new_vertice, v)

    def reduce_vertice_single_prev(self, v):
        global replace_occurred
        prev = self.get_prev_vertices(v)
        if len(prev) != 1:
            logger.debug("not a single prev for node")
            return
        p = prev[0]
        nexts = self.get_next_vertices(p)
        if len(nexts) > 1 or nexts[0] != v:
            logger.debug("multiple nexts for prev")
            return
        require_all_vertices = []
        if p.is_type_require_all():
            require_all_vertices.extend(p.value)
        else:
            require_all_vertices.append(p)
        if v.is_type_require_all():
            require_all_vertices.extend(v.value)
        else:
            require_all_vertices.append(v)
        new_vertice = ReducedVertice("require-all", require_all_vertices, v.decision)
        self.remove_edge_by_vertices(p, v)
        replace_occurred = False
        self.replace_vertice_in_edge_start(v, new_vertice)
        self.replace_vertice_in_edge_end(p, new_vertice)
        self.replace_vertice_in_single_vertices(p, new_vertice)
        self.replace_vertice_in_single_vertices(v, new_vertice)
        self.remove_vertice(p)
        self.remove_vertice(v)
        if not replace_occurred:
            self.add_vertice(new_vertice)
        if v in self.final_vertices:
            self.final_vertices.remove(v)
            self.final_vertices.append(new_vertice)

    def reduce_vertice_single_next(self, v):
        global replace_occurred
        next = self.get_next_vertices(v)
        if len(next) != 1:
            return
        n = next[0]
        prevs = self.get_prev_vertices(n)
        if len(prevs) > 1 or prevs[0] != v:
            return
        require_all_vertices = []
        if v.is_type_require_all():
            require_all_vertices.extend(v.value)
        else:
            require_all_vertices.append(v)
        if n.is_type_require_all():
            require_all_vertices.extend(n.value)
        else:
            require_all_vertices.append(n)
        new_vertice = ReducedVertice("require-all", require_all_vertices, n.decision)
        self.remove_edge_by_vertices(v, n)
        replace_occurred = False
        self.replace_vertice_in_edge_start(n, new_vertice)
        self.replace_vertice_in_edge_end(e, new_vertice)
        self.replace_vertice_in_single_vertices(v, new_vertice)
        self.replace_vertice_in_single_vertices(n, new_vertice)
        self.remove_vertice(v)
        self.remove_vertice(n)
        if not replace_occurred:
            self.add_vertice(new_vertice)
        if n in self.final_vertices:
            self.final_vertices.remove(n)
            self.final_vertices.append(new_vertice)

    def reduce_graph(self):
        self.set_final_vertices()

        # Do until no more changes.
        while True:
            self.reduce_changes_occurred = False
            copy_vertices = list(self.vertices)
            for v in copy_vertices:
                self.reduce_next_vertices(v)
            if self.reduce_changes_occurred == False:
                break
        # Do until no more changes.
        while True:
            self.reduce_changes_occurred = False
            copy_vertices = list(self.vertices)
            for v in copy_vertices:
                self.reduce_prev_vertices(v)
            if self.reduce_changes_occurred == False:
                break

        # Reduce graph starting from final vertices. Keep going until
        # final vertices don't change during an iteration.
        while True:
            copy_final_vertices = list(self.final_vertices)
            for v in copy_final_vertices:
                self.reduce_vertice_single_prev(v)
            if set(copy_final_vertices) == set(self.final_vertices):
                break
        for e in self.edges:
            v = e.end
            self.reduce_vertice_single_prev(v)

    def reduce_graph_with_metanodes(self):
        # Add require-any metanode if current node has multiple successors.
        copy_vertices = list(self.vertices)
        for v in copy_vertices:
            nlist = self.get_next_vertices(v)
            if len(nlist) >= 2:
                new_node = ReducedVertice("require-any", None, None)
                self.add_vertice(new_node)
                self.add_edge_by_vertices(v, new_node)
                for n in nlist:
                    self.remove_edge_by_vertices(v, n)
                    self.add_edge_by_vertices(new_node, n)

        start_list = self.get_start_vertices()
        new_node = ReducedVertice("start", None, None)
        self.add_vertice(new_node)
        for s in start_list:
            self.add_edge_by_vertices(new_node, s)

        # Add require-all metanode if current node has a require-any as a predecessor and is followed by another node.
        copy_vertices = list(self.vertices)
        for v in copy_vertices:
            prev_vertices = list(self.get_prev_vertices(v))
            next_vertices = list(self.get_next_vertices(v))
            for p in prev_vertices:
                if (p.is_type_require_any() or p.is_type_start()) and next_vertices:
                    # Except for when a require-entitlement ending block.
                    if v.is_type_require_entitlement():
                        has_next_nexts = False
                        for n in next_vertices:
                            if n.is_type_require_any():
                                for n2 in self.get_next_vertices(n):
                                    if self.get_next_vertices(n2):
                                        has_next_nexts = True
                                        break
                            else:
                                if self.get_next_vertices(n):
                                    has_next_nexts = True
                                    break
                        if not has_next_nexts:
                            continue
                    new_node = ReducedVertice("require-all", None, None)
                    self.add_vertice(new_node)
                    self.remove_edge_by_vertices(p, v)
                    self.add_edge_by_vertices(p, new_node)
                    self.add_edge_by_vertices(new_node, v)

    def __str__(self):
        result_str = ""
        for v in self.vertices:
            result_str += "(" + str(v.decision) + " "
            if (
                len(self.get_next_vertices(v)) == 0
                and len(self.get_next_vertices(v)) == 0
            ):
                if v in self.final_vertices:
                    result_str += str(v) + "\n"
            result_str += ")\n"
        for e in self.edges:
            result_str += str(e) + "\n"
        result_str += "\n"
        return result_str

    def remove_builtin_filters(self):
        copy_vertices = list(self.vertices)
        for v in copy_vertices:
            if re.search("###\$\$\$\*\*\*", str(v)):
                self.remove_vertice_update_decision(v)

    def reduce_integrated_vertices(self, integrated_vertices):
        if len(integrated_vertices) == 0:
            return (None, None)
        if len(integrated_vertices) > 1:
            return (
                ReducedVertice(
                    "require-any", integrated_vertices, integrated_vertices[0].decision
                ),
                integrated_vertices[0].decision,
            )
        require_all_vertices = []
        v = integrated_vertices[0]
        decision = None
        while True:
            if not re.search("entitlement-value #t", str(v)):
                require_all_vertices.append(v)
            next_vertices = self.get_next_vertices(v)
            if decision == None and v.decision != None:
                decision = v.decision
            self.remove_vertice(v)
            if v in self.final_vertices:
                self.final_vertices.remove(v)
            if next_vertices:
                v = next_vertices[0]
            else:
                break
        if len(require_all_vertices) == 0:
            return (None, v.decision)
        if len(require_all_vertices) == 1:
            return (
                ReducedVertice(
                    value=require_all_vertices[0].value,
                    decision=require_all_vertices[0].decision,
                    is_not=require_all_vertices[0].is_not,
                ),
                v.decision,
            )
        return (
            ReducedVertice(
                "require-all",
                require_all_vertices,
                require_all_vertices[len(require_all_vertices) - 1].decision,
            ),
            v.decision,
        )

    def aggregate_require_entitlement(self, v):
        next_vertices = []
        prev_vertices = self.get_prev_vertices(v)
        integrated_vertices = []
        for n in self.get_next_vertices(v):
            if not re.search("entitlement-value", str(n)):
                next_vertices.append(n)
                break
            integrated_vertices.append(n)
            current_list = [n]
            while current_list:
                current = current_list.pop()
                for n2 in self.get_next_vertices(current):
                    if not re.search("entitlement-value", str(n2)):
                        self.remove_edge_by_vertices(current, n2)
                        next_vertices.append(n2)
                    else:
                        current_list.append(n2)
        new_vertice = ReducedVertice(
            type="require-entitlement", value=(v, None), decision=None, is_not=v.is_not
        )
        for p in prev_vertices:
            self.remove_edge_by_vertices(p, v)
            self.add_edge_by_vertices(p, new_vertice)
        for n in next_vertices:
            self.remove_edge_by_vertices(v, n)
            self.add_edge_by_vertices(new_vertice, n)
        for i in integrated_vertices:
            self.remove_edge_by_vertices(v, i)
        self.remove_vertice(v)
        self.add_vertice(new_vertice)
        if v in self.final_vertices:
            self.final_vertices.remove(v)
            self.final_vertices.append(new_vertice)
        (new_integrate, decision) = self.reduce_integrated_vertices(integrated_vertices)
        for i in integrated_vertices:
            self.remove_vertice(i)
            if i in self.final_vertices:
                self.final_vertices.remove(i)
        new_vertice.set_integrated_vertice(new_integrate)
        new_vertice.set_decision(decision)

    def aggregate_require_entitlement_nodes(self):
        copy_vertices = list(self.vertices)
        idx = 0
        while idx < len(copy_vertices):
            v = copy_vertices[idx]
            if re.search("require-entitlement", str(v)):
                self.aggregate_require_entitlement(v)
            idx += 1

    def cleanup_filters(self):
        self.remove_builtin_filters()
        self.aggregate_require_entitlement_nodes()

    def replace_require_entitlement_with_metanodes(self, v):
        prev_list = self.get_prev_vertices(v)
        next_list = self.get_next_vertices(v)
        new_node = ReducedVertice(
            type="require-entitlement", value=v.value, decision=None, is_not=v.is_not
        )
        self.add_vertice(new_node)
        self.remove_vertice(v)
        for p in prev_list:
            self.add_edge_by_vertices(p, new_node)
        for n in next_list:
            self.add_edge_by_vertices(new_node, n)

    def aggregate_require_entitlement_with_metanodes(self):
        copy_vertices = list(self.vertices)
        for v in copy_vertices:
            if re.search("require-entitlement", str(v)):
                self.replace_require_entitlement_with_metanodes(v)

    def cleanup_filters_with_metanodes(self):
        self.aggregate_require_entitlement_with_metanodes()

    def print_vertices_with_operation(self, operation, out_f):
        allow_vertices = [v for v in self.vertices if "allow" in v.decision]
        deny_vertices = [v for v in self.vertices if "deny" in v.decision]
        if allow_vertices:
            out_f.write("(allow %s " % (operation))
            if len(allow_vertices) > 1:
                for v in allow_vertices:
                    out_f.write("\n" + 8 * " " + str(v))
            else:
                out_f.write(str(allow_vertices[0]))
            out_f.write(")\n")
        if deny_vertices:
            out_f.write("(deny %s " % (operation))
            if len(deny_vertices) > 1:
                for v in deny_vertices:
                    out_f.write("\n" + 8 * " " + str(v))
            else:
                out_f.write(str(deny_vertices[0]))
            out_f.write(")\n")

    def print_vertices_with_operation_metanodes(
        self, operation, default_is_allow, out_f
    ):
        # Return if only start node in list.
        if len(self.vertices) == 1 and self.vertices[0].is_type_start():
            return
        # Use reverse of default rule.
        if default_is_allow:
            out_f.write("(deny %s" % (operation))
        else:
            out_f.write("(allow %s" % (operation))
        vlist = []
        start_list = self.get_start_vertices()
        start_list.reverse()
        vlist.insert(0, (None, 0))
        for s in start_list:
            vlist.insert(0, (s, 1))
        while True:
            if not vlist:
                break
            (cnode, indent) = vlist.pop(0)
            if not cnode:
                out_f.write("\n" + indent * INDENT + ")")
                continue
            (first, last) = cnode.str_print()
            if first:
                if cnode.is_not:
                    out_f.write("\n" + indent * INDENT + "(require-not ")
                    for i, line in enumerate(first.splitlines()):
                        if i == 0:
                            out_f.write("\n" + (indent + 1) * INDENT + line)
                        else:
                            out_f.write("\n" + (indent + 2) * INDENT + line)
                    if (
                        cnode.is_type_require_any()
                        or cnode.is_type_require_all()
                        or cnode.is_type_require_entitlement()
                    ):
                        vlist.insert(0, (None, indent))
                    else:
                        out_f.write("\n" + indent * INDENT + ")")
                else:
                    for i, line in enumerate(first.splitlines()):
                        if i == 0:
                            out_f.write("\n" + (indent) * INDENT + line)
                            continue
                        out_f.write("\n" + (indent + 1) * INDENT + line)
            if last:
                vlist.insert(0, (None, indent))
            next_vertices_list = self.get_next_vertices(cnode)
            if next_vertices_list:
                if (
                    cnode.is_type_require_any()
                    or cnode.is_type_require_all()
                    or cnode.is_type_require_entitlement()
                ):
                    indent += 1
                next_vertices_list.reverse()
                if cnode.is_type_require_entitlement():
                    pos = 0
                    for n in next_vertices_list:
                        if (n.is_type_single()) or n.is_type_require_entitlement():
                            vlist.insert(pos + 1, (n, indent - 1))
                        else:
                            vlist.insert(0, (n, indent))
                            pos += 1
                else:
                    for n in next_vertices_list:
                        vlist.insert(0, (n, indent))
        out_f.write("\n")


def reduce_operation_node_graph(g):
    # Create reduced graph.
    rg = ReducedGraph()
    for node_iter in g.keys():
        rv = ReducedVertice(
            value=node_iter,
            decision=g[node_iter]["decision"],
            is_not=g[node_iter]["not"],
        )
        rg.add_vertice(rv)

    for node_iter in g.keys():
        rv = rg.get_vertice_by_value(node_iter)
        for node_next in g[node_iter]["list"]:
            rn = rg.get_vertice_by_value(node_next)
            rg.add_edge_by_vertices(rv, rn)

    # Handle special case for require-not (require-enitlement (...)).
    l = len(g.keys())
    for idx, node_iter in enumerate(g.keys()):
        rv = rg.get_vertice_by_value(node_iter)
        if not re.search("require-entitlement", str(rv)):
            continue
        if not rv.is_not:
            continue
        c_idx = idx
        while True:
            c_idx += 1
            if c_idx >= l:
                break
            rn = rg.get_vertice_by_value(g.keys()[c_idx])
            if not re.search("entitlement-value", str(rn)):
                break
            prevs_rv = rg.get_prev_vertices(rv)
            prevs_rn = rg.get_prev_vertices(rn)
            if sorted(prevs_rv) != sorted(prevs_rn):
                continue
            for pn in prevs_rn:
                rg.remove_edge_by_vertices(rn, pn)
            rg.add_edge_by_vertices(rv, rn)

    rg.cleanup_filters_with_metanodes()
    for node_iter in g.keys():
        rv = rg.get_vertice_by_value(node_iter)
    rg.reduce_graph_with_metanodes()
    return rg