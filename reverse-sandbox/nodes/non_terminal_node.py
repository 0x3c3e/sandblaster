class NonTerminalNode:
    """Intermediary node consisting of a filter to match

    The non-terminal node, when matched, points to a new node, and
    when unmatched, to another node.

    A non-terminal node consists of the filter to match, its argument and
    the match and unmatch nodes.
    """

    def __init__(self):
        self.filter_id = None
        self.filter = None
        self.argument_id = None
        self.argument = None
        self.match_offset = None
        self.match = None
        self.unmatch_offset = None
        self.unmatch = None

    def __eq__(self, other):
        return (
            self.filter_id == other.filter_id
            and self.argument_id == other.argument_id
            and self.match_offset == other.match_offset
            and self.unmatch_offset == other.unmatch_offset
        )

    def simplify_list(self, arg_list):
        result_list = []
        for a in arg_list:
            if len(a) == 0:
                continue
            tmp_list = list(result_list)
            match_found = False
            for r in tmp_list:
                if len(r) == 0:
                    continue
                if a == r or a + "/" == r or a == r + "/":
                    match_found = True
                    result_list.remove(r)
                    if a[-1] == "/":
                        result_list.append(a + "^^^")
                    else:
                        result_list.append(a + "/^^^")
            if match_found == False:
                result_list.append(a)

        return result_list

    def __str__(self):
        if self.filter:
            if self.argument:
                if type(self.argument) is list:
                    if len(self.argument) == 1:
                        ret_str = ""
                    else:
                        self.argument = self.simplify_list(self.argument)
                        if len(self.argument) == 1:
                            ret_str = ""
                        else:
                            ret_str = "(require-any\n"
                    for s in self.argument:
                        curr_filter = self.filter
                        regex_added = False
                        prefix_added = False
                        if len(s) == 0:
                            s = ".+"
                            if not regex_added:
                                regex_added = True
                                if self.filter == "literal":
                                    curr_filter = "regex"
                                else:
                                    curr_filter += "-regex"
                        else:
                            if s[-4:] == "/^^^":
                                curr_filter = "subpath"
                                s = s[:-4]
                            if (
                                "\\" in s
                                or "|" in s
                                or ("[" in s and "]" in s)
                                or "+" in s
                            ):
                                if curr_filter == "subpath":
                                    s = s + "/?"
                                if self.filter == "literal":
                                    curr_filter = "regex"
                                else:
                                    curr_filter += "-regex"
                                s = s.replace("\\\\.", "[.]")
                                s = s.replace("\\.", "[.]")
                            if "${" in s and "}" in s:
                                if not prefix_added:
                                    prefix_added = True
                                    curr_filter += "-prefix"
                        if "regex" in curr_filter:
                            ret_str += '(%s #"%s")\n' % (curr_filter, s)
                        else:
                            ret_str += '(%s "%s")\n' % (curr_filter, s)
                    if len(self.argument) == 1:
                        ret_str = ret_str[:-1]
                    else:
                        ret_str = ret_str[:-1] + ")"
                    return ret_str
                s = self.argument
                curr_filter = self.filter
                if not "regex" in curr_filter:
                    if "\\" in s or "|" in s or ("[" in s and "]" in s) or "+" in s:
                        if self.filter == "literal":
                            curr_filter = "regex"
                        else:
                            curr_filter += "-regex"
                        s = s.replace("\\\\.", "[.]")
                        s = s.replace("\\.", "[.]")
                if "${" in s and "}" in s:
                    if not "prefix" in curr_filter:
                        curr_filter += "-prefix"
                return "(%s %s)" % (curr_filter, s)
            else:
                return "(%s)" % (self.filter)
        return "(%02x %04x %04x %04x)" % (
            self.filter_id,
            self.argument_id,
            self.match_offset,
            self.unmatch_offset,
        )

    def values(self):
        if self.filter:
            return (self.filter, self.argument)
        return ("%02x" % self.filter_id, "%04x" % (self.argument_id))

    def is_entitlement_start(self):
        return self.filter_id == 0x1E or self.filter_id == 0xA0

    def is_entitlement(self):
        return (
            self.filter_id == 0x1E
            or self.filter_id == 0x1F
            or self.filter_id == 0x20
            or self.filter_id == 0xA0
        )

    def is_last_regular_expression(self):
        return self.filter_id == 0x81 and self.argument_id == num_regex - 1

    def convert_filter(self, convert_fn, f, sandbox_data, keep_builtin_filters):
        (self.filter, self.argument) = convert_fn(
            f, sandbox_data, keep_builtin_filters, self.filter_id, self.argument_id
        )

    def is_non_terminal_deny(self):
        if self.match.is_non_terminal() and self.unmatch.is_terminal():
            return self.unmatch.terminal.is_deny()

    def is_non_terminal_allow(self):
        if self.match.is_non_terminal() and self.unmatch.is_terminal():
            return self.unmatch.terminal.is_allow()

    def is_non_terminal_non_terminal(self):
        return self.match.is_non_terminal() and self.unmatch.is_non_terminal()

    def is_allow_non_terminal(self):
        if self.match.is_terminal() and self.unmatch.is_non_terminal():
            return self.match.terminal.is_allow()

    def is_deny_non_terminal(self):
        if self.match.is_terminal() and self.unmatch.is_non_terminal():
            return self.match.terminal.is_deny()

    def is_deny_allow(self):
        if self.match.is_terminal() and self.unmatch.is_terminal():
            return self.match.terminal.is_deny() and self.unmatch.terminal.is_allow()

    def is_allow_deny(self):
        if self.match.is_terminal() and self.unmatch.is_terminal():
            return self.match.terminal.is_allow() and self.unmatch.terminal.is_deny()
