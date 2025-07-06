import z3


def z3_to_sbpl_print(expr, payload, filters, mapping, level=0, output_func=print):
    indent = " " * level

    def emit(line: str):
        output_func(f"{indent}{line}")

    decl_kind = expr.decl().kind()
    args = expr.children()

    match decl_kind:
        case z3.Z3_OP_TRUE:
            emit("allow")
        case z3.Z3_OP_FALSE:
            emit("deny")
        case z3.Z3_OP_AND:
            emit("(require-all")
            for arg in args:
                z3_to_sbpl_print(arg, payload, filters, mapping, level + 2, output_func)
            emit(")")

        case z3.Z3_OP_OR:
            emit("(require-any")
            for arg in args:
                z3_to_sbpl_print(arg, payload, filters, mapping, level + 2, output_func)
            emit(")")

        case z3.Z3_OP_NOT:
            emit("(require-not")
            z3_to_sbpl_print(args[0], payload, filters, mapping, level + 2, output_func)
            emit(")")

        case z3.Z3_OP_ITE:
            emit("(if")
            z3_to_sbpl_print(
                args[0], payload, filters, mapping, level + 2, output_func
            )  # condition
            z3_to_sbpl_print(
                args[1], payload, filters, mapping, level + 2, output_func
            )  # then
            z3_to_sbpl_print(
                args[2], payload, filters, mapping, level + 2, output_func
            )  # else
            emit(")")
        case z3.Z3_OP_UNINTERPRETED:
            name = expr.decl().name()
            node = mapping[name]
            if isinstance(node.argument, list) and len(node.argument) > 1:
                out = (
                    ["(require-any"]
                    + [" " * 2 + f'({node.filter} "{k}")' for k in node.argument]
                    + [")"]
                )
                for a in out:
                    emit(a)
            elif isinstance(node.argument, list) and len(node.argument) == 1:
                emit(f'({node.filter} "{node.argument[0]}")')
            else:
                emit(f"({node.filter} {node.argument})")

        case _:
            raise ValueError(
                f"Unsupported Z3 expression: {expr} (decl kind: {decl_kind})"
            )
