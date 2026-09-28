#!/usr/bin/env python3
"""Split CrystalDirge's tools/docudp.py into the tools/docworld/ package.

A copy of split_core.py, the tool that cut OpenLobby's responders.py into
services/core/, generalised for a second source file; the differences are
listed under "Changes from split_core.py" below. It is deterministic: the
same source and the same map give the same package, so a dev commit ported
into the flat docudp.py is carried into the package by running it again.

    python split_docudp.py --src <flat docudp.py> --map split_docudp_map.txt \
        --out <repo>/tools/docworld --facade <repo>/tools/docudp.py
    python split_docudp.py --src ... --map ... --check        # report only, write nothing
    python split_docudp.py --src ... --map ... --verify <repo>/tools/docworld
                                        # every statement of the source is in the package,
                                        # changed only by the qualification below
    python split_docudp.py --src ... --ranges ranges.txt     # derive a map from line ranges

The flat file is the input, so keep it: `git show <commit>:tools/docudp.py`
of the last commit before the split, with any ported commits applied, is what
--src reads.

How it works
- Every top-level statement of the flat file is assigned to one module of the
  package by the map (defs and module globals by NAME; unnamed statements by a
  `~prefix` of their first line). The comment block above a statement travels
  with it, so the section banners and the per-function commentary survive.
- Inside a moved statement, every reference to a top-level name that now lives
  in ANOTHER module is rewritten to `<module>.<name>`. Scope analysis follows
  Python's rules (function scopes nest, class bodies do not), so a local that
  shadows a module name is left alone.
- Import-like statements (plain imports, and `try: import x / except: x = None`
  blocks) go to <package>/deps.py; a module that uses such a name gets the plain
  import, or `from .deps import x` for the optional ones.
- The old file becomes a facade: `import docudp as D` keeps working for every
  tool and test, reads AND writes (`D.name = fake`) are forwarded to the
  owning module, and `python docudp.py <flags>` still starts the server.

Changes from split_core.py
- Names are parameters (--name, --package, --title) instead of responders/core.
- `!extract FUNC NEW: BEGIN .. END` in the map moves a run of statements out
  of a function body into a new top-level function NEW before the split runs
  (docudp's argparse block leaves main() this way). The run must bind exactly
  one name, which NEW returns, and must not read any other local of FUNC.
- A `try:` block that imports and then sets a flag from the import
  (`try: import doc_kelcrypt; _KELCRYPT = ...`) counts as an optional import.
- `global` statements are supported: a function that declares a module name
  global and assigns it now assigns `<owner>.<name>`, and the `global` line
  is dropped when every name it lists lives in another module.
- `os.path.dirname(os.path.abspath(__file__))` in a moved statement is the
  flat file's own directory; inside the package it becomes the parent of the
  package directory, so data files next to the old file are still found.
- The map can send a non-import statement to deps with a `~prefix`
  (docudp's sys.path line, which must run before its sibling imports).
- The source's module docstring can be sent to a module with a `~` prefix
  that matches its first line, quotes included; it then becomes that
  module's docstring (docudp's argparse description is `__doc__`, so the
  docstring goes where the parser is built).
- --verify compares a written package with the source statement by statement.
- The source's `if __name__ == "__main__":` block is copied into the facade
  verbatim instead of a fixed `main()` call.
"""
import argparse
import ast
import collections
import io
import os
import re
import sys

BANNER = re.compile(r"^# -{20,} #\s*$")


# --------------------------------------------------------------------------- #
# Source model
# --------------------------------------------------------------------------- #
class Stmt:
    __slots__ = ("node", "names", "kind", "first", "last", "span_first", "text", "module")

    def __init__(self, node, names, kind, first, last):
        self.node = node
        self.names = names        # top-level names this statement binds
        self.kind = kind          # def | assign | import | optimport | other
        self.first = first        # first line of the statement proper
        self.last = last
        self.span_first = None    # first line including the comment block above
        self.text = None
        self.module = None


def bound_targets(target):
    out = []
    for n in ast.walk(target):
        if isinstance(n, ast.Name):
            out.append(n.id)
    return out


def classify(node):
    """(names, kind) for a top-level statement."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name], "def"
    if isinstance(node, ast.Assign):
        names = []
        for t in node.targets:
            names += bound_targets(t)
        return names, "assign"
    if isinstance(node, ast.AnnAssign):
        return bound_targets(node.target), "assign"
    if isinstance(node, ast.AugAssign):
        return [], "other"
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return [(a.asname or a.name).split(".")[0] for a in node.names], "import"
    if isinstance(node, ast.Try):
        # imports, optionally followed by plain assignments that record what
        # the import found (`_KELCRYPT = doc_kelcrypt.available()`)
        body_ok = node.body and isinstance(node.body[0], (ast.Import, ast.ImportFrom)) and all(
            isinstance(b, (ast.Import, ast.ImportFrom, ast.Assign)) for b in node.body)
        if body_ok and node.handlers:
            names = []
            for b in node.body:
                if isinstance(b, ast.Assign):
                    for t in b.targets:
                        names += bound_targets(t)
                else:
                    names += [(a.asname or a.name).split(".")[0] for a in b.names]
            return list(dict.fromkeys(names)), "optimport"
    return [], "other"


def load_source(path, text=None):
    if text is None:
        text = open(path, encoding="utf-8").read()
    lines = text.splitlines(keepends=True)
    tree = ast.parse(text)
    stmts = []
    for node in tree.body:
        names, kind = classify(node)
        first = node.lineno
        # decorators sit above the def line
        for d in getattr(node, "decorator_list", []):
            first = min(first, d.lineno)
        stmts.append(Stmt(node, names, kind, first, node.end_lineno))
    prev_end = 0
    for s in stmts:
        s.span_first = prev_end + 1
        s.text = "".join(lines[s.span_first - 1:s.last])
        prev_end = s.last
    trailing = "".join(lines[prev_end:])
    return text, lines, tree, stmts, trailing


# --------------------------------------------------------------------------- #
# The map
# --------------------------------------------------------------------------- #
def read_map(path):
    """{module: {"doc": str, "names": set, "prefixes": [str]}} in file order."""
    mods = collections.OrderedDict()
    cur = None
    for raw in open(path, encoding="utf-8"):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith(("#", "!")):
            continue
        m = re.match(r"^\[([A-Za-z_][A-Za-z0-9_]*)\]\s*(.*)$", line)
        if m:
            cur = m.group(1)
            mods[cur] = {"doc": m.group(2).strip(), "names": set(), "prefixes": []}
            continue
        if cur is None:
            raise SystemExit(f"{path}: entry before any [module] header: {line!r}")
        if line.startswith("~"):
            mods[cur]["prefixes"].append(line[1:].rstrip())
        else:
            for tok in line.split():
                mods[cur]["names"].add(tok)
    return mods


def read_directives(path):
    """The `!extract` and `!doc` lines of the map.

        !extract FUNC -> NEW: BEGIN .. END
        !doc NEW: one-line docstring for the extracted function
    """
    extracts, docs = [], {}
    for raw in open(path, encoding="utf-8"):
        line = raw.rstrip("\n")
        m = re.match(r"^!extract\s+(\w+)\s*->\s*(\w+):\s*(.+?)\s+\.\.\s+(.+)$", line)
        if m:
            extracts.append(m.groups())
            continue
        m = re.match(r"^!doc\s+(\w+):\s*(.+)$", line)
        if m:
            docs[m.group(1)] = m.group(2).strip()
    return extracts, docs


def apply_extract(text, func, new, begin, end, doc):
    """Move the statements of `func` from the one starting with BEGIN up to
    (not including) the one starting with END into a new top-level function
    `new`, placed just above `func`; `func` calls it instead. Refuses unless
    the run binds exactly one name and reads no other local of `func`."""
    lines = text.splitlines(keepends=True)
    tree = ast.parse(text)
    idx = [i for i, n in enumerate(tree.body)
           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func]
    if len(idx) != 1:
        raise SystemExit(f"!extract: no single top-level function {func!r}")
    fi = idx[0]
    fn = tree.body[fi]
    heads = [lines[b.lineno - 1].strip() for b in fn.body]
    starts = [k for k, h in enumerate(heads) if h.startswith(begin)]
    ends = [k for k, h in enumerate(heads) if h.startswith(end)]
    if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0]:
        raise SystemExit(f"!extract {func} -> {new}: BEGIN/END do not pick one run "
                         f"({len(starts)} begin, {len(ends)} end)")
    run = fn.body[starts[0]:ends[0]]
    first = run[0]
    if not (isinstance(first, ast.Assign) and len(first.targets) == 1
            and isinstance(first.targets[0], ast.Name)):
        raise SystemExit(f"!extract {func} -> {new}: the run must start with `name = ...`")
    ret = first.targets[0].id
    block = ast.Module(body=run, type_ignores=[])
    bound = local_bindings(block)
    if bound != {ret}:
        raise SystemExit(f"!extract {func} -> {new}: the run binds {sorted(bound)}, "
                         f"not just {ret!r}")
    others = local_bindings(fn) - {ret}
    reads = {n.id for n in global_name_refs(block)} & others
    if reads:
        raise SystemExit(f"!extract {func} -> {new}: the run reads locals {sorted(reads)}")
    indent = first.col_offset
    if indent != 4:
        raise SystemExit(f"!extract {func} -> {new}: expected a 4-space body, got {indent}")
    lo, hi = first.lineno, run[-1].end_lineno
    body_text = lines[lo - 1:hi]
    new_def = [f"def {new}():\n"]
    if doc:
        new_def.append(f'    """{doc}"""\n')
    new_def += body_text + [f"    return {ret}\n", "\n", "\n"]
    out = list(lines)
    out[lo - 1:hi] = [" " * indent + f"{ret} = {new}()\n"]
    # above the function's own comment block, right after the previous statement
    at = tree.body[fi - 1].end_lineno if fi > 0 else 0
    out[at:at] = ["\n", "\n"] + new_def[:-2]
    return "".join(out), (hi - lo + 1)


def assign_modules(stmts, mods, facade_prefixes):
    owner = {}
    for mod, spec in mods.items():
        for n in spec["names"]:
            if n in owner:
                raise SystemExit(f"map: {n} listed in both {owner[n]} and {mod}")
            owner[n] = mod
    unmapped = []
    for s in stmts:
        first_line = "".join(s.text.splitlines(keepends=True)[s.first - s.span_first:s.first - s.span_first + 1]).rstrip()
        if s.kind in ("import", "optimport"):
            s.module = "deps"
            continue
        if any(first_line.startswith(p) for p in facade_prefixes):
            s.module = "__facade__"
            continue
        hit = None
        for mod, spec in mods.items():
            if any(first_line.startswith(p) for p in spec["prefixes"]):
                hit = mod
                break
        if hit is None and s.names:
            owners = {owner.get(n) for n in s.names}
            owners.discard(None)
            if len(owners) > 1:
                raise SystemExit(f"L{s.first}: names {s.names} map to several modules {owners}")
            if owners:
                hit = owners.pop()
        if hit is None:
            if s.kind == "other" and isinstance(s.node, ast.Expr) and isinstance(
                    getattr(s.node, "value", None), ast.Constant) and s.first == 1:
                s.module = "__facade__"      # the module docstring
                continue
            unmapped.append(s)
            continue
        s.module = hit
    return owner, unmapped


# --------------------------------------------------------------------------- #
# Scope analysis
# --------------------------------------------------------------------------- #
def local_bindings(scope_node):
    """Names bound directly in this function/lambda/comprehension scope."""
    bound = set()
    declared_global = set()
    args = getattr(scope_node, "args", None)
    if args is not None:
        for a in args.posonlyargs + args.args + args.kwonlyargs:
            bound.add(a.arg)
        if args.vararg:
            bound.add(args.vararg.arg)
        if args.kwarg:
            bound.add(args.kwarg.arg)
    if isinstance(scope_node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
        for g in scope_node.generators:
            bound |= set(bound_targets(g.target))

    def walk(n):
        for c in ast.iter_child_nodes(n):
            if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bound.add(c.name)
                for d in c.decorator_list:
                    walk(d)
                if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for d in c.args.defaults + c.args.kw_defaults:
                        if d is not None:
                            walk(d)
                continue
            if isinstance(c, ast.Lambda):
                for d in c.args.defaults + c.args.kw_defaults:
                    if d is not None:
                        walk(d)
                continue
            if isinstance(c, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                # the first iterable is evaluated in the enclosing scope
                walk(c.generators[0].iter)
                continue
            if isinstance(c, ast.Name) and isinstance(c.ctx, (ast.Store, ast.Del)):
                bound.add(c.id)
            elif isinstance(c, ast.ExceptHandler) and c.name:
                bound.add(c.name)
            elif isinstance(c, (ast.Import, ast.ImportFrom)):
                for a in c.names:
                    bound.add((a.asname or a.name).split(".")[0])
            elif isinstance(c, ast.NamedExpr):
                bound.add(c.target.id)
            elif isinstance(c, ast.MatchAs) and c.name:
                bound.add(c.name)
            elif isinstance(c, ast.MatchStar) and c.name:
                bound.add(c.name)
            elif isinstance(c, ast.MatchMapping) and c.rest:
                bound.add(c.rest)
            elif isinstance(c, ast.Global):
                declared_global.update(c.names)
            walk(c)

    if isinstance(scope_node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
        for g in scope_node.generators:
            for cond in g.ifs:
                walk(cond)
            if g is not scope_node.generators[0]:
                walk(g.iter)
        if isinstance(scope_node, ast.DictComp):
            walk(scope_node.key)
            walk(scope_node.value)
        else:
            walk(scope_node.elt)
    else:
        walk(scope_node)
    # a name the scope declares `global` is the module's, however it is used
    return bound - declared_global


def global_name_refs(stmt_node):
    """Yield every Name node in the statement that resolves to MODULE scope."""
    out = []

    def visit(n, fn_scopes, in_class):
        # fn_scopes: list of sets of names bound in enclosing FUNCTION scopes
        for c in ast.iter_child_nodes(n):
            if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                for d in getattr(c, "decorator_list", []):
                    visit_expr(d, fn_scopes)
                for d in c.args.defaults + c.args.kw_defaults:
                    if d is not None:
                        visit_expr(d, fn_scopes)
                for a in c.args.posonlyargs + c.args.args + c.args.kwonlyargs:
                    if a.annotation is not None:
                        visit_expr(a.annotation, fn_scopes)
                if getattr(c, "returns", None) is not None:
                    visit_expr(c.returns, fn_scopes)
                inner = local_bindings(c)
                body = c.body if isinstance(c.body, list) else [c.body]
                for b in body:
                    visit(b, fn_scopes + [inner], False)
                    if isinstance(b, ast.Name):
                        resolve(b, fn_scopes + [inner])
                continue
            if isinstance(c, ast.ClassDef):
                visit_class(c, fn_scopes)
                continue
            if isinstance(c, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                visit(c.generators[0].iter, fn_scopes, in_class)
                if isinstance(c.generators[0].iter, ast.Name):
                    resolve(c.generators[0].iter, fn_scopes)
                inner = local_bindings(c)
                scopes = fn_scopes + [inner]
                parts = [g.ifs for g in c.generators] + [[g.iter] for g in c.generators[1:]]
                elts = [c.key, c.value] if isinstance(c, ast.DictComp) else [c.elt]
                for group in parts + [elts]:
                    for p in group:
                        visit(p, scopes, False)
                        if isinstance(p, ast.Name):
                            resolve(p, scopes)
                continue
            if isinstance(c, ast.Name):
                resolve(c, fn_scopes)
            visit(c, fn_scopes, in_class)

    def visit_expr(node, fn_scopes):
        if isinstance(node, ast.Name):
            resolve(node, fn_scopes)
        else:
            visit(node, fn_scopes, False)

    def resolve(name_node, fn_scopes):
        for sc in fn_scopes:
            if name_node.id in sc:
                return
        out.append(name_node)

    def visit_class(c, fn_scopes):
        for d in c.decorator_list:
            visit_expr(d, fn_scopes)
        for b in c.bases + [k.value for k in c.keywords]:
            visit_expr(b, fn_scopes)
        # names assigned directly in the class body are class attributes: they
        # shadow module names for the body's own statements, not for methods
        class_bound = set()
        for b in c.body:
            if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                class_bound.add(b.name)
                continue
            for n in ast.walk(b):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    class_bound.add(n.id)
        for b in c.body:
            if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                visit(ast.Module(body=[b], type_ignores=[]), fn_scopes, False)
            else:
                visit(b, fn_scopes + [class_bound], True)
                if isinstance(b, ast.Name):
                    resolve(b, fn_scopes + [class_bound])

    if isinstance(stmt_node, ast.Name):
        out.append(stmt_node)
        return out
    if isinstance(stmt_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        # the statement IS a function: its body runs in its own local scope
        for d in getattr(stmt_node, "decorator_list", []):
            visit_expr(d, [])
        for d in stmt_node.args.defaults + stmt_node.args.kw_defaults:
            if d is not None:
                visit_expr(d, [])
        for a in stmt_node.args.posonlyargs + stmt_node.args.args + stmt_node.args.kwonlyargs:
            if a.annotation is not None:
                visit_expr(a.annotation, [])
        if getattr(stmt_node, "returns", None) is not None:
            visit_expr(stmt_node.returns, [])
        inner = local_bindings(stmt_node)
        for b in stmt_node.body:
            visit(b, [inner], False)
        return out
    if isinstance(stmt_node, ast.ClassDef):
        visit_class(stmt_node, [])
        return out
    visit(stmt_node, [], False)
    return out


def inside_fstring(tree_stmt):
    """Set of id()s of Name nodes that sit inside f-strings (positions unreliable < 3.12)."""
    ids = set()
    for n in ast.walk(tree_stmt):
        if isinstance(n, ast.JoinedStr):
            for m in ast.walk(n):
                if isinstance(m, ast.Name):
                    ids.add(id(m))
    return ids


# --------------------------------------------------------------------------- #
# Rewriting
# --------------------------------------------------------------------------- #
def rewrite_statement(stmt, owner, lines, import_names, report):
    """Return the statement text with cross-module names qualified, plus the
    set of modules it references and the import-like names it uses."""
    edits = []          # (lineno, col, end_col, new)
    deps = set()
    used_imports = set()
    drop_lines = set()
    fstr = inside_fstring(stmt.node)
    # `global X` in a function: X is assigned as <owner>.X once X lives in
    # another module, so the declaration goes (or keeps only the local names)
    declared = set()
    for g in ast.walk(stmt.node):
        if not isinstance(g, ast.Global):
            continue
        declared |= set(g.names)
        keep = [n for n in g.names if owner.get(n) in (None, stmt.module)]
        if len(keep) == len(g.names):
            continue
        if g.lineno != g.end_lineno:
            report.append(f"L{g.lineno}: multi-line global statement -- fix by hand")
            continue
        if keep:
            line = lines[g.lineno - 1]
            edits.append((g.lineno, g.col_offset, len(line.rstrip("\r\n")),
                          "global " + ", ".join(keep)))
        else:
            drop_lines.add(g.lineno)
        report.append(f"L{g.lineno}: global {', '.join(g.names)} -> assigned through the owner")
    for nm in global_name_refs(stmt.node):
        ident = nm.id
        if ident in import_names:
            used_imports.add(ident)
            continue
        mod = owner.get(ident)
        if mod is None or mod == stmt.module:
            continue
        if (isinstance(nm.ctx, ast.Store) and ident not in declared
                and stmt.module != "boot" and stmt.module != "__facade__"):
            report.append(f"L{nm.lineno}: {stmt.module} STORES {ident} owned by {mod}")
        line = lines[nm.lineno - 1]
        if line[nm.col_offset:nm.end_col_offset] != ident or id(nm) in fstr and False:
            report.append(f"L{nm.lineno}:{nm.col_offset} position mismatch for {ident} "
                          f"(f-string?) -- fix by hand: {line.strip()[:80]}")
            continue
        if id(nm) in fstr:
            # position verified above; f-string names are rewritten too
            pass
        edits.append((nm.lineno, nm.col_offset, nm.end_col_offset, f"{mod}.{ident}"))
        deps.add(mod)
    # apply edits right-to-left per line
    text_lines = lines[stmt.span_first - 1:stmt.last]
    by_line = collections.defaultdict(list)
    for ln, c0, c1, new in edits:
        by_line[ln].append((c0, c1, new))
    for ln, eds in by_line.items():
        idx = ln - stmt.span_first
        s = text_lines[idx]
        for c0, c1, new in sorted(eds, reverse=True):
            s = s[:c0] + new + s[c1:]
        text_lines[idx] = s
    for ln in drop_lines:
        text_lines[ln - stmt.span_first] = None
    text_lines = [t for t in text_lines if t is not None]
    return "".join(text_lines), deps, used_imports


HERE_OLD = "os.path.dirname(os.path.abspath(__file__))"
HERE_NEW = "os.path.dirname(os.path.dirname(os.path.abspath(__file__)))"


def rehome_file_refs(text, report, where):
    """The flat file's directory is the package's parent directory."""
    n = text.count(HERE_OLD)
    if n:
        report.append(f"{where}: {n} x __file__ directory -> the package's parent")
    rest = text.replace(HERE_OLD, "")
    if "__file__" in rest:
        report.append(f"{where}: other __file__ use -- check by hand")
    return text.replace(HERE_OLD, HERE_NEW)


def module_docstring(doc):
    return '"""' + doc + '"""\n' if doc else ""


def import_lines_for(used, import_stmts, optional_names):
    """Emit the import statements a module needs, in the head's order."""
    plain = []
    optional = sorted(n for n in used if n in optional_names)
    for names, text, is_from in import_stmts:
        want = [n for n in names if n in used and n not in optional_names]
        if not want:
            continue
        if is_from and len(names) > 1:
            mod = re.match(r"\s*from\s+(\S+)\s+import", text).group(1)
            plain.append(f"from {mod} import {', '.join(sorted(want))}\n")
        else:
            plain.append(text.strip() + "\n")
    out = "".join(plain)
    if optional:
        out += f"from .deps import {', '.join(optional)}\n"
    return out




def verify(tree, pkg_dir, docstring_module):
    """Every top-level statement of the (extracted) flat source must appear in
    exactly one package module, identical up to `<module>.X` -> `X` and dropped
    `global` lines. Returns the statements that do not pair up."""
    mods = {f[:-3] for f in os.listdir(pkg_dir) if f.endswith(".py") and f != "__init__.py"}

    class Unqualify(ast.NodeTransformer):
        def visit_Attribute(self, node):
            self.generic_visit(node)
            if isinstance(node.value, ast.Name) and node.value.id in mods:
                return ast.copy_location(ast.Name(id=node.attr, ctx=node.ctx), node)
            return node

        def visit_Global(self, node):
            return None

    def norm(node):
        text = ast.unparse(node).replace(HERE_NEW, HERE_OLD)
        return ast.dump(Unqualify().visit(ast.parse(text)))

    def label(node):
        return getattr(node, "name", None) or ast.unparse(node).splitlines()[0][:70]

    pending = collections.defaultdict(list)
    for node in tree.body:
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            pending[norm(node)].append(label(node))
    extra = []
    for m in sorted(mods):
        body = ast.parse(open(os.path.join(pkg_dir, m + ".py"), encoding="utf-8").read()).body
        for i, node in enumerate(body):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            if (i == 0 and m != docstring_module and isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Constant)):
                continue            # the map's one-line module docstring
            key = norm(node)
            if pending.get(key):
                pending[key].pop()
            else:
                extra.append(f"only in {m}.py: {label(node)}")
    missing = [f"not in the package: {x}" for v in pending.values() for x in v]
    return extra + missing


FACADE_TEMPLATE = '''"""{title}

The code lives in the `{package}` package beside this file, one module per
concern ({package}/__init__.py lists them). This module is the entry point
the container runs (`python {name}.py <flags>`; `--help` lists them) and a
compatibility facade: `import {name}` still resolves every name, reading or
writing, to the module that owns it, so tools and tests written against the
single-file layout keep working.
"""
import os
import sys
import types

# ONE COPY OF THIS MODULE. The container runs `python {name}.py`, so the
# running copy is `__main__`; a later `import {name}` would otherwise load a
# second copy.
if __name__ == "__main__":
    sys.modules.setdefault("{name}", sys.modules[__name__])

# the package and the sibling modules it imports (doc_*.py) sit beside this file
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from {package} import (  # noqa: E402,F401
{module_imports}
)
from {package}.{main_module} import main  # noqa: E402

# Which {package} module owns each top-level name of the old {name}.py.
_OWNERS = {{
{owners}
}}
_MODULES = {{
{modules_dict}
}}


class _Facade(types.ModuleType):
    """`{name}.<name>` reads and writes go to the owning {package} module."""

    def __getattr__(self, name):
        mod = _OWNERS.get(name)
        if mod is None:
            raise AttributeError(f"module '{name}' has no attribute {{name!r}}")
        return getattr(_MODULES[mod], name)

    def __setattr__(self, name, value):
        mod = _OWNERS.get(name)
        if mod is None:
            super().__setattr__(name, value)
            return
        setattr(_MODULES[mod], name, value)
        if mod == "deps":
            # an imported name is a copy in every module that imported it;
            # a patch has to reach each copy
            for other in _MODULES.values():
                if other is not deps and hasattr(other, name):
                    setattr(other, name, value)

    def __dir__(self):
        return sorted(set(super().__dir__()) | set(_OWNERS))


sys.modules[__name__].__class__ = _Facade
{main_block}'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--map")
    ap.add_argument("--out")
    ap.add_argument("--facade")
    ap.add_argument("--name", default="docudp", help="the old module's name")
    ap.add_argument("--package", default="docworld", help="the package's name")
    ap.add_argument("--title", default="The Dirge of Cerberus world responder (UDP 55040).",
                    help="first line of the facade's and the package's docstring")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--verify", metavar="PKG_DIR",
                    help="compare a written package with the source, statement by statement")
    ap.add_argument("--ranges", help="derive a map from 'lo hi module' lines and print it")
    args = ap.parse_args()

    src_text = open(args.src, encoding="utf-8").read()
    extracted = []
    if args.map:
        extracts, docs = read_directives(args.map)
        for func, new, begin, end in extracts:
            src_text, n = apply_extract(src_text, func, new, begin, end, docs.get(new))
            extracted.append(f"{func} -> {new}: {n} lines")
    text, lines, tree, stmts, trailing = load_source(args.src, src_text)

    if args.ranges:
        ranges = []
        for raw in open(args.ranges, encoding="utf-8"):
            raw = raw.split("#")[0].strip()
            if not raw:
                continue
            lo, hi, mod = raw.split()
            ranges.append((int(lo), int(hi), mod))
        per = collections.OrderedDict()
        for lo, hi, mod in ranges:
            per.setdefault(mod, [])
        for s in stmts:
            if s.kind in ("import", "optimport") or not s.names:
                continue
            for lo, hi, mod in ranges:
                if lo <= s.first <= hi:
                    per[mod].extend(s.names)
                    break
            else:
                print(f"# UNCOVERED L{s.first}: {s.names}", file=sys.stderr)
        for mod, names in per.items():
            print(f"[{mod}]")
            buf = ""
            for n in names:
                if len(buf) + len(n) + 1 > 96:
                    print(buf.rstrip())
                    buf = ""
                buf += n + " "
            if buf:
                print(buf.rstrip())
            print()
        return

    mods = read_map(args.map)
    if "deps" not in mods:
        mods["deps"] = {"doc": "Imports shared by the package's modules.",
                        "names": set(), "prefixes": []}
    facade_prefixes = ["if __name__ == \"__main__\":"]
    owner, unmapped = assign_modules(stmts, mods, facade_prefixes)

    # the source's module docstring, when the map sends it to a module
    docstring_stmt = None
    first_node = tree.body[0] if tree.body else None
    if (isinstance(first_node, ast.Expr) and isinstance(first_node.value, ast.Constant)
            and isinstance(first_node.value.value, str)):
        docstring_stmt = stmts[0]
    mod_docstring = {}

    # import-like names and their statements
    import_stmts = []       # (names, text, is_from)
    optional_names = set()
    import_names = set()
    for s in stmts:
        if s.kind == "import":
            import_stmts.append((s.names, "".join(lines[s.first - 1:s.last]),
                                 isinstance(s.node, ast.ImportFrom)))
            import_names |= set(s.names)
        elif s.kind == "optimport":
            optional_names |= set(s.names)
            import_names |= set(s.names)
    # names bound in deps are owned by deps for the facade
    for n in import_names:
        owner.setdefault(n, "deps")

    report = []
    report += [f"EXTRACTED {e}" for e in extracted]
    if unmapped:
        for s in unmapped:
            first_line = lines[s.first - 1].rstrip()
            report.append(f"UNMAPPED L{s.first}-{s.last} {s.kind} {s.names or ''}: {first_line[:90]}")

    # build module bodies
    bodies = collections.OrderedDict((m, []) for m in mods)
    bodies["deps"] = bodies.get("deps", [])
    mod_deps = collections.defaultdict(set)
    mod_imports = collections.defaultdict(set)
    facade_head = []
    stats = collections.Counter()
    for s in stmts:
        if s.module is None:
            continue
        if s.module == "__facade__":
            facade_head.append(s)
            continue
        if s is docstring_stmt:
            mod_docstring[s.module] = "".join(lines[s.first - 1:s.last])
            continue
        if s.kind in ("import", "optimport"):
            if s.kind == "optimport" or s.module == "deps":
                bodies["deps"].append("".join(lines[s.span_first - 1:s.last]))
            continue
        new_text, deps, used = rewrite_statement(s, owner, lines, import_names, report)
        new_text = rehome_file_refs(new_text, report, f"L{s.first} {s.module}")
        bodies[s.module].append(new_text)
        mod_deps[s.module] |= deps
        mod_imports[s.module] |= used
        stats[s.module] += 1

    # module-name collisions with local variables: a function in module A that
    # binds a local named like module B while A references B.<x>
    for s in stmts:
        if s.module in (None, "__facade__", "deps") or s.kind != "def":
            continue
        for fn in ast.walk(s.node):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                loc = local_bindings(fn)
                clash = loc & mod_deps[s.module]
                for c in clash:
                    # only a problem if the function itself references that module
                    refs = {owner.get(n.id) for n in global_name_refs(fn) if owner.get(n.id) != s.module}
                    if c in refs:
                        report.append(f"L{fn.lineno}: local {c!r} in {s.module}.{getattr(fn, 'name', '<lambda>')} "
                                      f"shadows module {c} that the function references")
    # a module name that is also a top-level name of the source
    for m in mods:
        if m in owner and owner[m] != m:
            report.append(f"module name {m!r} is also a top-level name (owned by {owner[m]})")

    # import-time dependencies (module-level non-def statements using other modules)
    import_time = collections.defaultdict(set)

    def def_time_refs(node):
        """Names evaluated when a def/class statement itself executes."""
        exprs = list(getattr(node, "decorator_list", []))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            exprs += [d for d in node.args.defaults + node.args.kw_defaults if d is not None]
            exprs += [a.annotation for a in node.args.posonlyargs + node.args.args
                      + node.args.kwonlyargs if a.annotation is not None]
            if node.returns is not None:
                exprs.append(node.returns)
        elif isinstance(node, ast.ClassDef):
            exprs += node.bases + [k.value for k in node.keywords]
            for b in node.body:
                if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    exprs += def_time_exprs(b)
                else:
                    exprs.append(b)
        out = []
        for e in exprs:
            out += global_name_refs(e)
        return out

    def def_time_exprs(node):
        exprs = list(getattr(node, "decorator_list", []))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            exprs += [d for d in node.args.defaults + node.args.kw_defaults if d is not None]
        return exprs

    for s in stmts:
        if s.module in (None, "__facade__", "deps") or s is docstring_stmt:
            continue
        refs = def_time_refs(s.node) if s.kind == "def" else global_name_refs(s.node)
        for nm in refs:
            mod = owner.get(nm.id)
            if mod and mod not in (s.module, "deps") and nm.id not in import_names:
                # a def reference at import time needs the other module fully loaded
                import_time[s.module].add(f"{mod}.{nm.id}")

    # cycles among import-time deps
    def reaches(a, b, seen=None):
        seen = seen or set()
        for c in {x.split(".")[0] for x in import_time.get(a, ())}:
            if c == b or (c not in seen and reaches(c, b, seen | {c})):
                return True
        return False
    for a, bs in import_time.items():
        for b in {x.split(".")[0] for x in bs}:
            if reaches(b, a):
                report.append(f"IMPORT-TIME CYCLE {a} <-> {b}")

    print(f"statements: {len(stmts)}  modules: {len(bodies)}  unmapped: {len(unmapped)}")
    for m, c in stats.most_common():
        print(f"  {c:>4}  {m}  (uses: {', '.join(sorted(mod_deps[m]))})")
    if import_time:
        print("import-time dependencies:")
        for a, bs in import_time.items():
            print(f"  {a} -> {', '.join(sorted(bs))}")
    if report:
        print("\nREPORT (%d):" % len(report))
        for r in report:
            print("  " + r)
    if args.verify:
        doc_mod = docstring_stmt.module if docstring_stmt is not None else None
        problems = verify(tree, args.verify, doc_mod)
        # the facade keeps the `if __name__ == "__main__":` block
        problems = [p for p in problems if not p.startswith("not in the package: if __name__")]
        print(f"\nverify {args.verify}: {len(problems)} statement(s) do not pair up")
        for p in problems:
            print("  " + p)
        raise SystemExit(1 if problems else 0)
    if args.check or not args.out:
        return
    if unmapped or any(r.startswith(("IMPORT-TIME CYCLE", "UNMAPPED", "module name")) or "shadows module" in r
                       or "position mismatch" in r or "by hand" in r or " STORES " in r
                       for r in report):
        raise SystemExit("refusing to write: fix the report first")

    os.makedirs(args.out, exist_ok=True)
    order = list(mods)  # map order = import order; deps first
    if "deps" in order:
        order.remove("deps")
    order.insert(0, "deps")
    for m in order:
        spec = mods[m]
        buf = io.StringIO()
        buf.write(mod_docstring.get(m) or module_docstring(spec["doc"]))
        if m == "deps":
            buf.write("".join(bodies["deps"]))
        else:
            imp = import_lines_for(mod_imports[m], import_stmts, optional_names)
            buf.write(imp)
            deps = sorted(mod_deps[m])
            if deps:
                buf.write("from . import " + ", ".join(deps) + "\n")
            buf.write("\n")
            buf.write("".join(bodies[m]))
        content = buf.getvalue()
        if not content.endswith("\n"):
            content += "\n"
        with open(os.path.join(args.out, m + ".py"), "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    # package init: the layout, in map order, with each module's one-line description
    width = max(len(m) for m in order) + 4
    title = args.title[:-1] if args.title.endswith(".") else args.title
    with open(os.path.join(args.out, "__init__.py"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f'"""{title}, one module per concern.\n\n')
        for m in order:
            f.write(f"    {m + '.py':<{width}} {mods[m]['doc']}\n")
        f.write(f'\n{args.name}.py (one directory up) is the entry point and the compatibility\n'
                'facade over these modules.\n"""\n')
    # facade
    if args.facade:
        owners_lines = "\n".join(f"    {n!r}: {m!r}," for n, m in sorted(owner.items()))
        main_block = "".join("".join(lines[s.span_first - 1:s.last]) for s in facade_head
                             if isinstance(s.node, ast.If))
        facade = FACADE_TEMPLATE.format(
            title=args.title, name=args.name, package=args.package,
            main_module=owner["main"],
            module_imports="\n".join(f"    {m}," for m in order),
            owners=owners_lines,
            modules_dict="\n".join(f"    {m!r}: {m}," for m in order),
            main_block=main_block,
        )
        with open(args.facade, "w", encoding="utf-8", newline="\n") as f:
            f.write(facade)
    print("written:", args.out, "and", args.facade)


if __name__ == "__main__":
    main()
