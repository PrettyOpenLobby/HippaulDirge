#!/usr/bin/env python3
"""Prove that the docudp facade forwards every read and write to the docworld package.

    python tools/facade_rebind_check.py        # fail on any name the facade does not forward
    python tools/facade_rebind_check.py -v     # also list what was checked

tools/docudp.py is a facade over the tools/docworld package. Reads of
`docudp.<name>` go to the module that owns the name. That is not enough for a
test that REBINDS a name to fake something (`D.host_for = lambda ip: "x"`): a
rebinding that landed on the facade alone would leave every caller inside
the package calling the real function, and the test would keep passing while
testing nothing. So the facade forwards writes to the owning module, and for
a name that modules import by copy (`struct`, `doc_stats`, ...) to every
module that holds a copy.

This checks that promise three ways:
1. every rebinding the tools and tests make (`<alias>.<name> = ...`, where
   the alias is bound by `import docudp as <alias>`) is forwarded;
2. every name the facade owns is forwarded, by writing a sentinel through the
   facade and reading it back through the owner and every module holding a
   copy, so a rebinding a future test adds is covered already;
3. every `<alias>.<name>` a tool or test reads resolves (a read guarded by
   `hasattr(<alias>, "<name>")` is allowed to miss).
Before any of that it runs a falsifier: the same write test against a plain
module with no forwarding must FAIL, or the check cannot fail at all.
"""
import argparse
import ast
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCAN_DIRS = ("tools", "tests")
NAME = "docudp"


def module_aliases(tree):
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == NAME:
                    out.add(a.asname or a.name)
    return out


def uses():
    """([(file, line, attr)] rebindings, [(file, line, attr)] reads)."""
    writes, reads = [], []
    for d in SCAN_DIRS:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [x for x in dirnames if x not in ("__pycache__", "docworld")]
            for fn in sorted(filenames):
                if not fn.endswith(".py"):
                    continue
                path = os.path.join(dirpath, fn)
                rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
                try:
                    tree = ast.parse(open(path, encoding="utf-8").read())
                except (SyntaxError, UnicodeDecodeError):
                    continue
                aliases = module_aliases(tree)
                if not aliases:
                    continue
                # `hasattr(D, "X")` guards a read of a name that may not exist
                guarded = {n.args[1].value for n in ast.walk(tree)
                           if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                           and n.func.id == "hasattr" and len(n.args) == 2
                           and isinstance(n.args[0], ast.Name) and n.args[0].id in aliases
                           and isinstance(n.args[1], ast.Constant)}
                for node in ast.walk(tree):
                    if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                            and node.value.id in aliases):
                        site = (rel, node.lineno, node.attr)
                        if isinstance(node.ctx, ast.Store):
                            writes.append(site)
                        elif node.attr not in guarded:
                            reads.append(site)
    return writes, reads


def forwards(D, attr):
    """None when a write of `attr` through the facade reaches the owning module
    and every module holding a copy; otherwise the reason."""
    owners = getattr(D, "_OWNERS", None)
    modules = getattr(D, "_MODULES", None)
    if owners is None or modules is None:
        return "not the facade (no _OWNERS/_MODULES)"
    home = owners.get(attr)
    if home is None:
        return "not a name of the old docudp.py; the patch lands on the facade only"
    sentinel = object()
    saved = {m: vars(mod)[attr] for m, mod in modules.items() if attr in vars(mod)}
    facade_own = vars(D).get(attr, sentinel)
    try:
        setattr(D, attr, sentinel)
        if getattr(modules[home], attr, None) is not sentinel:
            return f"write did not reach the owner docworld.{home}"
        for m, mod in modules.items():
            if m in saved and getattr(mod, attr) is not sentinel:
                return f"docworld.{m} still holds the old copy"
        if facade_own is sentinel and getattr(D, attr) is not sentinel:
            return "read-back through the facade returned something else"
    finally:
        for m, old in saved.items():
            setattr(modules[m], attr, old)
    return None


def falsifier():
    """The write test must fail on a module that does not forward."""
    home = types.ModuleType("home")
    home.x = 1
    plain = types.ModuleType("plain")
    plain._OWNERS = {"x": "home"}
    plain._MODULES = {"home": home}
    return forwards(plain, "x") is not None


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    if not falsifier():
        print("[FAIL] the falsifier passed: this check cannot detect a facade that does not forward")
        return 1
    print("falsifier: a module that does not forward is caught")
    sys.path.insert(0, HERE)
    import docudp as D

    failures = []
    writes, reads = uses()
    print(f"{len(writes)} rebinding(s) and {len(reads)} read(s) of {NAME} across tools/ and tests/")
    for f, line, attr in writes:
        why = forwards(D, attr)
        if why:
            failures.append(f"rebinding {attr} at {f}:{line}: {why}")
    for f, line, attr in reads:
        if not hasattr(D, attr):
            failures.append(f"read {attr} at {f}:{line}: the facade has no such name")
    names = sorted(D._OWNERS)
    bad = 0
    for attr in names:
        why = forwards(D, attr)
        if why:
            bad += 1
            failures.append(f"{attr}: {why}")
        elif args.verbose:
            print(f"  [PASS] {attr:<32} -> docworld.{D._OWNERS[attr]}")
    print(f"{len(names) - bad}/{len(names)} names the facade owns are forwarded")
    for msg in failures:
        print("  [FAIL] " + msg)
    if failures:
        return 1
    print("every read and every rebinding through the facade reaches the module that runs it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
