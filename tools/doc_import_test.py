#!/usr/bin/env python3
"""doc_import_test.py -- `python docdb.py import STORE FILE [--merge]
[--dry-run]`: the responder's old JSON store files, into PostgreSQL.

    python doc_import_test.py

Checked on a throwaway database (docpg.py): a dry run on a database that has
never seen HippaulDirge's migrations writes nothing, not even them; an import
into an empty store; the store read back and exported as the file held it,
keys in the file's order; a second run that prints "Nothing to import" and
exits 0; a file with other contents refused (exit 2) and nothing written;
--merge adding only the new keys and listing the differing ones; a store
with sections (stats); a section the store does not have listed and
skipped; and files that cannot be read (exit 1). The source files are byte
for byte what they were.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

import docpg  # noqa: E402

FAILS = []


def check(label, cond, detail=""):
    print("  %-70s %s%s" % (label, "PASS" if cond else "FAIL",
                            ("  " + str(detail)[:600]) if detail and not cond else ""),
          flush=True)
    if not cond:
        FAILS.append(label)


def run(*args):
    p = subprocess.run([sys.executable, os.path.join(HERE, "docdb.py"), "import"]
                       + list(args), cwd=HERE, env=dict(os.environ),
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    return p.returncode, p.stdout + p.stderr


def digest(root):
    out = {}
    for d, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root)] = (hashlib.sha256(fh.read()).hexdigest(),
                                                 os.stat(p).st_mtime_ns)
    return out


#: doc-shop.json as the responder wrote it (sorted keys, as json.dump did)
SHOP = {
    "member:3/0x0001": {"bag": {"101": 2, "205": 1}, "gil": 1200, "kit": [1, 2]},
    "member:3/0x0002": {"bag": {}, "gil": 0, "kit": []},
    "member:7/0x0001": {"bag": {"9": 4}, "gil": 55, "kit": [3]},
}
STATS = {
    "chars": {"member:3/0x0001": {"battles": 4, "medals": {"a": 1, "b": 0}}},
    "weekly": {"2026-39": {"member:3/0x0001": {"kills": 2}}},
    "weeks_closed": {"2026-38": True},
    "extra_section": {"x": 1},
}


def main():
    docpg.need_database("doc_import")
    import docdb
    db = docdb.db
    base = tempfile.mkdtemp(prefix="doc-import-")
    try:
        _main(docdb, db, base)
    finally:
        db.close()
        shutil.rmtree(base, ignore_errors=True)
    print()
    print("FAIL: %d check(s)" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


def _tables(db):
    return sorted(r["t"] for r in db.query(
        "SELECT table_name AS t FROM information_schema.tables"
        " WHERE table_schema = current_schema() AND table_name LIKE 'doc\\_%%'"))


def _main(docdb, db, base):
    shop = os.path.join(base, "doc-shop.json")
    with open(shop, "w", encoding="utf-8") as fh:
        json.dump(SHOP, fh, indent=1, sort_keys=True)
    stats = os.path.join(base, "doc-stats.json")
    with open(stats, "w", encoding="utf-8") as fh:
        json.dump(STATS, fh, indent=1, sort_keys=True)
    before = digest(base)

    print("--dry-run on a database that never saw HippaulDirge's migrations")
    code, out = run("shop", shop, "--dry-run")
    check("exit 0", code == 0, out)
    check("says so", "Dry run: nothing was written." in out, out)
    check("plans the three wallets", "3 read, 0 in the table (not created yet), "
          "0 already there, 3 to insert" in out, out)
    check("no table was created, not even by the migrations", _tables(db) == [],
          _tables(db))

    print("import into an empty store")
    code, out = run("shop", shop)
    check("exit 0, done", code == 0 and "Done: 3 row(s) written." in out, out)
    check("the real run applied the migrations", "doc_wallet" in _tables(db),
          _tables(db))
    got = docdb.export("shop")
    check("the store reads back as the file held it", got == SHOP, got)
    check("keys in the file's order", list(got) == list(SHOP), list(got))
    check("and inside each value too",
          list(got["member:3/0x0001"]) == ["bag", "gil", "kit"]
          and list(got["member:3/0x0001"]["bag"]) == ["101", "205"], got)
    rows = db.query("SELECT key, data::text AS data FROM doc_wallet ORDER BY key")
    check("each row is the text a save writes (so the next save changes nothing)",
          all(r["data"] == docdb._dump(SHOP[r["key"]]) for r in rows), rows)
    t = docdb.store("shop")
    t.load()
    check("a store loaded from it has nothing to save", t._plan(docdb.export("shop"))[1:]
          == ([], []))

    print("a second run changes nothing")
    snap = docdb.export("shop")
    for extra in ((), ("--merge",)):
        code, out = run("shop", shop, *extra)
        check("exit 0, nothing to import%s" % (" (--merge)" if extra else ""),
              code == 0 and "Nothing to import" in out, out)
    check("the store as it was", docdb.export("shop") == snap)

    print("a store that holds other contents: refused, then --merge")
    other = dict(json.loads(json.dumps(SHOP)))
    other["member:3/0x0001"] = dict(other["member:3/0x0001"], gil=1)       # differs
    other["member:9/0x0001"] = {"bag": {}, "gil": 7, "kit": []}            # new
    shop2 = os.path.join(base, "doc-shop-2.json")
    with open(shop2, "w", encoding="utf-8") as fh:
        json.dump(other, fh)
    code, out = run("shop", shop2)
    check("refused: exit 2", code == 2 and "REFUSED: doc_wallet" in out
          and "--merge" in out, out)
    check("and lists the key that differs",
          "the file's differs: member:3/0x0001" in out, out)
    check("nothing written", docdb.export("shop") == snap)
    code, out = run("shop", shop2, "--merge", "--dry-run")
    check("--merge --dry-run writes nothing", code == 0 and docdb.export("shop") == snap,
          out)
    code, out = run("shop", shop2, "--merge")
    got = docdb.export("shop")
    check("--merge: exit 0, one row", code == 0 and "Done: 1 row(s) written." in out, out)
    check("--merge: the new key is in", got.get("member:9/0x0001", {}).get("gil") == 7, got)
    check("--merge: a key in both keeps the store's value",
          got["member:3/0x0001"]["gil"] == 1200, got)
    code, out = run("shop", shop2, "--merge")
    check("--merge again: nothing to import", code == 0 and "Nothing to import" in out,
          out)

    print("a store with sections")
    code, out = run("stats", stats)
    check("exit 0, done", code == 0 and "Done: 3 row(s) written." in out, out)
    check("a section the store has no table for is listed and skipped",
          "skipped section 'extra_section'" in out, out)
    got = docdb.export("stats")
    check("each section in its table",
          got == {k: v for k, v in STATS.items() if k != "extra_section"}, got)
    code, out = run("stats", stats)
    check("a second run: nothing to import", code == 0 and "Nothing to import" in out, out)

    print("files that cannot be read")
    code, out = run("gear", os.path.join(base, "missing.json"))
    check("a missing file: exit 1", code == 1 and "cannot read" in out, out)
    for name, body in (("notjson.json", "{not json"), ("list.json", "[1, 2]")):
        fn = os.path.join(base, name)
        with open(fn, "w", encoding="utf-8") as fh:
            fh.write(body)
        code, out = run("gear", fn)
        check("%s: exit 1" % name, code == 1 and "cannot read" in out, out)
        os.remove(fn)
    bad = os.path.join(base, "bad-stats.json")
    with open(bad, "w", encoding="utf-8") as fh:
        json.dump({"chars": [1, 2]}, fh)
    code, out = run("stats", bad)
    check("a section that is not an object: exit 1", code == 1 and "section 'chars'" in out,
          out)
    os.remove(bad)
    check("gear stayed empty", docdb.store("gear").count() == 0)
    code, out = run("nosuchstore", shop)
    check("an unknown store is a usage error", code == 2, out)

    os.remove(shop2)
    check("the sources are byte for byte what they were",
          digest(base) == before, sorted(set(digest(base)) ^ set(before)))


if __name__ == "__main__":
    sys.exit(main())
