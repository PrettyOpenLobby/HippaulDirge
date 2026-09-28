"""docdb.py -- where CrystalDirge reaches OpenLobby's storage layer.

The world responder keeps its durable player data (the rosters, the wallets,
the gear, the play time, the careers, the rankings and the units) in the
PostgreSQL database the whole stack shares, through OpenLobby's `polcore.db`
(POL_DATABASE_URL). Until this module it kept each of them in a JSON file on
the logs volume, rewritten whole on every change, and the stores were written
against that shape: a `data` dict loaded at start and saved after a change.
They keep that shape. A store's `data` is loaded from its tables here, and
`save()` writes back only the keys whose value changed since the last load or
save, in one transaction.

Each store is one or more tables with one row per key of the old file (see
doc_migrations/5001_doc_state.sql for what each table holds):

    store         tables                                 old file
    characters    doc_character                          doc-characters.json
    ip_members    doc_ip_member                          doc-ip-members.json
    shop          doc_wallet                             doc-shop.json
    gear          doc_gear                               doc-gear.json
    playtime      doc_playtime                           doc-playtime.json
    stats         doc_career / doc_week / doc_week_closed
                  ("chars" / "weekly" / "weeks_closed")  doc-stats.json
    rankings      doc_rank_char / doc_rank_unit
                  ("chars" / "units")                    doc-rankings.json
    units         doc_unit / doc_unit_enlist
                  ("units" / "enlist")                   doc-units.json

A store with several tables keeps the old file's top-level sections, one table
each, so `data["chars"]` still holds the careers.

Nothing here is live state: the responder keeps none outside its own process.
Losing the database loses the players' characters, so a load that cannot
reach it raises, and the responder does not start on an empty store. A save
that fails is reported and retried with the next save.

Finding polcore:

  * in the image, which is built FROM the OpenLobby image, it is /app/polcore
    and imports directly;
  * in a checkout, OPENLOBBY_SERVICES names OpenLobby's `services/`, then
    OPENLOBBY_DIR names the checkout, and failing both the checkout beside
    this repository (../openlobby) is used.

`accounts` (OpenLobby's account code) is found the same way; the resolver in
doc_charastore.py and the unit names in doc_unit.py read the core's session
and friend tables through it.

Migrations are tools/doc_migrations/NNNN_name.sql, applied with
`polcore.db.migrate(directory=...)`. They share OpenLobby's schema_migrations
table, which is keyed by the version number alone, so each repository owns a
range: CrystalDirge numbers its files 5001..5999, and every table it creates
starts with `doc_`.

    python docdb.py migrate               apply what is pending
    python docdb.py status                CrystalDirge's migrations and their state
    python docdb.py export STORE          print a store as its old JSON file
    python docdb.py import STORE FILE [--merge] [--dry-run]
                                          load an old JSON file into the store

`import` reads one old file into its store's tables, in one transaction, the
way the other titles' importers do. Each key of the file (of each section,
for a store with sections) is one row. An empty table takes every row. A
table that already holds rows is refused (exit 2) when the file has keys it
lacks, unless --merge is given, which adds only those keys; a key in both
whose value differs keeps the table's value and is listed. A table that
already holds every key prints "Nothing to import" and exits 0, so a second
run is harmless. --dry-run prints the same report and writes nothing, not
even the migrations. A file that cannot be read as a JSON object exits 1.
A section the store does not have is listed and skipped. The values are
written as every save writes them (docdb's own JSON text, keys sorted as
the old files wrote them), and the rows go in in the file's key order.
"""
import json
import os
import re
import sys
import threading

_HERE = os.path.dirname(os.path.abspath(__file__))

#: CrystalDirge's migration files. Versions 5001..5999 are this repository's.
MIGRATIONS_DIR = os.path.join(_HERE, "doc_migrations")

#: store -> table (a flat store) or {section: table} (one table per section)
STORES = {
    "characters": "doc_character",
    "ip_members": "doc_ip_member",
    "shop": "doc_wallet",
    "gear": "doc_gear",
    "playtime": "doc_playtime",
    "stats": {"chars": "doc_career", "weekly": "doc_week",
              "weeks_closed": "doc_week_closed"},
    "rankings": {"chars": "doc_rank_char", "units": "doc_rank_unit"},
    "units": {"units": "doc_unit", "enlist": "doc_unit_enlist"},
}


def _openlobby_services():
    """Candidate OpenLobby `services/` directories, most specific first."""
    out = []
    env = os.environ.get("OPENLOBBY_SERVICES", "").strip()
    if env:
        out.append(env)
    env = os.environ.get("OPENLOBBY_DIR", "").strip()
    if env:
        out.append(os.path.join(env, "services"))
    out.append(os.path.normpath(os.path.join(_HERE, os.pardir, os.pardir,
                                             "openlobby", "services")))
    out.append("/app")
    return out


def core_path():
    """The OpenLobby `services/` directory polcore is imported from, or None."""
    for cand in _openlobby_services():
        if os.path.isdir(os.path.join(cand, "polcore")):
            return cand
    return None


try:
    from polcore import db  # noqa: E402
except ImportError:
    _core = core_path()
    if _core and _core not in sys.path:
        sys.path.append(_core)
    from polcore import db  # noqa: E402,F811

_schema_lock = threading.Lock()
_schema_ready = set()


def errors():
    """The exceptions that mean the database could not be reached or read,
    as a tuple for `except`."""
    errs = [db.DatabaseNotConfigured, db.MigrationError, db.Error]
    try:
        from psycopg_pool import PoolTimeout
        errs.append(PoolTimeout)
    except ImportError:                                      # pragma: no cover
        pass
    return tuple(errs)


def ensure_schema(log=None):
    """Apply CrystalDirge's pending migrations, once per process and database.

    Cheap after the first call. Raises what `polcore.db.migrate` raises when
    the database cannot be reached, and remembers nothing then, so the next
    call tries again.
    """
    key = db.database_url()
    if key in _schema_ready:
        return
    with _schema_lock:
        if key in _schema_ready:
            return
        db.migrate(directory=MIGRATIONS_DIR,
                   log=log or (lambda msg: print("[docdb] %s" % msg, flush=True)))
        _schema_ready.add(key)


def forget_schema():
    """Drop the once-per-process memo (tests that switch databases)."""
    with _schema_lock:
        _schema_ready.clear()


def migrate_at_start(who):
    """A service's start-up call: apply the migrations now, and say so in the
    log if the database is not there yet (the first use tries again)."""
    try:
        ensure_schema(log=lambda msg: print("[%s] %s" % (who, msg), flush=True))
        return True
    except errors() as exc:
        print("[%s] database not ready (%s); CrystalDirge's tables are "
              "created on first use" % (who, exc), flush=True)
        return False


def accounts():
    """OpenLobby's account module (services/accounts.py), imported beside
    polcore."""
    import accounts as _accounts
    return _accounts


def where():
    """The database this process uses, for a log line (never the password)."""
    try:
        url = db.database_url()
    except db.DatabaseNotConfigured:
        return "(POL_DATABASE_URL is not set)"
    try:
        from urllib.parse import urlsplit
        u = urlsplit(url)
        return "postgresql://%s%s%s" % (u.hostname or "", ":%d" % u.port
                                        if u.port else "", u.path or "")
    except ValueError:
        return "(an unparsable POL_DATABASE_URL)"


def _dump(value):
    # sorted keys and no whitespace: the same text for the same value, so an
    # unchanged row is recognised and not written again
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


_WHINED = set()


def _whine(what, exc):
    if what not in _WHINED:
        _WHINED.add(what)
        print("[docdb] WARNING: %s failed (%r); the change stays in memory and "
              "goes with the next save" % (what, exc), flush=True)


_TABLE_NAME = re.compile(r"^doc_[a-z0-9_]+$")


class Table:
    """One table of `key -> JSON value` rows, read and written as a dict.

    load() returns every row as {key: value}, in key order. save(data) writes
    the keys whose value differs from what this object last loaded or saved,
    and deletes the keys it had that `data` no longer holds. A key this
    object never saw is left alone, so two objects over one table only
    overwrite each other's rows when both changed the same key.
    """

    def __init__(self, name):
        if not _TABLE_NAME.match(name):
            raise ValueError("not a CrystalDirge table name: %r" % name)
        self.name = name
        self._saved = {}

    def __repr__(self):
        return "<docdb.Table %s>" % self.name

    def load(self):
        ensure_schema()
        rows = db.query('SELECT key, data::text AS data FROM %s '
                        'ORDER BY key COLLATE "C"' % self.name)
        out = {}
        saved = {}
        for r in rows:
            out[r["key"]] = json.loads(r["data"])
            saved[r["key"]] = r["data"]
        self._saved = saved
        return out

    def _plan(self, data):
        new = {str(k): _dump(v) for k, v in data.items()}
        changed = [(k, t) for k, t in new.items() if self._saved.get(k) != t]
        gone = [k for k in self._saved if k not in new]
        return new, changed, gone

    def _apply(self, conn, changed, gone):
        if changed:
            with conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO %s (key, data, updated_at) "
                    "VALUES (%%s, %%s::json, now()) ON CONFLICT (key) DO UPDATE "
                    "SET data = EXCLUDED.data, updated_at = now()" % self.name,
                    changed)
        if gone:
            conn.execute("DELETE FROM %s WHERE key = ANY(%%s)" % self.name,
                         (gone,))

    def save(self, data):
        """Write what changed. True when the database has it (or nothing
        changed), False when the write failed (reported once; retried with
        the next save, since the rows are still marked unsaved)."""
        new, changed, gone = self._plan(data)
        if not changed and not gone:
            return True
        try:
            ensure_schema()
            with db.transaction() as conn:
                self._apply(conn, changed, gone)
        except errors() as exc:
            _whine("saving %s" % self.name, exc)
            return False
        self._saved = new
        return True

    def get(self, key):
        """One row's value, or None. Reads the database, not this object."""
        ensure_schema()
        row = db.query_one("SELECT data::text AS data FROM %s WHERE key = %%s"
                           % self.name, (str(key),))
        return None if row is None else json.loads(row["data"])

    def with_prefix(self, prefix):
        """{key: value} for every row whose key starts with `prefix`, in key
        order. Reads the database, not this object."""
        ensure_schema()
        pat = (prefix.replace("\\", "\\\\").replace("%", "\\%")
               .replace("_", "\\_") + "%")
        rows = db.query('SELECT key, data::text AS data FROM %s WHERE key LIKE %%s '
                        'ORDER BY key COLLATE "C"' % self.name, (pat,))
        return {r["key"]: json.loads(r["data"]) for r in rows}

    def count(self):
        ensure_schema()
        return int(db.query_one("SELECT count(*) AS n FROM %s" % self.name)["n"])

    def clear(self):
        """Delete every row (tests, and nothing else)."""
        ensure_schema()
        db.execute("DELETE FROM %s" % self.name)
        self._saved = {}


class Sections:
    """A store whose old file had fixed top-level sections, one table each:
    load() returns {section: {key: value}}, save(data) writes every section
    in one transaction. A section the store does not know is refused, so a
    new one cannot be silently dropped on the way to the database."""

    def __init__(self, tables):
        self.tables = {sec: Table(name) for sec, name in tables.items()}

    def __repr__(self):
        return "<docdb.Sections %s>" % ", ".join(
            "%s=%s" % (s, t.name) for s, t in self.tables.items())

    def load(self):
        return {sec: t.load() for sec, t in self.tables.items()}

    def save(self, data):
        unknown = sorted(set(data) - set(self.tables))
        if unknown:
            raise ValueError("%r has no table for section(s) %s"
                             % (self, ", ".join(map(repr, unknown))))
        plans = {sec: t._plan(data.get(sec) or {})
                 for sec, t in self.tables.items()}
        if not any(p[1] or p[2] for p in plans.values()):
            return True
        try:
            ensure_schema()
            with db.transaction() as conn:
                for sec, (_new, changed, gone) in plans.items():
                    self.tables[sec]._apply(conn, changed, gone)
        except errors() as exc:
            _whine("saving %r" % self, exc)
            return False
        for sec, (new, _c, _g) in plans.items():
            self.tables[sec]._saved = new
        return True

    def count(self):
        return sum(t.count() for t in self.tables.values())

    def clear(self):
        for t in self.tables.values():
            t.clear()


def store(name):
    """A fresh backing object for the store `name` (see STORES)."""
    spec = STORES[name]
    return Sections(spec) if isinstance(spec, dict) else Table(spec)


def export(name):
    """The store `name` as its old JSON file held it."""
    return store(name).load()


class _Rollback(Exception):
    pass


def _read_source(name, path):
    """{table: [(key, value)]} in the file's key order, and [(what, why)]
    skipped, from an old JSON file for the store `name`. Raises OSError or
    ValueError when the file cannot be read as that store's file."""
    spec = STORES[name]
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise ValueError("%s does not hold a JSON object" % path)
    skipped = []
    if not isinstance(spec, dict):
        return {spec: [(str(k), v) for k, v in doc.items()]}, skipped
    rows = {}
    for sec, table in spec.items():
        part = doc.get(sec) or {}
        if not isinstance(part, dict):
            raise ValueError("%s: section %r holds a %s, not an object"
                             % (path, sec, type(part).__name__))
        rows[table] = [(str(k), v) for k, v in part.items()]
    for sec in doc:
        if sec not in spec:
            skipped.append(("section %r" % sec, "the store has no table for it"))
    return rows, skipped


def import_file(name, path, merge=False, dry_run=False, out=print):
    """Import an old JSON file into the store `name`. Returns the exit
    status: 0 done, nothing to do or dry run; 1 the file or the database
    failed; 2 refused, a table already holds rows and the file has keys it
    lacks (without --merge). See the module docstring."""
    try:
        rows, skipped = _read_source(name, path)
    except (OSError, ValueError) as exc:
        out("error: cannot read %s: %s" % (path, exc))
        return 1
    out("import %s: %s" % (name, path))
    for what, why in skipped:
        out("  skipped %s: %s" % (what, why))
    if not dry_run:
        ensure_schema(log=lambda msg: out("  " + msg))
    plans = []
    status = None
    try:
        with db.transaction(lock="crystaldirge.import") as conn:
            for table, items in rows.items():
                exists = conn.execute("SELECT to_regclass(%s) IS NOT NULL AS ok",
                                      (table,)).fetchone()["ok"]
                if not exists and not dry_run:
                    raise RuntimeError("%s does not exist after the migrations"
                                       % table)
                have = {}
                if exists:
                    have = {r["key"]: r["data"] for r in conn.execute(
                        "SELECT key, data::text AS data FROM %s" % table)}
                new, same, differs = [], 0, []
                for key, value in items:
                    text = _dump(value)
                    if key not in have:
                        new.append((key, text))
                    elif _dump(json.loads(have[key])) == text:
                        same += 1
                    else:
                        differs.append(key)
                plans.append((table, len(have), new, differs))
                out("  %s: %d read, %d in the table%s, %d already there, %d to "
                    "insert" % (table, len(items), len(have),
                                "" if exists else " (not created yet)",
                                same + len(differs), len(new)))
                for key in differs:
                    out("    kept the table's row, the file's differs: %s" % key)
            if any(new and target for _t, target, new, _d in plans) and not merge:
                status = "refused"
                raise _Rollback()
            if dry_run:
                status = "dry-run"
                raise _Rollback()
            written = 0
            for table, _target, new, _d in plans:
                for key, text in new:
                    written += conn.execute(
                        "INSERT INTO %s (key, data, updated_at) VALUES "
                        "(%%s, %%s::json, now()) ON CONFLICT (key) DO NOTHING"
                        % table, (key, text)).rowcount
            status = "done" if written else "nothing"
    except _Rollback:
        pass
    except errors() + (RuntimeError,) as exc:
        out("FAILED, rolled back: %s" % exc)
        return 1
    if status == "refused":
        out("REFUSED: %s already holds rows. Nothing was written. Run again "
            "with --merge to add only the keys it lacks."
            % ", ".join(t for t, target, new, _d in plans if new and target))
        return 2
    if status == "dry-run":
        out("Dry run: nothing was written.")
    elif status == "nothing":
        out("Nothing to import: the store already holds every key. "
            "Nothing was changed.")
    else:
        out("Done: %d row(s) written." % written)
    return 0


def _import_main(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="python docdb.py import",
                                 description="Import an old JSON store file "
                                 "(uses POL_DATABASE_URL).")
    ap.add_argument("store", choices=list(STORES))
    ap.add_argument("source")
    ap.add_argument("--merge", action="store_true",
                    help="add only the keys the tables lack")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be imported; write nothing")
    args = ap.parse_args(argv)
    try:
        return import_file(args.store, args.source, merge=args.merge,
                           dry_run=args.dry_run)
    except errors() as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    finally:
        db.close()


def _main(argv):
    cmds = ("migrate", "status", "export", "import")
    if argv and argv[0] == "import":
        return _import_main(argv[1:])
    if not argv or argv[0] not in cmds:
        print(__doc__)
        return 2
    try:
        if argv[0] == "migrate":
            names = db.migrate(directory=MIGRATIONS_DIR)
            print("applied: " + ", ".join(names) if names else "up to date")
        elif argv[0] == "status":
            have = db.applied_migrations()
            for version, name, _path in db.migration_files(MIGRATIONS_DIR):
                row = have.get(version)
                print("%-32s %s" % (name, "applied %s" % row["applied_at"]
                                    if row else "pending"))
        else:
            print(json.dumps(export(argv[1]), indent=1, sort_keys=True))
        return 0
    except (IndexError, KeyError):
        print("usage: docdb.py export STORE | import STORE FILE [--merge] "
              "[--dry-run]; stores: %s" % ", ".join(STORES), file=sys.stderr)
        return 2
    except errors() + (RuntimeError, ValueError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
