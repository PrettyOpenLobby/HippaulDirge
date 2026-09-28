#!/usr/bin/env python3
"""Throwaway PostgreSQL databases for the self-tests, from OpenLobby's
tools/pgtest.py.

    import docpg
    if docpg.fresh_database() is None:       # sets POL_DATABASE_URL
        sys.exit(docpg.skip_or_fail("doc_stats"))

pgtest.py starts a throwaway postgres container on a free loopback port (or
uses POL_TEST_DATABASE_URL's server) and hands out one empty database per
call, and removes what it started when the test process exits. It is found in
the OpenLobby checkout docdb.py finds (OPENLOBBY_SERVICES, OPENLOBBY_DIR, else
the checkout beside this repository).

When doc_run_all.py runs a suite it has already made that suite a database
and says so with DOC_TEST_DATABASE=1; the suite then uses POL_DATABASE_URL as
given. Otherwise a suite always makes its own and never trusts a
POL_DATABASE_URL it finds in the environment, which could be a real stack's.

A suite that starts the responder as a subprocess passes its environment on,
so the responder writes to the suite's database. `new_database()` gives a
subprocess a database of its own, where a suite used to hand a server a
fresh store file.

With no Docker and no POL_TEST_DATABASE_URL there is no server:
fresh_database returns None and the suite reports SKIP, unless
POL_TEST_REQUIRE_DB=1 (CI), which makes that a failure.
"""
import atexit
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import docdb  # noqa: E402

_CORE = docdb.core_path()
if _CORE:
    _tools = os.path.normpath(os.path.join(_CORE, os.pardir, "tools"))
    if os.path.isfile(os.path.join(_tools, "pgtest.py")) and _tools not in sys.path:
        sys.path.append(_tools)

try:
    import pgtest  # noqa: E402
except ImportError:                                          # no core beside us
    pgtest = None


def require_db():
    return os.environ.get("POL_TEST_REQUIRE_DB", "") == "1"


def server_available():
    """True when pgtest can reach or start a server."""
    if pgtest is None:
        print("[docpg] OpenLobby's tools/pgtest.py was not found", file=sys.stderr)
        return False
    try:
        pgtest.server_url()
        return True
    except Exception as exc:                                 # noqa: BLE001
        print("[docpg] no test database server: %s" % exc, file=sys.stderr)
        return False


def _point_at(url):
    os.environ["POL_DATABASE_URL"] = url
    docdb.db.configure(None)
    docdb.forget_schema()


def fresh_database():
    """POL_DATABASE_URL for this process: the runner's, or a new empty
    database dropped at exit. None when no server is available."""
    if os.environ.get("DOC_TEST_DATABASE") == "1" and \
            os.environ.get("POL_DATABASE_URL"):
        return os.environ["POL_DATABASE_URL"]
    url = new_database()
    if url is not None:
        _point_at(url)
    else:
        os.environ.pop("POL_DATABASE_URL", None)
    return url


def new_database():
    """A new empty database, dropped at exit, WITHOUT pointing this process at
    it: the URL to hand a subprocess (env POL_DATABASE_URL). None when no
    server is available."""
    if not server_available():
        return None
    url = pgtest.create_database()
    atexit.register(_drop, url)
    return url


def use(url):
    """Point this process at `url` (a database new_database() made)."""
    _point_at(url)


def e2e_database(suite):
    """For a suite that starts the responder: a new empty database that this
    process AND every server it starts afterwards use (POL_DATABASE_URL in the
    environment the servers inherit). Exits the suite with skip_or_fail()
    when there is no server. Returns the URL."""
    url = new_database()
    if url is None:
        sys.exit(skip_or_fail(suite))
    _point_at(url)
    return url


def _drop(url):
    try:
        docdb.db.close()
    except Exception:                                        # noqa: BLE001
        pass
    try:
        pgtest.drop_database(url)
    except Exception:                                        # noqa: BLE001
        pass


def skip_or_fail(suite, what="PostgreSQL server"):
    """What a suite returns when there is no server: 0 (SKIP), or 1 when
    POL_TEST_REQUIRE_DB=1."""
    if require_db():
        print("[%s] FAIL: no %s and POL_TEST_REQUIRE_DB=1" % (suite, what))
        return 1
    print("[%s] SKIP: no %s (set POL_TEST_DATABASE_URL or run Docker)" % (suite, what))
    return 0


def need_database(suite):
    """fresh_database(), or exit the suite with skip_or_fail()."""
    if fresh_database() is None:
        sys.exit(skip_or_fail(suite))


def seed(name, doc, url=None):
    """Replace the store `name` with `doc` (its old JSON file's content), in
    this process's database or in `url`'s. What a suite did with json.dump
    before starting a server."""
    with _at(url):
        st = docdb.store(name)
        st.clear()
        if not st.save(doc):
            raise RuntimeError("seeding %s did not reach the database" % name)


def read(name, url=None):
    """The store `name` as its old JSON file would hold it. What a suite did
    with json.load after a server wrote the file."""
    with _at(url):
        return docdb.store(name).load()


def reset(name, url=None):
    """Empty the store `name`. What a suite did with os.remove on its file."""
    with _at(url):
        docdb.store(name).clear()


class _at:
    """Run a block against `url`, then go back to this process's database."""

    def __init__(self, url):
        self.url = url
        self.prev = None

    def __enter__(self):
        if self.url:
            self.prev = os.environ.get("POL_DATABASE_URL")
            _point_at(self.url)
        return self

    def __exit__(self, *exc):
        if self.url:
            if self.prev is None:
                os.environ.pop("POL_DATABASE_URL", None)
                docdb.db.configure(None)
                docdb.forget_schema()
            else:
                _point_at(self.prev)
        return False
