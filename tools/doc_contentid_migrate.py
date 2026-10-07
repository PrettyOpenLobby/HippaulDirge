#!/usr/bin/env python3
"""Give existing DoC characters their POL Content ID as their character id.

    python doc_contentid_migrate.py                       # dry run: print the plan
    python doc_contentid_migrate.py --apply --i-stopped-docudp --map-out MAP.json
    python doc_contentid_migrate.py --rollback MAP.json --i-stopped-docudp
    python doc_contentid_migrate.py --selftest            # needs a test database

Why (2026-10-05, static RE of the retail client, scratchpad re-loadout/): the
client saves each character's gun loadout to the memory card and, at the next
boot, deletes every saved slot whose owner is not one of the handle's DoC
Content IDs (service code 10). docudp handed out ids of its own
(charrecords.chara_id_for), so no loadout ever survived a power cycle.

What it does, per `member:N` roster in doc_character, characters in slot order:
the i-th character without a Content ID takes the i-th of the member's active
code-10 Content IDs that no character holds yet ("cid" in its roster element,
which charrecords.chara_id_of then serves). Every store row keyed by the old
id (`member:N/0x<old>`) moves to `member:N/0x<cid>`, every exact string
`member:N/0x<old>` inside a stored value is renamed (weekly medals, closed
weeks, units), and a career / ranking row's "id" field follows. `addr:`
rosters and characters with no free Content ID keep their derived id.

docudp keeps every store in memory and writes it back on its next save, so
this must run with docudp STOPPED (and pol-git-sync.timer stopped, so nothing
restarts it); --apply and --rollback refuse without --i-stopped-docudp. The
whole change is one transaction; --map-out records every pair and a pre-image
of each table, and --rollback reverses the pairs (play since the migration is
kept).
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import docdb  # noqa: E402
from docworld import charrecords  # noqa: E402
import doc_charastore  # noqa: E402

#: every table holding a per-character key or id; doc_ip_member is per member
TABLES = ("doc_character", "doc_wallet", "doc_gear", "doc_playtime",
          "doc_career", "doc_week", "doc_week_closed", "doc_rank_char",
          "doc_rank_unit", "doc_unit", "doc_unit_enlist")
#: tables whose row "id" field is the character id
ID_FIELD_TABLES = ("doc_career", "doc_rank_char")
LOCK = "hippauldirge.contentid"


def char_key(member_key, cid):
    return "%s/0x%08x" % (member_key, cid & 0x3FFFFFFF)


def db_ids_for(member):
    """The member's active DoC Content IDs, in POL order (the live lookup)."""
    acc = docdb.accounts()
    conn = acc.connect()
    try:
        return acc.member_content_id_list(conn, member,
                                          doc_charastore.DOC_CONTENT_CODE,
                                          active_only=True)
    finally:
        conn.close()


def plan(rosters, ids_for, base=0x1000):
    """[(member key, slot, name, old id, cid)] for every character that gets
    a Content ID now, plus [(member key, slot, name, why)] for those that do
    not. `rosters` = doc_character's rows; `ids_for(member int)` -> ids."""
    held = {doc_charastore.content_id_of(c) for cs in rosters.values() for c in (cs or ())}
    held.discard(0)
    pairs, skipped = [], []
    for key in sorted(rosters):
        chars = sorted((c for c in rosters[key] or () if isinstance(c, dict)),
                       key=lambda c: c.get("slot", 0))
        if not (key.startswith("member:") and key[7:].isdigit()):
            skipped += [(key, c.get("slot"), c.get("name"), "not a member roster")
                        for c in chars]
            continue
        free = []
        for raw in ids_for(int(key[7:])) or ():
            try:
                v = int(raw)
            except (TypeError, ValueError):
                continue
            if 0 < v < doc_charastore.CONTENT_ID_MAX and v not in held:
                free.append(v)
        for c in chars:
            if doc_charastore.content_id_of(c):
                continue
            slot = c.get("slot", 0)
            if not free:
                skipped.append((key, slot, c.get("name"), "no free Content ID"))
                continue
            cid = free.pop(0)
            held.add(cid)
            pairs.append((key, slot, c.get("name"),
                          charrecords.chara_id_for(base, 0, key, slot), cid))
    return pairs, skipped


def _rename(value, names):
    """`value` with every dict key / string equal to an old key renamed."""
    if isinstance(value, str):
        return names.get(value, value)
    if isinstance(value, list):
        return [_rename(v, names) for v in value]
    if isinstance(value, dict):
        return {names.get(k, k): _rename(v, names) for k, v in value.items()}
    return value


def transform(data, pairs, reverse=False):
    """{table: rows} -> {table: rows} with `pairs` applied (or undone)."""
    names, ids, cids = {}, {}, {}
    for key, slot, _name, old, cid in pairs:
        a, b = (char_key(key, cid), char_key(key, old)) if reverse else \
               (char_key(key, old), char_key(key, cid))
        names[a] = b
        ids[(cid if reverse else old)] = (old if reverse else cid)
        cids[(key, slot)] = cid
    out = {}
    for table, rows in data.items():
        new = {}
        for k, v in rows.items():
            if table == "doc_character":
                v = [dict(c) for c in (v or ())]
                for c in v:
                    if (k, c.get("slot", 0)) in cids:
                        if reverse:
                            c.pop("cid", None)
                        else:
                            c["cid"] = cids[(k, c.get("slot", 0))]
            else:
                v = _rename(v, names)
                if table in ID_FIELD_TABLES and isinstance(v, dict) \
                        and isinstance(v.get("id"), int) and v["id"] in ids:
                    v = dict(v, id=ids[v["id"]])
            new[names.get(k, k)] = v
        out[table] = new
    return out


def preflight(data, pairs, reverse=False):
    """Problems that stop the run: a target key already taken."""
    out = []
    for key, _slot, _name, old, cid in pairs:
        src, dst = (char_key(key, cid), char_key(key, old)) if reverse else \
                   (char_key(key, old), char_key(key, cid))
        for table, rows in data.items():
            if table != "doc_character" and dst in rows:
                out.append("%s already holds %s (would overwrite on %s)"
                           % (table, dst, src))
    return out


def load_all():
    tables = {t: docdb.Table(t) for t in TABLES}
    return tables, {t: tab.load() for t, tab in tables.items()}


def write_all(tables, new):
    """Every table's changes in ONE transaction."""
    plans = {t: tables[t]._plan(new[t]) for t in tables}
    docdb.ensure_schema()
    with docdb.db.transaction(lock=LOCK) as conn:
        for t, (_n, changed, gone) in plans.items():
            tables[t]._apply(conn, changed, gone)
    return {t: (len(p[1]), len(p[2])) for t, p in plans.items()}


def run(mode, ids_for=db_ids_for, base=0x1000, map_out=None, map_in=None,
        out=print):
    """mode: 'dry' / 'apply' / 'rollback'. Returns 0 on success."""
    tables, data = load_all()
    reverse = mode == "rollback"
    if reverse:
        with open(map_in, encoding="utf-8") as f:
            pairs = [tuple(p) for p in json.load(f)["pairs"]]
        skipped = []
    else:
        pairs, skipped = plan(data["doc_character"], ids_for, base)
    for key, slot, name, old, cid in pairs:
        out("  %s slot %s %-15s 0x%08x -> %d (0x%08x)%s"
            % (key, slot, name or "?", old, cid, cid, "  [UNDO]" if reverse else ""))
    for key, slot, name, why in skipped:
        out("  %s slot %s %-15s keeps its derived id: %s" % (key, slot, name or "?", why))
    out("%d character(s) to %s, %d keep their id"
        % (len(pairs), "restore" if reverse else "move", len(skipped)))
    bad = preflight(data, pairs, reverse)
    for b in bad:
        out("  REFUSED: " + b)
    if bad:
        return 2
    new = transform(data, pairs, reverse)
    moved = {t: sum(1 for k in new[t] if k not in data[t]) for t in TABLES}
    for t in TABLES:
        if len(new[t]) != len(data[t]):
            out("  REFUSED: %s would go from %d to %d rows" % (t, len(data[t]), len(new[t])))
            return 2
    out("rows re-keyed per table: %s" % ", ".join("%s %d" % (t, n) for t, n in moved.items() if n))
    if mode == "dry" or not pairs:
        return 0
    if map_out and not reverse:
        with open(map_out, "w", encoding="utf-8") as f:
            json.dump({"made": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "base": base, "pairs": [list(p) for p in pairs],
                       "pre": data}, f)
        out("map + pre-image: %s" % map_out)
    counts = write_all(tables, new)
    _t2, after = load_all()
    for t in TABLES:
        if after[t] != new[t]:
            out("  VERIFY FAILED on %s (the transaction committed; use --rollback)" % t)
            return 3
    out("written (changed, removed) per table: %s" % counts)
    return 0


def selftest():
    import docpg
    docpg.need_database("doc_contentid_migrate")
    fails = []

    def check(name, cond, detail=""):
        print("  %s %s%s" % ("ok  " if cond else "FAIL", name,
                             ("  " + str(detail)) if detail else ""))
        if not cond:
            fails.append(name)

    m15 = charrecords.chara_id_for(0x1000, 0, "member:15", 0)
    m15b = charrecords.chara_id_for(0x1000, 0, "member:15", 1)
    m20 = charrecords.chara_id_for(0x1000, 0, "member:20", 0)
    k15, k15b, k20 = (char_key("member:15", m15), char_key("member:15", m15b),
                      char_key("member:20", m20))
    seed = {
        "doc_character": {"member:15": [{"name": "Malk", "slot": 0},
                                        {"name": "Two", "slot": 1}],
                          "member:20": [{"name": "Nina", "slot": 0}],
                          "addr:1.2.3.4": [{"name": "Lone", "slot": 0}]},
        "doc_wallet": {k15: {"gil": 500}, k15b: {"gil": 7}, k20: {"gil": 9},
                       "member:15": {"gil": 1}, "member:3/0x000410d0": {"gil": 2}},
        "doc_gear": {k15: {"suit": 1}},
        "doc_playtime": {k15: {"s": 60}},
        "doc_career": {k15: {"id": m15, "rp": 40}, k20: {"id": m20, "rp": 3}},
        "doc_week": {"2026-09-28": {k15: {"kills": 4}, k20: {"kills": 1}}},
        "doc_week_closed": {"2026-09-21": {"awards": [{"key": k15, "medal": 18}]}},
        "doc_rank_char": {k15: {"id": m15, "name": "Malk"}},
        "doc_rank_unit": {},
        "doc_unit": {"u1": {"registrant": k15, "members": [k15, k20]}},
        "doc_unit_enlist": {k15: "u1"},
    }
    tabs = {t: docdb.Table(t) for t in TABLES}
    for t, rows in seed.items():
        tabs[t].clear()
        tabs[t].save(rows)
    ids = {15: ["30000057"], 20: ["30000058"]}
    lines = []
    rc = run("dry", ids_for=lambda m: ids.get(m, []), out=lines.append)
    _t, after = load_all()
    check("dry run: rc 0, plans 2 moves, writes nothing", rc == 0
          and any("2 character(s) to move" in s for s in lines) and after == seed,
          "; ".join(lines[-3:]))
    import tempfile
    mp = os.path.join(tempfile.mkdtemp(), "map.json")
    rc = run("apply", ids_for=lambda m: ids.get(m, []), map_out=mp, out=lines.append)
    _t, a = load_all()
    n15, n20 = char_key("member:15", 30000057), char_key("member:20", 30000058)
    check("apply: rc 0, slot-0 characters carry their cid, slot 1 (no id left) "
          "and the addr: roster keep theirs",
          rc == 0 and a["doc_character"]["member:15"][0].get("cid") == 30000057
          and "cid" not in a["doc_character"]["member:15"][1]
          and a["doc_character"]["member:20"][0].get("cid") == 30000058
          and "cid" not in a["doc_character"]["addr:1.2.3.4"][0], rc)
    check("apply: keys moved, inner ids and keys renamed",
          a["doc_wallet"].get(n15) == {"gil": 500} and k15 not in a["doc_wallet"]
          and a["doc_career"][n15]["id"] == 30000057
          and set(a["doc_week"]["2026-09-28"]) == {n15, n20}
          and a["doc_week_closed"]["2026-09-21"]["awards"][0]["key"] == n15
          and a["doc_unit"]["u1"] == {"registrant": n15, "members": [n15, n20]}
          and a["doc_unit_enlist"] == {n15: "u1"} and a["doc_rank_char"][n15]["id"] == 30000057)
    check("TWIN: the slot-1 character, the bare member wallet and a stray crossover "
          "row are untouched",
          a["doc_wallet"].get(k15b) == {"gil": 7} and a["doc_wallet"]["member:15"] == {"gil": 1}
          and a["doc_wallet"]["member:3/0x000410d0"] == {"gil": 2})
    lines2 = []
    rc2 = run("apply", ids_for=lambda m: ids.get(m, []), out=lines2.append)
    _t, a2 = load_all()
    check("a second apply is a no-op", rc2 == 0 and a2 == a
          and any("0 character(s) to move" in s for s in lines2))
    rc3 = run("rollback", map_in=mp, out=lines.append)
    _t, r = load_all()
    check("rollback restores every table exactly", rc3 == 0 and r == seed,
          [t for t in TABLES if r[t] != seed[t]])
    tabs["doc_wallet"].save(dict(seed["doc_wallet"], **{n15: {"gil": 1}}))
    lines3 = []
    rc4 = run("apply", ids_for=lambda m: ids.get(m, []), out=lines3.append)
    check("REFUSED when a target key already exists (nothing written)",
          rc4 == 2 and any("REFUSED" in s for s in lines3)
          and load_all()[1]["doc_character"] == seed["doc_character"])
    for t in TABLES:
        tabs[t].clear()
    print("ALL PASS" if not fails else "%d FAILED: %s" % (len(fails), fails))
    return 1 if fails else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--rollback", metavar="MAP.json")
    ap.add_argument("--map-out", metavar="MAP.json")
    ap.add_argument("--i-stopped-docudp", action="store_true",
                    help="confirm docudp is stopped (it would write the old keys back)")
    ap.add_argument("--chara-id-base", type=lambda x: int(x, 0), default=0x1000)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if (a.apply or a.rollback) and not a.i_stopped_docudp:
        ap.error("--apply / --rollback need --i-stopped-docudp (stop docudp and "
                 "pol-git-sync.timer first)")
    if a.apply and not a.map_out:
        ap.error("--apply needs --map-out (the rollback map)")
    mode = "rollback" if a.rollback else ("apply" if a.apply else "dry")
    return run(mode, base=a.chara_id_base, map_out=a.map_out, map_in=a.rollback)


if __name__ == "__main__":
    sys.exit(main())
