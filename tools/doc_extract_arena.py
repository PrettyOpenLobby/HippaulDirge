#!/usr/bin/env python3
"""Build the arena tables docudp.py reads from YOUR OWN copy of the game.

    python tools/doc_extract_arena.py GAME_DIR              # both tables, beside docudp.py
    python tools/doc_extract_arena.py GAME_DIR --out DIR    # somewhere else
    python tools/doc_extract_arena.py GAME_DIR --only spawns
    python tools/doc_extract_arena.py --selftest            # no game files needed

GAME_DIR is the game's installed data as copied off the PlayStation 2 hard
disk (the folder holding data/zone/), or that data/ or data/zone/ folder
itself, or an unpacked patch tree laid out the same way. Every arena has a
folder zNNN (201 and up) holding bzd.bin, the arena's level file. The
server was written against the files of retail patch 20060124_3, whose
arena files start with the version tag "bzd048"; files with another tag, or
with record sizes other than the ones below, are skipped with a message, so
an older install (the disc's own bzd045 files) or a prototype build gives
no table rather than a wrong one.

Two tables are written:

  doc_mission_spawns.json   {zone: {controller: {"count", "flags", "level",
                            "patrol", "spawn": [[x, y, z], ...]}}}
      Every arena's NPC controllers with their enemy spawn nodes. The mission
      battles place their enemies at these nodes.

  doc_item_generators.json  {zone: {"sets": {i: [[item, qty, weight], ...]},
                            "situations": {id: [[x, y, z, set], ...]}}}
      Every arena's item sets, and for each situation (controller) the item
      generator nodes it enables with the set each one draws from.

The arena file (all little-endian). A table directory starts at 0x20 with
a u32 table count; table j's u32 (offset, count, record size) sit at
0x34 + 16*j. The tables read here:

  15  placement nodes, 80 B: a 4x4 float matrix whose position row (x, y, z)
      is at +48; +64 u8 node type (3 = item generator); +72 u32 link (for an
      item generator, the index of its item set in table 22)
  22  item sets, 104 B: an 8-byte header, then 8 entries of
      {u32 item id (0xFFFFFFFF = empty), u32 quantity, u32 weight}
  28  controllers, 48 B: +4 u16 controller id, +6 u16 index, +8 u16 spawn
      count, +10 u16 patrol-node count, +12 u16 level, +14 u16 flags, +16/+20/
      +24 u32 a, b, c: indices into table 29. [a, b) lists the enemy spawn
      nodes, [b, c) the controller's other nodes (item generators among them)
  29  u16 node indices into table 15

Nothing here is game data: the tables are read from the files you point it
at, and the output stays on your machine (.gitignore keeps it out of the
repository).
"""
import argparse
import glob
import json
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

VERSION_TAG = b"bzd048"
DIR_COUNT = 0x20             # u32 number of tables
DIR_BASE = 0x34              # table j: (offset, count, record size) at DIR_BASE + 16*j
T_NODES, T_SETS, T_CTL, T_LIST = 15, 22, 28, 29
NODE_SIZE, SET_SIZE, CTL_SIZE, LIST_SIZE = 80, 104, 48, 2
NODE_POS = 48                # 3 floats
NODE_TYPE = 64               # u8
NODE_LINK = 72               # u32
NODE_ITEM_GEN = 3
SET_ENTRIES, SET_HEAD, SET_ENTRY = 8, 8, 12
EMPTY_ITEM = 0xFFFFFFFF
CTL_FIELDS = 4               # 6 x u16: id, index, spawn count, patrol, level, flags
CTL_LISTS = 16               # 3 x u32: a, b, c

SPAWNS_NAME = "doc_mission_spawns.json"
GENERATORS_NAME = "doc_item_generators.json"


class LayoutError(ValueError):
    """The file is not an arena file this tool knows the layout of."""


def table(buf, j, recsize):
    """(offset, count) of table j, after checking it lies inside the file and
    has the record size this tool reads."""
    if len(buf) < DIR_BASE + 16 * (T_LIST + 1):
        raise LayoutError("too short for the table directory")
    ntab = struct.unpack_from("<I", buf, DIR_COUNT)[0]
    if j >= ntab:
        raise LayoutError("no table %d (the file has %d)" % (j, ntab))
    off, count, size = struct.unpack_from("<3I", buf, DIR_BASE + 16 * j)
    if count and size != recsize:
        raise LayoutError("table %d has %d-byte records, expected %d"
                          % (j, size, recsize))
    if count and off + count * recsize > len(buf):
        raise LayoutError("table %d runs past the end of the file" % j)
    return off, count


def check_arena(buf):
    if not buf.startswith(VERSION_TAG):
        raise LayoutError("version tag %r, expected %r"
                          % (bytes(buf[:6]), VERSION_TAG))
    for j, size in ((T_NODES, NODE_SIZE), (T_SETS, SET_SIZE),
                    (T_CTL, CTL_SIZE), (T_LIST, LIST_SIZE)):
        table(buf, j, size)


def node_lists(buf):
    off, count = table(buf, T_LIST, LIST_SIZE)
    return struct.unpack_from("<%dH" % count, buf, off) if count else ()


def node_pos(buf, off, i):
    x, y, z = struct.unpack_from("<3f", buf, off + NODE_SIZE * i + NODE_POS)
    return [round(x, 1), round(y, 1), round(z, 1)]


def controllers(buf):
    """{controller id: record} for the mission spawn table."""
    o_ctl, n_ctl = table(buf, T_CTL, CTL_SIZE)
    o_nodes, n_nodes = table(buf, T_NODES, NODE_SIZE)
    lists = node_lists(buf)
    out = {}
    for i in range(n_ctl):
        rec = o_ctl + CTL_SIZE * i
        cid, _idx, cnt, npatrol, lvl, flags = struct.unpack_from(
            "<6H", buf, rec + CTL_FIELDS)
        a, b, c = struct.unpack_from("<3I", buf, rec + CTL_LISTS)
        spawn = []
        if 0 <= a <= b <= len(lists):
            spawn = [node_pos(buf, o_nodes, n) for n in lists[a:b] if n < n_nodes]
        out[str(cid)] = {"count": cnt, "spawn": spawn, "patrol": npatrol,
                         "level": lvl, "flags": flags}
    return out


def item_sets(buf):
    """{set index (str): [[item id "0x%08X", qty, weight], ...]}"""
    off, count = table(buf, T_SETS, SET_SIZE)
    out = {}
    for i in range(count):
        rec = off + SET_SIZE * i + SET_HEAD
        ents = []
        for k in range(SET_ENTRIES):
            iid, qty, weight = struct.unpack_from("<3I", buf, rec + SET_ENTRY * k)
            if iid != EMPTY_ITEM:
                ents.append(["0x%08X" % iid, qty, weight])
        out[str(i)] = ents
    return out


def generators(buf):
    """{"sets": ..., "situations": {id: [[x, y, z, set], ...]}} for one arena.
    A situation lists the item generators among its [b, c) nodes, in list
    order; situations with none are left out."""
    o_nodes, n_nodes = table(buf, T_NODES, NODE_SIZE)
    o_ctl, n_ctl = table(buf, T_CTL, CTL_SIZE)
    lists = node_lists(buf)
    gens = {}
    for i in range(n_nodes):
        rec = o_nodes + NODE_SIZE * i
        if buf[rec + NODE_TYPE] == NODE_ITEM_GEN:
            link = struct.unpack_from("<I", buf, rec + NODE_LINK)[0]
            gens[i] = node_pos(buf, o_nodes, i) + [link]
    sits = {}
    for i in range(n_ctl):
        rec = o_ctl + CTL_SIZE * i
        cid = struct.unpack_from("<H", buf, rec + CTL_FIELDS)[0]
        _a, b, c = struct.unpack_from("<3I", buf, rec + CTL_LISTS)
        nodes = ([n for n in lists[b:c] if n < n_nodes]
                 if 0 <= b <= c <= len(lists) else [])
        sits[cid] = [gens[n] for n in nodes if n in gens]
    return {"sets": item_sets(buf),
            "situations": {str(k): v for k, v in sits.items() if v}}


def zone_dir(game_dir):
    """The folder holding the zNNN arena folders, found from GAME_DIR."""
    for sub in ("", "zone", os.path.join("data", "zone")):
        d = os.path.join(game_dir, sub)
        if glob.glob(os.path.join(d, "z2*", "bzd.bin")):
            return d
    return None


def arenas(zdir, log=print):
    """[(zone number as str, file bytes)] for every arena file with the
    layout this tool reads, in folder order; the rest are reported."""
    out = []
    for p in sorted(glob.glob(os.path.join(zdir, "z2*", "bzd.bin"))):
        name = os.path.basename(os.path.dirname(p))
        with open(p, "rb") as f:
            buf = f.read()
        try:
            check_arena(buf)
        except LayoutError as ex:
            log("  skip %s: %s" % (name, ex))
            continue
        out.append((name[1:], buf))
    return out


def write_spawns(arena_files, path):
    zones = {z: controllers(buf) for z, buf in arena_files}
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(zones, f, indent=0, sort_keys=True)
    return zones


def write_generators(arena_files, path):
    zones = {z: generators(buf) for z, buf in arena_files}
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(zones, f, separators=(",", ":"))
    return zones


def extract(game_dir, out_dir, only=("spawns", "generators"), log=print):
    zdir = zone_dir(game_dir)
    if zdir is None:
        log("no zNNN/bzd.bin arena files under %s" % game_dir)
        return 1
    files = arenas(zdir, log)
    if not files:
        log("none of the arena files under %s has the %s layout"
            % (zdir, VERSION_TAG.decode()))
        return 1
    os.makedirs(out_dir, exist_ok=True)
    if "spawns" in only:
        path = os.path.join(out_dir, SPAWNS_NAME)
        zones = write_spawns(files, path)
        n = sum(len(v) for v in zones.values())
        m = sum(1 for v in zones.values() for k, c in v.items()
                if 3000 <= int(k) < 4000 and c["count"])
        log("%s: %d zones, %d controllers, %d mission controllers with "
            "spawns" % (path, len(zones), n, m))
    if "generators" in only:
        path = os.path.join(out_dir, GENERATORS_NAME)
        zones = write_generators(files, path)
        g = sum(len(s) for v in zones.values() for s in v["situations"].values())
        log("%s: %d zones, %d generator placements over every situation"
            % (path, len(zones), g))
    return 0


# ---------------------------------------------------------------- self-test

def synthetic_arena(tag=VERSION_TAG, ctl_size=CTL_SIZE):
    """A minimal arena file: 3 nodes (two spawns, one item generator), one
    item set, two controllers, and the node list they index. Every value is
    made up for the test."""
    ntab = 35
    head = bytearray(DIR_BASE + 16 * ntab)
    head[:len(tag)] = tag
    struct.pack_into("<I", head, DIR_COUNT, ntab)
    nodes = bytearray()
    for i, (pos, typ, link) in enumerate((((1.25, 2.0, -3.04), 0, 0),
                                          ((10.0, 0.0, 20.0), 0, 0),
                                          ((5.0, -1.0, 7.5), NODE_ITEM_GEN, 0))):
        rec = bytearray(NODE_SIZE)
        struct.pack_into("<3f", rec, NODE_POS, *pos)
        rec[NODE_TYPE] = typ
        struct.pack_into("<I", rec, NODE_LINK, link)
        nodes += rec
    sets = bytearray(SET_SIZE)
    for k in range(SET_ENTRIES):
        struct.pack_into("<3I", sets, SET_HEAD + SET_ENTRY * k, EMPTY_ITEM, 0, 0)
    struct.pack_into("<3I", sets, SET_HEAD, 0x11223344, 5, 60)
    struct.pack_into("<3I", sets, SET_HEAD + SET_ENTRY, 0x55667788, 1, 40)
    ctls = bytearray()
    # controller 3000: spawns at nodes 0, 1 (list [0, 2)), generator node 2
    # in [2, 3); controller 1000: no spawn, an out-of-range list
    for cid, cnt, a, b, c in ((3000, 2, 0, 2, 3), (1000, 0, 9, 9, 99)):
        rec = bytearray(ctl_size)
        struct.pack_into("<6H", rec, CTL_FIELDS, cid, 0, cnt, 4, 30, 266)
        struct.pack_into("<3I", rec, CTL_LISTS, a, b, c)
        ctls += rec
    lists = struct.pack("<3H", 0, 1, 2)
    body = bytearray()
    where = {}
    for j, blob, size, count in ((T_NODES, nodes, NODE_SIZE, 3),
                                 (T_SETS, sets, SET_SIZE, 1),
                                 (T_CTL, ctls, ctl_size, 2),
                                 (T_LIST, lists, LIST_SIZE, 3)):
        where[j] = (len(head) + len(body), count, size)
        body += blob
    for j, (off, count, size) in where.items():
        struct.pack_into("<3I", head, DIR_BASE + 16 * j, off, count, size)
    return bytes(head + body)


def selftest():
    fails = []

    def check(name, cond, detail=""):
        print("  %s %s%s" % ("ok  " if cond else "FAIL", name,
                             ("  " + detail) if detail else ""))
        if not cond:
            fails.append(name)

    with tempfile.TemporaryDirectory() as tmp:
        game = os.path.join(tmp, "game")
        for zone, blob in (("z201", synthetic_arena()),
                           ("z202", synthetic_arena(tag=b"bzd045")),
                           ("z203", synthetic_arena(ctl_size=1072))):
            d = os.path.join(game, "data", "zone", zone)
            os.makedirs(d)
            with open(os.path.join(d, "bzd.bin"), "wb") as f:
                f.write(blob)
        out = os.path.join(tmp, "out")
        lines = []
        rc = extract(game, out, log=lines.append)
        check("the extraction ran", rc == 0, "; ".join(lines))
        check("an older version tag is skipped",
              any("skip z202" in s and "bzd045" in s for s in lines))
        check("a controller table with another record size is skipped",
              any("skip z203" in s and "1072" in s for s in lines))
        with open(os.path.join(out, SPAWNS_NAME), encoding="utf-8") as f:
            sp = json.load(f)
        check("only the good arena is in the spawn table", list(sp) == ["201"],
              "%r" % list(sp))
        c = sp.get("201", {}).get("3000", {})
        check("controller 3000: count, patrol, level, flags",
              (c.get("count"), c.get("patrol"), c.get("level"), c.get("flags"))
              == (2, 4, 30, 266), "%r" % c)
        check("controller 3000: its two spawn nodes, rounded to 0.1",
              c.get("spawn") == [[1.2, 2.0, -3.0], [10.0, 0.0, 20.0]],
              "%r" % c.get("spawn"))
        check("an out-of-range node list gives no spawn",
              sp.get("201", {}).get("1000", {}).get("spawn") == [])
        with open(os.path.join(out, GENERATORS_NAME), encoding="utf-8") as f:
            gen = json.load(f)
        g = gen.get("201", {})
        check("the item set, empty entries left out",
              g.get("sets") == {"0": [["0x11223344", 5, 60],
                                      ["0x55667788", 1, 40]]}, "%r" % g.get("sets"))
        check("situation 3000 enables the generator node with its set",
              g.get("situations") == {"3000": [[5.0, -1.0, 7.5, 0]]},
              "%r" % g.get("situations"))
        lines = []
        rc = extract(os.path.join(tmp, "nothing"), out, log=lines.append)
        check("a folder without arena files is an error", rc == 1)
    print("%d check(s) failed" % len(fails) if fails else "ALL PASS")
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("game_dir", nargs="?",
                    help="your game data: the folder holding data/zone/")
    ap.add_argument("--out", default=HERE,
                    help="where to write the tables (default: beside docudp.py)")
    ap.add_argument("--only", choices=("spawns", "generators"),
                    help="write one table only")
    ap.add_argument("--selftest", action="store_true",
                    help="check the reader on a synthetic arena file")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.game_dir:
        ap.error("GAME_DIR is required")
    only = (a.only,) if a.only else ("spawns", "generators")
    return extract(a.game_dir, a.out, only)


if __name__ == "__main__":
    sys.exit(main())
