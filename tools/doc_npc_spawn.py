"""doc_npc_spawn -- the DoC lobby NPCs, pushed the way the game server did it.

2026-09-13 (static, read off the client's own NPC path). Online, the
client SKIPS its own bzd chara loop (0x004a39d0 is gated on the online bit
[0x00612430] & 1), so the NPCs placed in zone/z217/bzd.bin never appear unless
the server announces them. The announcement is game-server notify kind 15,
"Add Npc" (0x00bc3248): u32 count at body[16], then 24-byte entries from
body[20]:

    +0   u32 id        registered as "NPC%x"; the client's id lookup reads the
                       kelsvc +288 table only for ids with bit 0x40000000
    +4   u32 HP        "Npc Hp %d" -> unit +44 / +692
    +8   u16 type      -> kelsvc +288 record +26 and unit +686 (its model
                       reader is NOT found -- hence --npc-spawn-type)
    +10  s16 x, +12 y, +14 z      world units, unscaled (cvt.s.w)
    +16  s16 dx, +18 dy, +20 dz   direction x 0.001 (0x0058b290)
    +22  u16                      unread

Each entry also spawns an avatar unit (0x00bdcc58, as a remote player does);
with the controller id 0 no client controls it. Proven offline by
an offline run of the client's own code (doc_npc_spawn_proof) (registration + unit spawn); NOT proven live,
and NOT proven to draw the bzd model.
"""
import json
import os
import struct

KIND_ADD_NPC = 15
KIND_EXTINCT = 22
ID_BASE = 0x40000000
ENTRY_LEN = 24
PER_MSG = 8               # 8 x 24 B per message keeps a datagram well under 1 KB
DEFAULT_HP = 100
TYPE_MODES = ("idx", "num", "chr")

# THE PLACEMENT TABLE IS NOT IN THIS FILE. It is the lobby's own NPC list:
# (lnpc number, record index in the zone's character table, type, x, y, z,
# dir x, dir z, stand motion), one row per standing NPC, read out of the
# game's own zone data (the lobby zone's character table as the game loads
# it). That is Square Enix's level data, so it ships with nothing here: it is
# read from doc_npc_table.json beside this module, {"npcs": [[...], ...]},
# when that file exists, and --npc-spawn has nothing to push without it. The
# private deployment's table held 33 standing NPCs (the 7 parked at y ~31000
# and record 0, the player template, left out).
LOBBY_NPCS = []
TABLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "doc_npc_table.json")


def load_table(path=TABLE_PATH):
    """The placement rows from `path`, or [] when there is no such file."""
    try:
        with open(path, encoding="utf-8") as fh:
            rows = json.load(fh).get("npcs") or []
    except (OSError, ValueError):
        return []
    return [tuple(r) for r in rows if len(r) == 9]


LOBBY_NPCS = load_table()


def _s16(v):
    return max(-32768, min(32767, int(round(v))))


def npc_id(num):
    return ID_BASE | (num & 0xFFFF)


def entry(nid, typ, pos, direction=(0.0, 0.0, 0.0), hp=DEFAULT_HP):
    """One 24-byte kind-15 entry."""
    x, y, z = (_s16(v) for v in pos)
    dx, dy, dz = (_s16(v * 1000.0) for v in direction)
    return struct.pack("<IIH3h3hH", nid & 0xFFFFFFFF, hp & 0xFFFFFFFF,
                       typ & 0xFFFF, x, y, z, dx, dy, dz, 0)


def parse_only(spec):
    """'4,31,32,33' -> {4, 31, 32, 33}; '' -> None (all)."""
    nums = {int(t, 0) for t in (spec or "").replace(" ", ",").split(",") if t}
    return nums or None


def select(only=None):
    return [n for n in LOBBY_NPCS if only is None or n[0] in only]


def type_of(npc, mode="idx"):
    if mode not in TYPE_MODES:
        raise ValueError("type mode %r not in %s" % (mode, TYPE_MODES))
    return {"idx": npc[1], "num": npc[0], "chr": npc[2]}[mode]


def payloads(only=None, mode="idx", hp=DEFAULT_HP, per_msg=PER_MSG):
    """kind-15 payloads (build_gs_notify puts them at body[16]): u32 count +
    entries, at most per_msg entries each."""
    npcs = select(only)
    out = []
    for i in range(0, len(npcs), per_msg):
        chunk = npcs[i:i + per_msg]
        body = struct.pack("<I", len(chunk))
        for n in chunk:
            body += entry(npc_id(n[0]), type_of(n, mode), n[3:6],
                          (n[6], 0.0, n[7]), hp)
        out.append(body)
    return out


NAME_MSGID_BASE = 0xd400   # online string group 53: the lobby NPC names
NAME_MODES = ("bzd", "msgid", "index", "none")


def name_field(num, mode="bzd", bzd=0):
    """wire+6 of an NPC's type-125 record (-> +288 rec+4, profile+68).

    KEY: 09-13 (static, modelled against lobby RAM from two live savestates): the
    lobby name plate (0x00ace9e0) does NOT read this as a msgid. It does
        obj  = 0x0049b310(profile+68)      # bzd TABLE 0 record; idx >= 41 -> 0
        name = 0x0058f388(0xd3ff + obj+154)  # +154 = the lnpc number
    (base 0xd3ff because profile+62 & 0x20, i.e. rec+32 = 1). So wire+6 must be
    the bzd RECORD INDEX -- the same value as wire+4. The msgid we sent first
    (0xd400 + n - 1) clamped to record 0 (p_Vin, +154 = 0) -> 0xd3ff -> "!!na!!"
    for every NPC. 'msgid'/'index' are kept only to reproduce that."""
    if mode == "none":
        return 0
    if mode == "bzd":
        return bzd
    return (NAME_MSGID_BASE + num - 1) if mode == "msgid" else (num - 1)


def wu_records(only=None, mode="idx", name="bzd"):
    """The lobby NPCs as TYPE-125 world-update records (docudp
    build_world_update keys) -- the path retail used (sec 4gs addendum 5).

    0x00bd2358: an id whose top nibble is 4 is looked up in kelsvc +288; an
    unknown one is INSERTED (rec+6 = wire+4 u16, rec+32 = 1) and a local
    entity message posted. The lookup then reads profile+62 = 0x28 and
    profile+70 = wire+4, and the online entity pump builds the chara from bzd
    record profile+70 (0x00beb418, flags 0x80|0x100). So wire+4 = the bzd
    record index (1..40 = lnpc_04..43 in z217); no game-server channel."""
    out = []
    for n in select(only):
        t = type_of(n, mode)
        out.append(dict(id=npc_id(n[0]), x=n[3], y=n[4], z=n[5],
                        dx=n[6], dy=0.0, dz=n[7], b4=t & 0xFF, b5=(t >> 8) & 0xFF,
                        h6=name_field(n[0], name, bzd=n[1])))
    return out


ARENA_ID_BASE = ID_BASE | 0x100   # arena test NPCs never collide with lobby ids
ARENA_TYPES_DEFAULT = "1,2,3,4,14,15,45,52"


def parse_types(spec):
    """'1,2,45' -> [1, 2, 45] (order kept, one NPC per entry)."""
    return [int(t, 0) for t in (spec or "").replace(" ", ",").split(",") if t]


def ring_payloads(center, types, radius=150.0, hp=DEFAULT_HP, per_msg=PER_MSG):
    """One NPC per `types` entry, evenly on a circle of `radius` around
    `center` (x, y, z) in the x/z plane, each facing the centre. For the arena
    test (sec 4gs addendum 4): the channel is already open there, so this asks
    only whether kind 15 draws anything, and which type value draws what."""
    import math
    n = max(1, len(types))
    ents = []
    for i, typ in enumerate(types):
        ang = 2.0 * math.pi * i / n
        ca, sa = math.cos(ang), math.sin(ang)
        pos = (center[0] + radius * ca, center[1], center[2] + radius * sa)
        ents.append(entry(ARENA_ID_BASE + i, typ, pos, (-ca, 0.0, -sa), hp))
    out = []
    for i in range(0, len(ents), per_msg):
        chunk = ents[i:i + per_msg]
        out.append(struct.pack("<I", len(chunk)) + b"".join(chunk))
    return out


def _selftest():
    fails = []

    def check(cond, what):
        print("  %s  %s" % ("PASS" if cond else "FAIL", what))
        if not cond:
            fails.append(what)

    e = entry(npc_id(7), 4, (1164.74, -0.2, -17.4), (-0.979, 0.0, 0.205), 100)
    check(len(e) == ENTRY_LEN, "an entry is 24 bytes")
    f = struct.unpack("<IIH3h3hH", e)
    check(f[0] == 0x40000007, "+0 id carries bit 0x40000000 (the +288 lookup)")
    check(f[1] == 100 and f[2] == 4, "+4 HP, +8 type")
    check(f[3:6] == (1165, 0, -17), "+10/12/14 position in whole world units")
    check(f[6:9] == (-979, 0, 205), "+16/18/20 direction x 1000")
    if not LOBBY_NPCS:
        print("  SKIP  no doc_npc_table.json beside this module: the placement "
              "checks need your own table (see the README)")
        print("ALL PASS" if not fails else "%d FAIL" % len(fails))
        return 1 if fails else 0
    check(len(LOBBY_NPCS) == 33 and all(n[4] < 2000 for n in LOBBY_NPCS),
          "33 standing NPCs, none of the y ~31000 parked ones")
    ps = payloads()
    check([struct.unpack_from("<I", p)[0] for p in ps] == [8, 8, 8, 8, 1],
          "33 NPCs go out as 8+8+8+8+1")
    check(all(len(p) == 4 + ENTRY_LEN * struct.unpack_from("<I", p)[0] for p in ps),
          "each payload is count + count x 24 B")
    one = payloads(parse_only("4, 31,32,33"), mode="num")
    check(len(one) == 1 and struct.unpack_from("<I", one[0])[0] == 4
          and struct.unpack_from("<H", one[0], 4 + 8)[0] == 4,
          "--npc-spawn-only picks the four gate guards; mode num = lnpc number")
    check(parse_only("") is None, "empty --npc-spawn-only = all")
    check(type_of(LOBBY_NPCS[0], "chr") == 45 and type_of(LOBBY_NPCS[0]) == 1,
          "type modes: idx = bzd record index, chr = the bzd type field")
    rp = ring_payloads((925.4, -12.3, -1271.7), parse_types(ARENA_TYPES_DEFAULT), 150.0)
    check(len(rp) == 1 and struct.unpack_from("<I", rp[0])[0] == 8,
          "arena ring: 8 default types -> one message of 8")
    r0 = struct.unpack_from("<IIH3h3hH", rp[0], 4)
    check(r0[0] == ARENA_ID_BASE and r0[2] == 1 and r0[3:6] == (1075, -12, -1272)
          and r0[6:9] == (-1000, 0, 0),
          "arena ring: NPC 0 at centre + (150, 0), facing the centre, own id range")
    check(parse_types("1, 45,0x34") == [1, 45, 52], "parse_types keeps order, takes hex")
    wr = wu_records()
    check(len(wr) == 33 and wr[0]["id"] == 0x40000004 and wr[0]["b4"] == 1
          and wr[0]["b5"] == 0, "type-125: lnpc_04 = id 0x40000004, wire+4 = bzd record 1")
    check(all(r["id"] >> 28 == 4 for r in wr), "type-125: every id has top nibble 4 "
          "(the 0x00bd2358 NPC arm)")
    byn = {r["id"] & 0xFFFF: r["h6"] for r in wu_records()}
    check(byn[7] == 4 and byn[20] == 17 and byn[40] == 37 and byn[43] == 40,
          "name (default bzd): wire+6 = the bzd record index (7->4, 20->17, 40->37, 43->40)")
    check(all(0 < v < 41 for v in byn.values()) and all(
        r["h6"] == r["b4"] for r in wu_records()),
          "name: every wire+6 < 41 (table 0 has 41 records) and equals wire+4")
    check(wu_records(parse_only("30"), name="msgid")[0]["h6"] == 0xd41d,
          "name mode msgid kept for reproduction: lnpc_30 -> 0xd41d")
    check(wu_records(parse_only("30"), name="index")[0]["h6"] == 29
          and wu_records(parse_only("30"), name="none")[0]["h6"] == 0,
          "name modes: index = lnpc - 1, none = 0")
    w1 = wu_records(parse_only("4"))
    check(len(w1) == 1 and (w1[0]["x"], w1[0]["z"]) == (1004.52, -485.16),
          "--npc-spawn-only 4: one record, the gate guard at its bzd spot")
    print("ALL PASS" if not fails else "%d FAIL" % len(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
