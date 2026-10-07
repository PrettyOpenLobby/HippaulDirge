#!/usr/bin/env python3
"""Dirge of Cerberus Online: the arena ITEM GENERATORS (2026-09-26).

Retail maps put items on the field during a match (source: the Lifestream
fan archive's map notes, e.g. Limit Breakers and Ethers appearing on certain
maps). Online, the SERVER placed them (notify kind 10, the field
the client's table [chan+1284] holds), so the timing was server logic.

WHERE THE DATA IS (static RE on the retail client + the served 20060124_3
bzd files, 2026-09-26):
  * script command 94 PopItemFromGenerator (0x00685d80) -> 0x0049bb50: a
    placement NODE (bzd table j15, 80 B: 4x4 matrix, position at +48, type
    byte +64 -- 3 = item generator, 4 = enemy, 2 = player spawn; set index
    u32 +72) -> 0x0049bcf0: an ITEM SET (j22, 104 B: u16 header, 8 x {u32
    item, u32 qty, u32 weight}; weights sum <= 100 = percent, INFERRED --
    the pick routine 0x00657b30 was not traced) -> 0x0049d218 picks one.
  * each SITUATION (j28: 1000-1123 PvP modes, 3000-3008 missions, 9xxx)
    lists its own nodes, so a battle switches on its own generators.
  * NO respawn interval or count exists in any record: RESPAWN_S is ours.

doc_item_generators.json = {zone: {"sets": {i: [[item, qty, weight], ..]},
"situations": {sit: [[x, y, z, set], ..]}}}. That table is the arenas' own
level data, so it is not shipped here: put one read out of your own copy
beside this module (tools/doc_extract_arena.py writes it). Without it no generator places anything (the field
still carries the players' own drops and the capsules).

The field itself (slots, kind 10/11, pick-ups) is docudp's; this module only
decides WHAT appears WHERE and WHEN.
"""
import json
import os
import random

import doc_npcquests

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "doc_item_generators.json")

RESPAWN_S = 30.0          # OURS: a picked or empty generator rolls again after this
MAX_ITEMS = 96            # OURS: leave room in the 128-slot table for drops
#: never from a generator: capsules have their own rules (docudp's capsule
#: field), a mission's QUEST items (the church's Fuzzy Seed, set 7 at 100 %)
#: are placed ONCE per run by doc_npcquests.mission_items -- a generator would
#: respawn them forever. 2026-09-26: Chocobo Coins (0x67300001) ARE placed now
#: -- docudp counts each player's pick-ups and doc_stats pays 1000 gil apiece at
#: the end (COIN_GIL). The rest of category 0x6730 stays out: 0x67300000 is gil
#: itself, and 0x67300002..6 are SE placeholders in our build (item names "gold
#: 2..6", value word 0 in the client's item table) that some generator sets list.
SKIP_ITEMS = ((0x6B300000, 0x67300000, 0x67300002, 0x67300003, 0x67300004,
               0x67300005, 0x67300006)
              + tuple(sorted(doc_npcquests.FIELD_QUEST_ITEMS)))
SKIP_CATEGORIES = ()
#: the thin PvP arenas' ammo sets name 0x62300004..6 ("Bullet 4-6", no weapon
#: loads them) with the standard 9 / 4 / 30 amounts; z230 names 0..2 in the
#: same set. Read as handgun / rifle / MG -- OURS, to be checked live.
ITEM_ALIAS = {0x62300004: 0x62300000, 0x62300005: 0x62300001,
              0x62300006: 0x62300002}

_cache = {}


def load(path=DATA):
    """The generator table ({} if the data file is missing)."""
    if path not in _cache:
        try:
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError):
            raw = {}
        out = {}
        for zone, z in raw.items():
            sets = {int(i): [(int(it, 0) if isinstance(it, str) else int(it),
                              int(q), int(w)) for it, q, w in rows]
                    for i, rows in z.get("sets", {}).items()}
            sits = {int(s): [((float(x), float(y), float(zz)), int(st))
                             for x, y, zz, st in gens]
                    for s, gens in z.get("situations", {}).items()}
            out[int(zone)] = (sets, sits)
        _cache[path] = out
    return _cache[path]


def usable(item):
    return item not in SKIP_ITEMS and (item >> 16) not in SKIP_CATEGORIES


def pvp_twins(situation):
    """2026-10-03: the 9xxx situations to try for a PvP one. Nine PvP arenas
    (z203/204/205/208/209/212/231/233/235) have no 10xx/11xx controller, so
    the 1100 we send placed NO items (live: Church, Train Graveyard). Where
    both families exist, 1000 == 9000 and 1100 == 9100 enable exactly the
    same generator nodes, so 10xx borrows 9000/9001 and 11xx-19xx 9100/9101.
    The client never loads a model set for 9xxx (ev2045 mdlResLoad), so only
    the server uses them, for item placement."""
    s = int(situation or 0)
    if 1000 <= s < 1100:
        return (9000, 9001)
    if 1100 <= s < 2000:
        return (9100, 9101)
    return ()


def _placed(sets, nodes):
    out = []
    for pos, st in nodes:
        rows = [(ITEM_ALIAS.get(i, i), q, w) for i, q, w in sets.get(st, ())
                if usable(ITEM_ALIAS.get(i, i)) and w > 0]
        if rows:
            out.append((pos, rows))
    return out


def generators(zone, situation, table=None):
    """[(pos, set rows)] for the battle's zone + situation, with the rows a
    generator can actually drop (see SKIP_*); generators left with nothing
    are dropped. [] when the zone or situation has no data. A PvP situation
    takes whichever of itself and its 9xxx twins (pvp_twins) places the most:
    z235's 1100 is a 2-node stub beside a full 9100."""
    table = load() if table is None else table
    sets, sits = table.get(int(zone or 0), ({}, {}))
    s = int(situation or 0)
    out = _placed(sets, sits.get(s, []))
    for twin in pvp_twins(s):
        alt = _placed(sets, sits.get(twin, []))
        if len(alt) > len(out):
            out = alt
    return out[:MAX_ITEMS]


def roll(rows, rng=random):
    """One pick from a set: (item, qty), or None (the weights' remainder to
    100 is 'nothing this time')."""
    r = rng.uniform(0, 100)
    for item, qty, w in rows:
        if r < w:
            return item, qty
        r -= w
    return None


MAKO_CAPSULE = 0x6B300000


def capsule_spots(zone, situation, table=None):
    """2026-10-05: the positions of (zone, situation)'s item generators whose
    set can hold a Mako Capsule -- SE's own capsule spots (the Trooper 3rd
    exam's 201:3001 has exactly the 3 its objective asks). The capsule
    missions placed theirs on a ring around the start instead (live: one
    inside a box). [] when there are none."""
    table = load() if table is None else table
    sets, sits = table.get(int(zone or 0), ({}, {}))
    out = []
    for node in sits.get(int(situation or 0), []):
        pos, si = node[0], node[1]
        if any(item == MAKO_CAPSULE for item, _q, _w in sets.get(si, ())):
            out.append(tuple(pos))
    return out


class Generators(object):
    """One battle's generators: which are holding an item on the field
    (gen -> slot), and when an empty one rolls again."""

    def __init__(self, gens, now, respawn_s=RESPAWN_S):
        self.gens = list(gens)
        self.respawn_s = float(respawn_s)
        self.slot_of = {}                     # gen index -> field slot
        self.due = {i: now for i in range(len(self.gens))}

    def tick(self, now, free_slot, rng=random):
        """[(gen, slot, item, qty, pos)] to place now. `free_slot()` returns
        a free field slot or None. A generator that rolls nothing waits a
        full RESPAWN_S before it rolls again."""
        out = []
        for i, t in sorted(self.due.items()):
            if t > now:
                continue
            got = roll(self.gens[i][1], rng)
            if got is None:
                self.due[i] = now + self.respawn_s
                continue
            slot = free_slot()
            if slot is None:
                self.due[i] = now + self.respawn_s
                continue
            del self.due[i]
            self.slot_of[i] = slot
            out.append((i, slot, got[0], got[1], self.gens[i][0]))
        return out

    def picked(self, slot, now):
        """The item in `slot` was taken: its generator rolls again later.
        Returns the generator index, or None if the slot was not one of ours."""
        for i, s in list(self.slot_of.items()):
            if s == slot:
                del self.slot_of[i]
                self.due[i] = now + self.respawn_s
                return i
        return None

    def next_due(self):
        return min(self.due.values()) if self.due else None


def _selftest():
    fails = []

    def check(name, cond):
        print("  %s %s" % ("ok  " if cond else "FAIL", name))
        if not cond:
            fails.append(name)

    table = {204: ({2: [(0x69320006, 1, 40)],
                    7: [(0x62300000, 9, 20), (0x62300001, 4, 20),
                        (0x62300002, 30, 20)],
                    8: [(0x6B300000, 1, 100)],
                    9: [(0x62300004, 9, 100)]},
                   {3002: [((1.0, 2.0, 3.0), 2), ((4.0, 5.0, 6.0), 7),
                           ((7.0, 8.0, 9.0), 8), ((0.0, 0.0, 0.0), 9)]})}
    g = generators(204, 3002, table)
    check("generators: the capsule-only one is skipped, the rest kept",
          [p for p, _ in g] == [(1.0, 2.0, 3.0), (4.0, 5.0, 6.0), (0.0, 0.0, 0.0)])
    check("generators: Bullet 4 reads as handgun (ITEM_ALIAS)",
          g[2][1] == [(0x62300000, 9, 100)])
    check("generators: an unknown zone / situation has none",
          generators(999, 3002, table) == [] and generators(204, 1, table) == [])
    # 2026-10-03 (live: Church / Train Graveyard placed nothing): a PvP
    # situation the arena lacks borrows its 9xxx twin; a mission never does
    tw = {212: ({7: [(0x62300000, 9, 50)]},
                {9100: [((1.0, 0.0, 1.0), 7), ((2.0, 0.0, 2.0), 7)],
                 9000: [((3.0, 0.0, 3.0), 7)]})}
    check("generators: TBT 1100 missing -> the 9100 twin's 2 nodes",
          [p for p, _ in generators(212, 1100, tw)]
          == [(1.0, 0.0, 1.0), (2.0, 0.0, 2.0)])
    check("generators: BT 1000 missing -> the 9000 twin",
          [p for p, _ in generators(212, 1000, tw)] == [(3.0, 0.0, 3.0)])
    check("generators: a mission (3000) does not borrow a PvP twin",
          generators(212, 3000, tw) == [])
    tw[212][1][1100] = [((9.0, 0.0, 9.0), 7)]
    check("generators: a 1-node 1100 stub loses to its 2-node 9100 twin",
          len(generators(212, 1100, tw)) == 2)
    # 2026-09-26: coins are placed now (doc_stats pays them); gil itself and
    # the unnamed "gold 2..6" placeholders are not
    ct = {201: ({1: [(0x67300001, 1, 10), (0x67300002, 1, 6),
                     (0x67300003, 1, 2), (0x67300000, 1, 5)]},
                {1100: [((1.0, 0.0, 1.0), 1)]})}
    check("generators: a Chocobo Coin set keeps the coin, drops gil and the "
          "placeholders", generators(201, 1100, ct) == [
              ((1.0, 0.0, 1.0), [(0x67300001, 1, 10)])])
    check("TWIN: the old category skip (0x6730) would have dropped the coin too",
          not [r for r in ct[201][0][1] if (r[0] >> 16) not in (0x6730,)])
    if load():
        real = generators(201, 1100)
        check("your z201 table (situation 1100, a PvP battle) places "
              "Chocobo Coins",
              any(it == 0x67300001 for _p, rows in real for it, _q, _w in rows))
    else:
        print("  SKIP no doc_item_generators.json beside this module (README): "
              "the checks against the arena data need your own table")

    class R:
        def __init__(self, v):
            self.v = v

        def uniform(self, a, b):
            return self.v
    check("roll: 10 of 100 on the ammo set -> handgun x9",
          roll(g[1][1], R(10)) == (0x62300000, 9))
    check("roll: 70 of 100 on the ammo set (60 %) -> nothing",
          roll(g[1][1], R(70)) is None)
    free = iter(range(5, 128))
    st = Generators(g, now=0.0, respawn_s=30.0)
    placed = st.tick(0.0, lambda: next(free), R(10))
    check("tick at the start: every generator whose roll lands places an item",
          [(i, s, it) for i, s, it, _q, _p in placed]
          == [(0, 5, 0x69320006), (1, 6, 0x62300000), (2, 7, 0x62300000)])
    check("tick again at once: nothing (all three are holding)",
          st.tick(1.0, lambda: next(free), R(10)) == [])
    check("picked: slot 6's generator is freed and due in 30 s",
          st.picked(6, 10.0) == 1 and st.due == {1: 40.0})
    check("TWIN: a slot that is not a generator's (a player drop) frees nothing",
          st.picked(99, 10.0) is None)
    check("tick before the respawn: nothing; at it: a new item",
          st.tick(39.0, lambda: next(free), R(10)) == []
          and len(st.tick(40.0, lambda: next(free), R(10))) == 1)
    st2 = Generators(g, now=0.0)
    st2.tick(0.0, lambda: None, R(10))
    check("a full field: nothing placed, every generator retries later",
          st2.slot_of == {} and all(t == RESPAWN_S for t in st2.due.values()))
    real = load()
    check("the shipped data loads (z204 has situation 3002's Ether generators)",
          not real or any(r[0][0] == 0x69320006
                          for _p, r in generators(204, 3002, real)))
    print("doc_field selftest: %s" % ("ALL PASS" if not fails else "%d FAIL" % len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
