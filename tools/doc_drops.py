#!/usr/bin/env python3
"""Dirge of Cerberus ENEMY DROPS -- the retail client's own drop tables,
rolled by the server (2026-09-24).

Online, the client never rolls a drop itself: the death handler 0x00680b20
skips its roll when the actor has flag [+0x28] & 0x20, which every mission
enemy carries (measured, retail SLPM-66271, 0x2284ab). So the server rolls and
places the drop as a field item (notify kind 10) at the enemy's last reported
position; picking it up is the ordinary 119 -> kind 11 path.

THE ROLL, as the client's 0x004a7310 does it (static):
    r1 = int(100 * rand()); r2 = int(100 * rand())      (rand in [0, 1))
    if r1 < chance: walk the entries summing weights; the first entry with
        r2 < running sum drops {item, count}. Weights summing under 100 leave
        a "nothing" share. At most ONE item per kill; the count is fixed.

THE TABLES live per enemy DEF RECORD (0x20C bytes, bank at [zonecfg+0x38];
+0x70 s16 chance %, +0x1D0 five {u32 item, u32 count, s16 weight} entries),
read out of the retail and US-preview savestates. One model has several
records (spawn variants) with different tables, and which record a kind-15
NPC gets is not known to the server, so:
  * DROPS_BY_SET pins the variant MEASURED for a (zone, situation) -- z201
    3001's DG soldiers (Beginner's Course) all use record 0x00fa5f84:
    chance 100, Potion w77 / Phoenix Down w3, no bullets.
  * DROPS_BY_MODEL is otherwise the model's bullet-carrying combat variant
    (OURS: the choice of variant; the numbers are SE's).
Models not found in any savestate (e028 sniper, e019 / e020 / e069 Wastelands
beasts) drop nothing until their zone's bank is read.
"""
import random

POTION, PHOENIX_DOWN = 0x69320000, 0x69320004
HANDGUN, RIFLE, MG = 0x62300000, 0x62300001, 0x62300002

# model -> (chance %, ((item, count, weight), ...))
DROPS_BY_MODEL = {
    "e102": (100, ((POTION, 1, 25), (HANDGUN, 9, 25), (RIFLE, 4, 25), (MG, 30, 25))),
    "e030": (65, ((POTION, 1, 25), (HANDGUN, 9, 30), (RIFLE, 4, 20), (MG, 30, 25))),
    "e015": (10, ((POTION, 1, 10), (HANDGUN, 9, 20), (RIFLE, 4, 17), (MG, 30, 20))),
    "e038": (65, ((POTION, 1, 20), (PHOENIX_DOWN, 1, 1), (HANDGUN, 9, 25),
                  (RIFLE, 4, 25), (MG, 30, 29))),
    "e040": (40, ((POTION, 1, 80), (PHOENIX_DOWN, 1, 2))),
    "e042": (7, ((POTION, 1, 15), (HANDGUN, 9, 25), (RIFLE, 4, 25), (MG, 30, 35))),
    "e039": (40, ((HANDGUN, 9, 50), (MG, 30, 50))),
    # the preview's 0x64300009 w10 entry is left out (id not named): its
    # share becomes "nothing"
    "e046": (20, ((HANDGUN, 9, 35), (MG, 30, 55))),
    "e036": (100, ((PHOENIX_DOWN, 1, 10),)),
    "e037": (100, ((POTION, 1, 100),)),
    "e047": (10, ((POTION, 1, 10), (HANDGUN, 9, 20), (RIFLE, 4, 17), (MG, 30, 20))),
}
# (zone, situation, model) -> the variant measured in that arena
DROPS_BY_SET = {
    (201, 3001, "e102"): (100, ((POTION, 1, 77), (PHOENIX_DOWN, 1, 3))),
}


def table(model, zone=None, situation=None):
    """The (chance, entries) an enemy of `model` rolls on, or None."""
    return (DROPS_BY_SET.get((zone, situation, model))
            or DROPS_BY_MODEL.get(model))


def roll(model, zone=None, situation=None, rng=random):
    """(item id, count) this kill drops, or None -- 0x004a7310's roll."""
    t = table(model, zone, situation)
    if t is None:
        return None
    chance, entries = t
    r1 = int(100 * rng.random())
    r2 = int(100 * rng.random())
    if r1 >= chance:
        return None
    run = 0
    for item, count, weight in entries:
        run += weight
        if r2 < run:
            return item, count
    return None


def _selftest():
    fails = []

    def check(name, cond):
        if not cond:
            fails.append(name)
        print("  %s %s" % ("ok  " if cond else "FAIL", name))

    class Seq(object):
        def __init__(self, *v):
            self.v = list(v)

        def random(self):
            return self.v.pop(0)

    # e102 combat variant: chance 100, 4 x w25 -> r2 picks the quarter
    check("e102 r2 0.10 -> Potion x1", roll("e102", rng=Seq(0.5, 0.10)) == (POTION, 1))
    check("e102 r2 0.30 -> 9 handgun", roll("e102", rng=Seq(0.5, 0.30)) == (HANDGUN, 9))
    check("e102 r2 0.60 -> 4 rifle", roll("e102", rng=Seq(0.5, 0.60)) == (RIFLE, 4))
    check("e102 r2 0.99 -> 30 MG", roll("e102", rng=Seq(0.5, 0.99)) == (MG, 30))
    # chance gate: e015 10 %
    check("e015 r1 0.10 (>= 10) -> nothing", roll("e015", rng=Seq(0.10, 0.0)) is None)
    check("e015 r1 0.09 -> rolls (r2 0.15 -> 9 handgun)",
          roll("e015", rng=Seq(0.09, 0.15)) == (HANDGUN, 9))
    # weights under 100 leave a nothing share (e015 sums 67)
    check("TWIN: e015 r2 0.67 -> the nothing share", roll("e015", rng=Seq(0.0, 0.67)) is None)
    # the measured Beginner's Course variant has no bullets
    check("z201 3001 e102 -> Potion / Phoenix Down only",
          {roll("e102", 201, 3001, Seq(0.0, r)) for r in (0.0, 0.5, 0.78, 0.79, 0.99)}
          == {(POTION, 1), (PHOENIX_DOWN, 1), None})
    check("unread model e028 drops nothing", roll("e028", rng=Seq(0.0, 0.0)) is None)
    # over many kills a DG soldier drops bullets about 3 times in 4
    rng = random.Random(7)
    n = sum(1 for _ in range(4000)
            if (roll("e102", rng=rng) or (0,))[0] in (HANDGUN, RIFLE, MG))
    check("e102: ~75 %% of kills drop bullets (%d / 4000)" % n, 2800 < n < 3200)
    print("doc_drops selftest: %s" % ("ALL PASS" if not fails else
                                      "%d FAILED" % len(fails)))
    return not fails


if __name__ == "__main__":
    raise SystemExit(0 if _selftest() else 1)
