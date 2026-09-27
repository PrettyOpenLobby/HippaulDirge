#!/usr/bin/env python3
"""Dirge of Cerberus online MAGIC -- the server's MP ledger (2026-09-24).

the protocol notes sec 4hh.6. Read from the client (arena savestate
doc_gunfire_pc_slot03_20260913_1453.p2s, kel_rel / online module; emulated
where marked) and one live cast:

  * MP IS SERVER-OWNED. The client gates a cast on its synced copy (self record
    R+48 -> chara+36 every frame; gate 0x006b7d70: MP >= cost) and never spends
    it locally for a network actor (0x006b8bf4). What sets R+48: message 61
    (the answer to request 60), notify kind 44 (u32 at body[16], HIGH 16 bits
    = MP; low 16 nonzero = also HP to max), kind 34 sub 0, and kinds 2 / 51
    (the client itself refills to 100 at the battle spawn / a mission reset,
    unless the table restricts Magic: flag 0x20000 + restriction bit 0x02).
    Max MP is a client constant, 100, for everyone (chara+8 from data table 4
    +0x11e; the setter clamps to [0, 100]).
  * A CAST = request 60 {u16 60, u16 session, u32 0, u32 arg = element | level
    << 16}, sent in the same call as the type-112 shot -- nothing waits for the
    answer, so the server cannot veto a cast (61 status < 0 only posts error
    40000 + status and leaves MP alone). Answer 61 {body+4 status 0, body+8 new
    MP}: emulated 100 -> 70 for body+8 = 70, 100 -> 0 for the old zero answer.
  * COST = magic def +6, def row from the ONLINE index at data table 4 +0x344
    (0x0049af68), emulated for all 18 pairs: Fire 30, Thunder 50, Blizzard
    20 / 10, Cure 30, Bind (= Cure level 2) 20, Grenade 25 / 20 / 20, Flash
    25 / 20 / 20. Rows reading 1 are filler (power 1 or a copy) -> level-1 cost.
    x0.6 truncated when the SUIT is class 3 = Magic Suit (0x6331003C..4F)
    (0x004a2300; chara+96 bit 0x100 is set unconditionally at chara init). No
    other modifier. LEVEL = the sum of the fitted parts' level bits, clamped to
    3 (materia 1, Bind 2, Materia Floater +1, Materia Booster +1, Beta +2) and
    it rides in the arg, so the server prices a cast from the arg alone.
  * ELEMENT: 1 Fire (0x6F340017; live arg 0x10001), 2 Thunder (0x19),
    3 Blizzard (0x18), 4 Cure (0x1A) / Bind (0x1C, level 2), 5 Grenade (0x1D),
    6 Flash (0x1B).
  * RETRANSMITS. Game-server requests are mode 4: the header is enciphered with
    a per-boot key we do not hold, so docudp can neither read the transport seq
    nor ACK, and the client's reliable layer (500 ms timer, doubling) resends
    every request. Live 07:20:09Z, ONE cast: copies at +0.598 / +1.588 / +3.599
    / +7.585 s. The header is a block cipher (every byte changes per datagram,
    capture 09-24) and the plaintext prefix carries a send clock, so a resend is
    not byte-identical: the SCHEDULE is the only mark of a resend. A new 60
    cannot be built while one is outstanding (0x00bc7928 needs [chan+0x864] ==
    1), and a genuine recast needs the fire FSM's 60-tick cycle (~1 s).

WHAT IS OURS (SE's server logic is lost): refilling MP on a KO respawn (kind
44), and charging a same-spell 60 that lands on the resend schedule as a
resend (a real recast at exactly +0.6 / +1.6 / +3.6 / +7.6 s +-0.2 would go
free -- retail had a similar hole: a cast while any request is outstanding
sends no 60 at all).
"""
import sys

MP_MAX = 100
#: element -> (level-1, level-2, level-3) MP cost; None = filler row (cost 1)
COST = {1: (30, None, None),      # Fire
        2: (50, None, None),      # Thunder
        3: (20, 10, None),        # Blizzard
        4: (30, 20, None),        # Cure / Bind (level 2)
        5: (25, 20, 20),          # Grenade
        6: (25, 20, 20)}          # Flash
ELEMENT_NAMES = {1: "Fire", 2: "Thunder", 3: "Blizzard", 4: "Cure", 5: "Grenade",
                 6: "Flash"}
MAGIC_SUIT_CLASS = 3              # suit item byte +0x10: 0x6331003C..4F
SUIT_BASE, SUIT_STEP = 0x63310000, 20
#: the reliable layer's resend offsets (500 ms timer, doubling), measured live
RESEND_OFFSETS = (0.6, 1.6, 3.6, 7.6, 15.6)
RESEND_TOLERANCE = 0.2
RESTRICT_MAGIC = 0x02             # battletable wire+116 bit
FLAG_HAS_RESTRICT = 0x00020000


def parse_arg(arg):
    """(element, level) from request 60's arg."""
    arg = int(arg or 0) & 0xFFFFFFFF
    return arg & 0xFFFF, (arg >> 16) & 0xFFFF


def suit_class(item):
    item = int(item or 0) & 0xFFFFFFFF
    if item & 0xFFFF0000 != SUIT_BASE or (item & 0xFFFF) >= 5 * SUIT_STEP:
        return None
    return (item & 0xFFFF) // SUIT_STEP


def cast_cost(element, level, suit=None):
    """MP a cast costs, or None for an element the client has no row for."""
    row = COST.get(element)
    if row is None:
        return None
    lvl = min(max(int(level or 1), 1), 3)
    cost = row[lvl - 1] if row[lvl - 1] is not None else row[0]
    if suit_class(suit) == MAGIC_SUIT_CLASS:
        cost = int(cost * 0.6)
    return cost


def magic_restricted(flags, restrictions):
    """True when the client leaves MP at 0 on the spawn (kind 2 / 51)."""
    return bool(int(flags or 0) & FLAG_HAS_RESTRICT
                and int(restrictions or 0) & RESTRICT_MAGIC)


class Ledger(object):
    """Per character: current MP for the battle it is in, and the last charged
    cast (for the resend schedule)."""

    def __init__(self, mp_max=MP_MAX):
        self.mp_max = mp_max
        self.chars = {}          # cid -> {"battle", "mp", "cast": (arg, t0)}

    def enter(self, cid, battle, restricted=False):
        """Called on every request 60 with the player's current battle key:
        a new battle starts at full MP (0 when Magic is restricted), exactly as
        the client's own kind-2 refill."""
        c = self.chars.get(cid)
        if c is None or c["battle"] != battle:
            c = self.chars[cid] = {"battle": battle, "casts": [],
                                   "mp": 0 if restricted else self.mp_max}
        return c

    def refill(self, cid, mp=None):
        c = self.chars.get(cid)
        if c is not None:
            c["mp"] = self.mp_max if mp is None else max(0, min(mp, self.mp_max))
            return c["mp"]
        return None

    def mp(self, cid):
        c = self.chars.get(cid)
        return None if c is None else c["mp"]

    def credit(self, cid, battle, amount, restricted=False):
        """2026-09-26: MP GAINED (an Ether, an MP point): enter the battle
        like a cast does, add, clamp to max. Returns the new MP."""
        c = self.enter(cid, battle, restricted)
        c["mp"] = max(0, min(self.mp_max, c["mp"] + int(amount)))
        return c["mp"]

    def cast(self, cid, battle, arg, now, suit=None, restricted=False):
        """(mp to answer, charged cost or 0, note). A same-spell 60 on the
        resend schedule of the last charged cast is a resend: answered with the
        same MP, not charged again."""
        c = self.enter(cid, battle, restricted)
        el, lvl = parse_arg(arg)
        # every charged cast still inside its resend window, not just the last:
        # a recast within 8 s must not turn the first cast's later resends into
        # new casts
        c["casts"] = [(a, t) for a, t in c["casts"]
                      if now - t <= RESEND_OFFSETS[-1] + RESEND_TOLERANCE]
        for a, t in c["casts"]:
            dt = now - t
            if a == arg and any(abs(dt - off) <= RESEND_TOLERANCE
                                for off in RESEND_OFFSETS):
                return c["mp"], 0, "resend (+%.2f s)" % dt
        cost = cast_cost(el, lvl, suit)
        c["casts"].append((arg, now))
        if cost is None:
            return c["mp"], 0, "unknown element %d level %d: not charged" % (el, lvl)
        c["mp"] = max(0, c["mp"] - cost)
        return c["mp"], cost, "%s level %d cost %d%s" % (
            ELEMENT_NAMES.get(el, "element %d" % el), lvl, cost,
            " (Magic Suit x0.6)" if suit_class(suit) == MAGIC_SUIT_CLASS else "")


def _selftest():
    fails = []

    def check(name, cond):
        if not cond:
            fails.append(name)
        print("  %s %s" % ("ok  " if cond else "FAIL", name))

    check("live arg 0x10001 = Fire level 1", parse_arg(0x10001) == (1, 1))
    check("costs: Fire 30, Thunder 50, Blizzard 20, Cure 30, Grenade 25, Flash 25",
          [cast_cost(e, 1) for e in range(1, 7)] == [30, 50, 20, 30, 25, 25])
    check("level 2: Blizzard 10, Bind 20, Grenade 20; filler Fire L2 -> 30",
          (cast_cost(3, 2), cast_cost(4, 2), cast_cost(5, 2), cast_cost(1, 2), cast_cost(1, 3))
          == (10, 20, 20, 30, 30))
    check("Magic Suit x0.6 truncated (Fire 18, Thunder 30, Blizzard L2 6)",
          (cast_cost(1, 1, 0x6331003C), cast_cost(2, 1, 0x6331004F), cast_cost(3, 2, 0x63310040))
          == (18, 30, 6))
    check("other suits pay full (Soldier, Sniper, Speed, Armored)",
          all(cast_cost(1, 1, s) == 30 for s in (0x63310000, 0x63310014, 0x63310028, 0x63310050)))
    check("unknown element -> None", cast_cost(7, 1) is None and cast_cost(0, 1) is None)
    check("restriction needs flag 0x20000 AND bit 0x02",
          magic_restricted(0x20000, 0x02) and not magic_restricted(0, 0x02)
          and not magic_restricted(0x20000, 0x08))

    # the live cast: 07:20:09.665 + resends, then a genuine second cast at +9 s
    L = Ledger()
    t0 = 1000.0
    live = [0.0, 0.598, 1.588, 3.599, 7.585]
    got = [L.cast(7, "b1", 0x10001, t0 + d) for d in live]
    check("live: first copy charges Fire 30 -> MP 70", got[0][:2] == (70, 30))
    check("live: the four resends answer 70 and charge nothing",
          all(g[:2] == (70, 0) for g in got[1:]))
    check("a real recast off the schedule (+9.0 s) charges again -> 40",
          L.cast(7, "b1", 0x10001, t0 + 9.0)[:2] == (40, 30))
    check("a different spell at a resend offset is a NEW cast",
          L.cast(7, "b1", 0x10003, t0 + 9.6)[:2] == (20, 20))
    # a same-spell recast at +2 s: the FIRST cast's +7.6 s resend (= recast
    # +5.6) must still read as a resend
    L3 = Ledger()
    for d in (0.0, 0.6, 1.6, 2.0, 2.6, 3.6, 5.6, 7.6, 9.6):
        L3.cast(5, "b", 0x10001, t0 + d)
    check("recast at +2 s: two charges exactly (100 -> 40), all resends free",
          L3.mp(5) == 40)
    L4 = Ledger()
    L4.cast(4, "b", 0x10001, t0)
    L4.cast(4, "b", 0x10002, t0 + 5.0)
    check("credit: Ether +50 on MP 20 -> 70", L4.credit(4, "b", 50) == 70)
    check("credit clamps at 100", L4.credit(4, "b", 50) == 100)
    check("credit in a NEW battle starts from 100 (the spawn refill)",
          Ledger().credit(4, "x", 10) == 100)
    check("MP floors at 0", L.cast(7, "b1", 0x10002, t0 + 20.0)[0] == 0)
    check("a new battle starts at 100", L.cast(7, "b2", 0x10001, t0 + 30.0)[:2] == (70, 30))
    check("refill -> 100", L.refill(7) == 100 and L.mp(7) == 100)
    check("a Magic-restricted battle starts at 0",
          Ledger().cast(9, "b3", 0x10001, 0.0, restricted=True)[:2] == (0, 30))
    # TWIN: without the schedule, the live cast would have cost 150 (5 x 30)
    L2 = Ledger()
    for d in live:
        c = L2.enter(8, "b1")
        c["mp"] = max(0, c["mp"] - cast_cost(1, 1))
    check("TWIN: charging every copy drains 100 -> 0 on ONE cast", L2.mp(8) == 0)
    print("doc_magic selftest: %s" % ("ALL PASS" if not fails else "FAIL %s" % fails))
    return not fails


if __name__ == "__main__":
    sys.exit(0 if _selftest() else 1)
