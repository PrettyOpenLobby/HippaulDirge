#!/usr/bin/env python3
"""Dirge of Cerberus online: ITEM USE and MP POINTS (2026-09-26).

Read from the retail client (arena savestate doc_gunfire_pc_slot03_20260913_1453
and capsule savestate doc_capsule_church_slot07_20260924; the item scripts were
RUN in the emulator, see an offline run of the client's own code (doc_mp_heal_proof)):

ITEM USE (game-server request 21 -> message 22)
  * The player's use (0x006b49xx, arena) plays the "use" half of the item
    script (event 104), then asks the server: entity 0x00bed268 -> engine
    interface vt+128 (0x00be9e90: only while HP > 0) -> 0x00bc53f0: request 21
    {u16 21, u16 session, u32 0, u32 ITEM}. No target: an item is always used
    on oneself. It does NOT mark a request outstanding ([chan+2148] is read,
    never set), and 0x00bdef58 -> 0x00be6c08 takes ONE of the item out of the
    self record's bag (R+800 count, 8-byte rows from R+868 {u32 id, u16 flags,
    u16 count}) as soon as the request is sent. The CLIENT empties the bag; the
    answer never touches it.
  * Message 22 (arm 0x00bc503c): 0x00bdfb20 stores body+8 in the record whose
    chara id is the ident -- the self record OR any teammate record
    ([mgr+3488], 700-byte rows) -- and raises flag 0x2000; the next record
    tick hands (id, item) to the net listener (0x00be5658 -> listener vt+32
    0x00bf0310) -> "[KelAppNetClientEntityPlayer] receiveUseItem %x" ->
    actor event 3 -> 0x0068dca0(actor, item, 100): the item's EFFECT script.
    So message 22 IS the effect, and it is built to arrive for other players'
    units too (that is what the teammate loop is for).
  * The effect scripts, emulated (item -> actor messages):
      Potion-class 0x69320000/01/02/03/05/0A -> 301 HEAL 150
      0x6932000B/0C                          -> 301 HEAL 200
      Phoenix Down 0x69320004                -> 376 {2}, 311 {2} (clear status 2),
                                                310 {status 3} (a status bit ->
                                                request 46, which docudp answers)
      Ether 0x69320006                       -> 334 MP +50
      0x69320007/08/09                       -> 513 / 511 / 515 (not HP or MP)
    No 0x6932 item heals HP AND MP (there is no online Elixir in this build).
  * HP: message 301 on the player's own actor goes 0x006b25d0 -> entity
    0x00bed138 (self only, entity+20 & 0x40) -> engine vt+104 0x00bea120 ->
    0x00bdf7f0: R+44 += amount, clamped to R+752 (max HP), only while HP != 0.
    R+44 IS the HP store (what the per-frame copy reads), so a Potion heal
    lasts with no server push.
  * MP: message 334 adds to chara+36 (0x004a13b0) only -- the local copy that
    the per-frame sync overwrites from R+48 (sec 4hh.6) -- so an Ether is lost
    unless the server moves R+48: docudp pushes notify kind 44 with the new MP.

MP POINTS (P2P type 117; the retail name is "magic supply", zone setup step 3)
  * Created ONCE at zone setup (0x00bf1370 arena / 0x004ccae0 capsule state)
    from the situation's controller (bzd table 29): every placement node of
    type 8 becomes an object whose obj+194 bit 1 marks it an MP point and
    obj+204 = its ORDINAL among the type-8 nodes (0x006a17f8 capsule state,
    0x006c2790 arena). Only ordinals
    below [chan+1312] are created, enabled by bit n of [chan+1316..1323] --
    both written by notify kind 28 (rec[2] = count <= 64, rec+4 = u64 mask,
    0x00bc3098). docudp's zero kind 28 made the count 0: no MP point was ever
    created (arena controller 0 has 5 type-8 nodes; with count 64 the spawner
    asks for all 5, emulated).
  * Touching one (every frame within range, capsule state 0x006a1e48 ->
    0x00683c78) with MP
    below max sends 117 over the same RELIABLE sender as a 119 pick-up
    (0x00696038 -> 0x004c84a0 -> 0x00bef368, needs HP > 0 -> builder 0x00bee448):
    payload {u16 0, u16 POINT ORDINAL, u8 0, pad, u32 0, u32 per-sender count}.
    The point is not consumed and nothing on the client changes MP: the SERVER
    decides the amount. What retail granted per 117 is not in the client.

OURS (flagged in docudp): the MP an MP point grants per credit, and how often
one point credits one player (--mp-point-amount / --mp-point-every).
"""
import struct
import sys

P2P_MP_POINT = 117
#: measured (emulated item scripts, arena state): item -> MP the script adds
ITEM_MP = {0x69320006: 50}                    # Ether
#: measured: item -> HP the script heals (applied by the client itself)
ITEM_HP = {0x69320000: 150, 0x69320001: 150, 0x69320002: 150, 0x69320003: 150,
           0x69320005: 150, 0x6932000A: 150, 0x6932000B: 200, 0x6932000C: 200}
PHOENIX_DOWN = 0x69320004
#: the reliable layer's resend offsets (500 ms, doubling) -- doc_magic's,
#: re-measured on request 21 live +0.51 / +1.51 / +3.52 s
RESEND_OFFSETS = (0.6, 1.6, 3.6, 7.6, 15.6)
RESEND_TOLERANCE = 0.2

MP_POINT_AMOUNT = 10       # OURS: MP per credit
MP_POINT_EVERY = 0.5       # OURS: seconds between credits, per player per point


def parse_mp_point(body):
    """(kind, point ordinal, count) of a 117 payload, or None when short."""
    if body is None or len(body) < 4:
        return None
    kind, point = struct.unpack_from("<HH", body, 0)
    n = struct.unpack_from("<I", body, 12)[0] if len(body) >= 16 else None
    return kind, point, n


def build_mp_point_body(point, n=0, kind=0):
    """The client's own 117 payload (builder 0x00bee448), for tests."""
    return struct.pack("<HHB3xII", kind & 0xFFFF, point & 0xFFFF, 0, 0,
                       n & 0xFFFFFFFF)


def mp_points_record(count=64, mask=None):
    """Notify kind 28's payload that ENABLES the MP points: 4 pad bytes, then
    the record the arm reads at body[20]: rec[2] = count (<= 64), rec+4 = u64
    mask. rec[0] = 0 (no 4-byte entry list), rec[1] = 0 and rec[3] = 0 keep
    the arm's [chan+204] bits exactly as the old zero record set them (0x500)."""
    count = max(0, min(64, int(count)))
    if mask is None:
        mask = (1 << count) - 1
    rec = bytearray(64)
    rec[2] = count
    struct.pack_into("<Q", rec, 4, mask & 0xFFFFFFFFFFFFFFFF)
    return bytes(4) + bytes(rec)


class UseLedger(object):
    """Which request-21 datagrams are NEW uses. Each use the client sends has
    already taken one item out of its bag, so every new one is answered; a
    RESEND (same transport seq when the header is readable, else same item on
    the reliable layer's schedule of an answered use) is not."""

    def __init__(self):
        self.seqs = {}       # (cid, seq) -> time
        self.uses = {}       # cid -> [(item, time)]

    def use(self, cid, item, now, seq=None):
        """(new?, note)."""
        self.seqs = {k: t for k, t in self.seqs.items() if now - t < 30.0}
        hist = [(i, t) for i, t in self.uses.get(cid, [])
                if now - t <= RESEND_OFFSETS[-1] + RESEND_TOLERANCE]
        self.uses[cid] = hist
        if seq is not None:
            if (cid, seq) in self.seqs:
                return False, "resend (seq %d)" % seq
            self.seqs[(cid, seq)] = now
            hist.append((item, now))
            return True, "new use (seq %d)" % seq
        for i, t in hist:
            dt = now - t
            if i == item and any(abs(dt - off) <= RESEND_TOLERANCE
                                 for off in RESEND_OFFSETS):
                return False, "resend (+%.2f s)" % dt
        hist.append((item, now))
        return True, "new use"


class MpPoints(object):
    """OURS: at most one credit per `every` seconds per (player, point)."""

    def __init__(self, amount=MP_POINT_AMOUNT, every=MP_POINT_EVERY):
        self.amount = amount
        self.every = every
        self.last = {}       # (cid, battle, point) -> time

    def credit(self, cid, battle, point, now):
        """MP to add now (0 while the point is cooling down for this player)."""
        k = (cid, battle, point)
        t = self.last.get(k)
        if t is not None and now - t < self.every:
            return 0
        self.last[k] = now
        return self.amount


def _selftest():
    fails = []

    def check(name, cond):
        if not cond:
            fails.append(name)
        print("  %s %s" % ("ok  " if cond else "FAIL", name))

    b = build_mp_point_body(3, n=41)
    check("117 payload = {u16 0, u16 point, u8 0, pad, u32 0, u32 n} (16 B)",
          len(b) == 16 and parse_mp_point(b) == (0, 3, 41))
    check("short 117 -> None", parse_mp_point(b"\x00\x00") is None)
    r = mp_points_record()
    check("kind 28 MP record: count 64, mask all ones, rec[0/1/3] zero",
          r[4 + 2] == 64 and struct.unpack_from("<Q", r, 8)[0] == (1 << 64) - 1
          and r[4] == r[5] == r[7] == 0 and len(r) == 68)
    check("kind 28 count clamps to 64", mp_points_record(99)[6] == 64)
    # the live uses: readable seqs 3147 / 3151 / 3152 in 0.3 s = 3 uses
    L = UseLedger()
    got = [L.use(1, 0x69320000, 100.0 + d, seq=s)[0]
           for d, s in ((0.0, 3147), (0.074, 3151), (0.284, 3152), (0.5, 3147))]
    check("readable seqs: three distinct uses, the repeated seq is a resend",
          got == [True, True, True, False])
    # the live run: header unreadable, copies at +0.514 / +1.509 / +3.52
    L = UseLedger()
    got = [L.use(1, 0x69320000, 200.0 + d)[0] for d in (0.0, 0.514, 1.509, 3.52)]
    check("unreadable: the resend schedule is ONE use", got == [True, False, False, False])
    check("unreadable: a use off the schedule (+2.5 s) is new",
          L.use(1, 0x69320000, 202.5)[0])
    check("unreadable: another item at a resend offset is new",
          L.use(1, 0x69320006, 200.6)[0])
    # TWIN: the old 10 s window answered only the first of three real uses
    old, seen = [], {}
    for d in (0.0, 0.074, 0.284):
        k = (1, 0x69320000)
        ok = 100.0 + d - seen.get(k, 0.0) >= 10.0
        if ok:
            seen[k] = 100.0 + d
        old.append(ok)
    check("TWIN: the old 10 s window answered 1 of 3 real uses", old == [True, False, False])
    P = MpPoints(amount=10, every=0.5)
    got = [P.credit(1, "b", 2, 10.0 + d) for d in (0.0, 0.1, 0.3, 0.5, 0.6, 1.0)]
    check("MP point: one credit per 0.5 s per point", got == [10, 0, 0, 10, 0, 10])
    check("MP point: another point credits at once", P.credit(1, "b", 3, 10.1) == 10)
    check("MP point: another player credits at once", P.credit(2, "b", 2, 10.1) == 10)
    check("Ether = MP 50 (measured)", ITEM_MP.get(0x69320006) == 50)
    print("doc_items selftest: %s" % ("ALL PASS" if not fails else "FAIL %s" % fails))
    return not fails


if __name__ == "__main__":
    sys.exit(0 if _selftest() else 1)
