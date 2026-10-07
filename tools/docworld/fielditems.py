"""Items on the battlefield: field item notices, capsules (pick-up, drop, hold, scoreboard) and dropped items."""
import struct
import time
import doc_missions
from . import gamemsg


# 2026-09-24 (static RE on the retail client, not yet live): TEAM
# CAPSULE battles. The Mako Capsule is item 0x6B300000 (item-def +12 == 10,
# the "field item" class). The SERVER places it (notify kind 10, arm
# 0x00bcba04: record at body[20] {u32 id, u16 count, u16 slot < 128, u16,
# s16 x, y, z}, integer world units); touching one sends P2P 119 {+20 u32
# slot, +24 u32 1, +28 seq, +32.. f32 pos} and the client waits: kind 11
# (ident = the PICKER, same record) removes it from the field for everyone
# and bags it for the picker ("%s captures a mako capsule!"). A carrier's
# drop (KO) is P2P 118 {+20 u32 item, +24 u32 count, +28 seq, +32.. f32 pos}
# -- already out of its own bag; kind 21 (ident = the dropper) spawns it for
# the others, kind 10 for the dropper. Kind 46 = the scoreboard (body[20..47]
# 7 x u32 holder id, body[48..54] 7 x u8 count), kinds 47 / 48 = the hold
# countdown (10 s, index at body[16]) start / cancel. The client has no
# capsule win test: the server ends it (kind 4 via end_battle).
MAKO_CAPSULE = 0x6B300000
#: the item-id class (id >> 16) of the consumables, Potion .. Ether
#: (doc_items: 0x69320000..0x6932000C); manual p.34 "consumable items"
CONSUMABLE_CLASS = 0x6932
CAPSULE_HOLD_S = 10.0
CAPSULE_RING = 150.0          # OURS: no fixed capsule points found in bzd
CAPSULE_HOLDERS = 7
#: OURS: a carrier's DROP (P2P 118) this soon after its KO was caused by that
#: KO (Capsule Seeker; the drop and request 30 come from the victim's client in
#: no measured order)
CARRIER_DROP_S = 3.0


FIELD_QUIET = 2               # kind 10 body[16] == 2 skips the HUD notice


def field_item_payload(iid, slot, pos, count=1, head=0):
    """Kind 10 / 11 / 21's payload: body[16] u32 `head` (0 = the HUD notice,
    FIELD_QUIET = none; any nonzero value also clears whatever the game had
    in that slot first -- pickup RE 2026-09-26), then the 16-byte record."""
    x, y, z = (max(-32768, min(32767, int(round(v)))) for v in pos)
    return struct.pack("<I", head) + struct.pack("<IHHHhhh", iid & 0xFFFFFFFF, count & 0xFFFF,
                                  slot & 0xFFFF, 0, x, y, z)


def capsule_ring(center, n, radius=CAPSULE_RING):
    """`n` field positions on a ring around `center` (x, y, z)."""
    import math
    cx, cy, cz = center
    return [(cx + radius * math.cos(2 * math.pi * i / max(1, n)), cy,
             cz + radius * math.sin(2 * math.pi * i / max(1, n)))
            for i in range(n)]


def capsule_scoreboard_payload(holders):
    """Kind 46: up to 7 {holder id, count} pairs (holders = {cid: count})."""
    rows = [(c, n) for c, n in sorted(holders.items()) if n > 0][:CAPSULE_HOLDERS]
    ids = [c for c, _ in rows] + [0] * (CAPSULE_HOLDERS - len(rows))
    cnt = [n for _, n in rows] + [0] * (CAPSULE_HOLDERS - len(rows))
    return (bytes(4) + struct.pack("<7I", *[i & 0xFFFFFFFF for i in ids])
            + bytes(min(255, n) for n in cnt))


def p2p_pickup_slot(payload):
    return struct.unpack_from("<I", payload, 0)[0] if len(payload) >= 4 else None


def p2p_drop(payload):
    """(item, count, (x, y, z)) of a 118 payload, or None."""
    if len(payload) < 24:
        return None
    iid, count = struct.unpack_from("<II", payload, 0)
    return iid, count, struct.unpack_from("<fff", payload, 12)


# The capsule RULES, pure (the room holds the state; main() only sends).
# Each returns [(kind, payload, ident, to)] with to = "all" | "self" | "others"
# relative to the acting member, plus a log note.

# 2026-09-26: the field holds ANY item, not only capsules. A capsule entry is
# (id, pos); any other item is (id, pos, count). Every battle gets a field, so
# a player can drop ammo for a teammate (118) and anyone can pick it up (119)
# -- before this, a non-capsule 118 left the dropper's bag and went nowhere.
FIELD_SLOTS = 128               # the client's table [chan+1284] (slot < 128)


def capsule_pickup(room, cid, slot):
    field = room.field
    if field is None or room.over or slot not in field:
        return [], ("ignored (%s)" % ("no capsule field" if field is None else
                                      "battle over" if room.over else
                                      "slot %s empty -- taken" % slot))
    iid, pos, *_rest = field.pop(slot)
    if iid != MAKO_CAPSULE:
        # kind 11, ident = the picker: gone for everyone, bagged by the picker
        count = _rest[0] if _rest else 1
        return ([(11, field_item_payload(iid, slot, pos, count), cid, "all")],
                "PICKED UP slot %d: 0x%08x x%d" % (slot, iid, count))
    room.holders[cid] = room.holders.get(cid, 0) + 1
    room.last_pick = cid
    return ([(11, field_item_payload(iid, slot, pos), cid, "all")],
            "PICKED UP slot %d -> holds %d" % (slot, room.holders[cid]))


def capsule_drop(room, cid, iid, count, pos, now=None):
    field = room.field
    if field is None or room.over:
        return [], "ignored (%s)" % ("no capsule field" if field is None
                                     else "battle over")
    if iid != MAKO_CAPSULE:
        # the item already left the dropper's bag: place it, kind 10 to ALL
        # (ident = the dropper). Not kind 21 to the dropper: that arm cuts
        # the item from the bag a second time (pickup RE, 2026-09-26).
        slot = next((i for i in range(FIELD_SLOTS) if i not in field), None)
        if slot is None:
            return [], "ignored (field full: %d items)" % len(field)
        count = max(1, min(int(count), 0xFFFF))
        field[slot] = (iid, pos, count)
        return ([(10, field_item_payload(iid, slot, pos, count), cid, "all")],
                "DROPPED 0x%08x x%d -> slot %d" % (iid, count, slot))
    held = room.holders.get(cid, 0)
    now = time.time() if now is None else now
    seeker = room.credit_carrier_ko(cid, now) if held else None
    _lk = room.last_ko.get(cid)
    if held and (_lk is None or now - _lk[1] > CARRIER_DROP_S):
        room.carrier_drop[cid] = now        # its request 30 may come next
    count = max(1, min(int(count), held)) if held else max(1, int(count))
    room.holders[cid] = max(0, held - count)
    out = []
    for _ in range(count):
        slot = next((i for i in range(FIELD_SLOTS) if i not in field), None)
        if slot is None:
            break
        field[slot] = (iid, pos)
        pl = field_item_payload(iid, slot, pos)
        out.append((10, pl, cid, "self"))      # it left its bag already
        out.append((21, pl, cid, "others"))    # spawns it for everyone else
    return out, "DROPPED %d -> holds %d%s" % (
        count, room.holders[cid],
        " (KO'd by 0x%x: a carrier KO, Capsule Seeker)" % seeker
        if seeker is not None else "")


def capsule_ko_drop(room, victim, pos):
    """2026-10-06: a carrier's KO drops every capsule it holds. The client
    never does it: P2P 118 is only the item menu's Drop (builder 0x00BEE4E0,
    sole caller chain 0x004A38C8 command 3), so a KO'd carrier kept them
    (live, Jungle). PROVEN by running the retail arm 0x00BCBED4 (scratchpad
    re-capdrop/): kind 21 with ident == the receiver cuts the item from its
    bag once and spawns it, but skips the channel's field table; kind 10
    registers that table. So: 21 then a quiet 10 to the victim, 10 to the
    others, one slot per capsule. Returns ([(kind, payload, ident, to)], note)."""
    field = room.field
    held = room.holders.get(victim, 0)
    if field is None or room.over or held <= 0 or pos is None:
        return [], None
    out = []
    n = 0
    for _ in range(held):
        slot = next((i for i in range(FIELD_SLOTS) if i not in field), None)
        if slot is None:
            break
        field[slot] = (MAKO_CAPSULE, tuple(pos))
        out.append((21, field_item_payload(MAKO_CAPSULE, slot, pos), victim, "self"))
        out.append((10, field_item_payload(MAKO_CAPSULE, slot, pos, head=FIELD_QUIET),
                    victim, "self"))
        out.append((10, field_item_payload(MAKO_CAPSULE, slot, pos), victim, "others"))
        n += 1
    room.holders[victim] = held - n
    return out, "KO'd carrier DROPPED %d capsule(s) at %s -> holds %d" % (
        n, tuple(round(v) for v in pos), room.holders[victim])


def capsule_hold(room, now):
    """The scoreboard, then the hold: a team holding every capsule starts the
    countdown (47); losing one cancels it (48)."""
    out = [(46, capsule_scoreboard_payload(room.holders), 0, "all")]
    n = room.rules.capsules
    per = {}
    for c, k in room.holders.items():
        per[room.team_of(c)] = per.get(room.team_of(c), 0) + k
    full = [tm for tm, k in per.items() if k >= n > 0]
    note = ""
    if full and room.cap_hold is None:
        room.cap_hold = (full[0], now + CAPSULE_HOLD_S)
        room.cap_last = room.last_pick
        out.append((47, struct.pack("<I", full[0] & 0xFFFFFFFF), 0, "all"))
        note = "team %d holds all %d -- %.0f s hold (47)" % (full[0], n, CAPSULE_HOLD_S)
    elif room.cap_hold is not None and room.cap_hold[0] not in full:
        out.append((48, struct.pack("<I", room.cap_hold[0] & 0xFFFFFFFF), 0, "all"))
        note = "team %d lost a capsule -- hold CANCELLED (48)" % room.cap_hold[0]
        room.cap_hold = None
        room.cap_last = None
    return out, note


def capsule_count(room):
    """How many capsules `room`'s field gets: a TEAM CAPSULE table's record
    count, a capsule MISSION's (doc_missions.capsule_setup), else 0."""
    if room is None:
        return 0
    if room.mission is not None:
        cs = doc_missions.capsule_setup(room.mission)
        return cs[0] if cs else 0
    if room.rules.mode == "TCP":
        return max(0, room.rules.capsules)
    return 0


def capsule_mission_check(room):
    """A capsule MISSION: the players (co-op, all of them together) hold its
    target -> the room is over with the objective. Returns a log note."""
    if room.mission is None or room.over:
        return ""
    held = sum(room.holders.values())
    if doc_missions.capsules_end(room.mission, held):
        room.over = True
        room.why = "%s: %d Mako Capsule(s) collected" % (
            doc_missions.WHY_OBJECTIVE, held)
        return "mission target reached (%d held)" % held
    return "mission: %d held" % held


def capsule_hold_done(room, now):
    """True (and the winner set) when a running hold has lasted."""
    if room.cap_hold is None or room.over or now < room.cap_hold[1]:
        return False
    room.capsule_winner = min(max(room.cap_hold[0], 0), gamemsg.GS_TEAM_SLOTS - 1)
    room.last_capsule = room.cap_last
    return True
