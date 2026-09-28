"""The game-server channel (inner type 130): the request/answer ladder, the notify kinds and their builders."""
import math
import struct
from . import framing, worldchannel



def build_gs_stats(entries=(), state=1, seq=0, ident=0):
    """Game-server message 27 -- a REWARD GRANT: (item id, quantity) pairs.

    WARNING: RETRACTED: this was first read as a stat/medal tally, on the strength of
    the Status screen's Medals page appearing right after we started sending it.
    It is not. Sending keys 16/17/18 with 4444/5555/6666 put THREE CHAT LINES on
    the account holder's screen --

        You obtain ??id?? x4444.
        You obtain ??id?? x5555.
        You obtain ??id?? x6666.

    -- which is msgid 0x9c29, `You obtain %s x%d.`, printed once per entry by the
    loop at 0x00ad93f8: `a3 = [array+8+8i]` (the ITEM ID) and `t1 =
    [array+12+8i]` (the QUANTITY), straight out of what this message writes. So
    the KEY is an ITEM ID and the AMOUNT is a quantity.

    WARNING: `??id??` is the string table's OTHER sentinel -- group 0 entry 6, the
    ITEM-name-by-id failure, distinct from `!!na!!` (group 0 entry 0). So 16, 17
    and 18 are not valid item ids. The valid id space is NOT decoded; item names
    live in their own table around 0x01fe4c00-0x01fe61ec, not in KelStr, and
    `--find` does not see them.

    WARNING: And the grant ANNOUNCES without DELIVERING: nothing appeared in the
    items screen. Either the ids have to be real, or the inventory add is a
    separate message.

    The rest below still holds -- the wire format, the destination, and the
    accumulation -- because those were measured rather than inferred.

    This is the only wire path found so far into the LOCAL profile record, the
    object `0x00bdd960` copies from and the Status screen renders. The user-list
    record cannot reach it; this can:

        msg 27 -> 0x00bc1458 -> 0x00bdeef8(userdata, entry)
                             -> 0x00be6b20(userdata + 304, entry)

    and `userdata + 304` IS that record.

    THE BODY, in docudp's body[] terms (record+20.. == wire+24.. == body[0]..):

        body[0..1]     u16  = 27
        body[12]       u8   COUNT, clamped to 6 by the handler
        body[13]       u8   STATE: bit 0 -> [array+0] = 1, bit 1 -> 2, else 0
        body[16+8i]    u32  KEY
        body[20+8i]    u16  AMOUNT
        (stride 8, i < COUNT)

    `0x00be6b20` keeps a tally at `record+868` with its count at `record+800`,
    up to 256 keys: a key already present has the amount ADDED to it, otherwise
    the pair is appended. So amounts ACCUMULATE across messages -- sending the
    same message twice doubles it.

    WARNING: The body must still be >= 13 bytes for the handler to run at all, and a
    COUNT of 0 skips the entry loop entirely while still writing `[array+0]` and
    `[array+4]`. That is what we shipped first, and the Status screen's Rank
    Points went from 0 to -1 -- our own empty tally, observed live.

    WARNING: The KEY SPACE IS NOT DECODED. Which key drives which row is exactly what a
    sweep has to find, and the amounts accumulate, so a sweep is not free.
    """
    n = min(len(entries), 6)
    body = bytearray(16 + 8 * max(n, 6))
    struct.pack_into("<H", body, 0, GS_ARM_MSG)
    body[12] = n
    body[13] = state & 0xFF
    for i, (key, amount) in enumerate(list(entries)[:6]):
        struct.pack_into("<I", body, 16 + 8 * i, key & 0xFFFFFFFF)
        struct.pack_into("<H", body, 20 + 8 * i, amount & 0xFFFF)
    return build_gs_message(GS_ARM_MSG, seq=seq, ident=ident,
                            body_extra=bytes(body[4:]))


# --- the GAME SERVER channel, inner type 130 (sec 4cq) ------------------------
GS_INNER_TYPE = 130
GS_MSG_MAX = 61
GS_ARM_MSG = 27           # the only message that sets [chan+204] bit 6
GS_ARM_MIN_BODY = 13      # 0x00bc1458 bails if [msg+18] < 13
GS_KEEPALIVE_MSG = 29     # its table entry IS the shared epilogue -- a true no-op
GS_REVIVE_REQ = 43      # 2026-09-23: the client's ACK of a kind-9 kill notice (not an item)
GS_ITEM_USE_REQ = 21      # 2026-09-23: USE ITEM (item id at body+8) -> message 22
# 2026-09-24: MAGIC CAST. The cast 0x006b87d0 -> shot sender 0x00be9500 sees a
# magic flags word ((flags >> 3) & 7 = element) and calls 0x00bc7928: request
# 60 {u16 60, u16 session, u32 0, u32 arg = element | level << 16}, marked
# outstanding. The answer 61 (handler 0x00bc5358) clears the outstanding flag
# and, when body+4 (status) >= 0, stores body+8 as the self CURRENT MP (R+48 ->
# chara+36 each frame); the cast gate 0x006b7d70 needs chara+36 >= the spell's
# cost. Our old answer was the zero 61 = MP 0 after the first cast, and nothing
# else refills it (only kinds 2 / 51 / 44 / 34 write R+48). Emulated on the
# arena state: zeros -> 100 -> 0, body+8 = 70 -> 70 (an offline run of the client's own code (doc_magic_mp_proof)).
GS_MAGIC_REQ = 60
GS_MAGIC_ANS = 61
GS_REQ_ANSWERS = {31: 32, 33: 34, 36: 37, 47: 48, 56: 57, 58: 59, 60: 61,
                  # sec 4he: 38 -> 39 (arm 0x00bc5174: body[4] >= 0 posts
                  # facade 0x400, ev2045's reload-and-respawn path), 45 -> 46
                  # and 54 -> 55 (0x00bc5214: body[4] < 0 would KICK with an
                  # error; zero is the plain epilogue)
                  38: 39, 45: 46, 54: 55, 46: 47}
# request 46 = a character STATUS-BIT change (engine
# interface vt+68 / vt+76 -> builder 0x00bce5d8). The client marks a request
# outstanding ([chan+2136] = 2) and message 47 (handler 0x00bccd3c) is what sets
# it back to 1. Unanswered, every revive left the channel stuck and the player
# INVINCIBLE (kind 18 and 19 alike).
# sec 4he: the client's REAL request builders are 1, 21, 24, 25, 26, 30, 31,
# 33, 36, 38, 42, 43, 44, 45, 47, 53, 54, 56, 58, 60, 62, 64, 100.
# The "queue reply 4/5/6/9.." names an earlier reading gave 0x00bc31b0 were
# HUD EVENT numbers (it feeds the battle HUD 0x00ad9380, not the wire).
GS_REQ_NAMES = {1: "keepalive", 24: "1 Hz battle report (needs kind 3)",
                26: "req 26 (no caller)", 30: "KILL REPORT {killer, victim}",
                31: "team/state set", 33: "req 33", 36: "req 36",
                38: "P2P respawn / control request (39: body[4] >= 0)",
                42: "req 42", 43: "kill-notice ack (kind 9 arm)",
                44: "item-use counts (kind-4 reply, no answer)",
                45: "leave / exit (46)",
                47: "leaveBriefingRoom", 53: "ack of kind 36",
                54: "kelsvc vt+732 (55: body[4] < 0 = error kick)", 56: "req 56",
                58: "req 58 (item)", 60: "req 60",
                62: "NPC control SET", 64: "NPC control CLEAR", 100: "req 100"}
GS_NOTIFY_MSG = 35
GS_NOTIFY_NAMES = {2: "battle spawn", 3: "restart pos", 4: "battle SETUP",
                   5: "battle START", 22: "extinct", 27: "npc control",
                   31: "add chara", 51: "reset mission", 52: "round interval end",
                   53: "new round start", 54: "quest phase"}
GS_SETUP_LEN = 400        # kind 4 reads up to record+333; a zero record is the
                          # conservative "no rules, no npcs" (0x00bc1760)
GS_LEAVE_BRIEFING = 47
GS_READY_ROSTER_OFF = 132  # selector 38: 28-byte roster entries from body[132]
GS_READY_ROSTER_STRIDE = 28
GS_READY_SESSION_OFF = 36  # selector 38: u16 session id -> [chan+220]
GS_READY_COUNT_OFF = 40    # selector 38: u16 roster count (<= 32)
GS_READY_KIND_OFF = 6      # selector 38: u16; 2 -> [chan+204] = 0x800 + facade 0x4000


def gs_request_type(data, inner):
    """(message type, body) of an inbound type-130 datagram, or (None, None)."""
    body = worldchannel.request_body(data, inner)
    if body is None or len(body) < 2:
        return None, body
    return struct.unpack_from("<H", body, 0)[0], body


def build_gs_notify(kind, payload=b"", seq=0, ident=0, flags=0x01):
    """Message 35 carrying notify KIND at body[12..15] and `payload` from
    body[16].  The dispatcher 0x00bc3918 reads the kind as a u32 at
    datagram+36 (== body[12]) and jumps through 0x00bf2c80 (55 arms)."""
    extra = bytes(8) + struct.pack("<I", kind & 0xFFFFFFFF) + bytes(payload)
    return build_gs_message(GS_NOTIFY_MSG, seq=seq, body_extra=extra,
                            flags=flags, ident=ident)


def build_gs_team_list(entries=(), seq=0, ident=0, word12=0, word16=0):
    """Message 57: the answer to 56, plus the team list its stub copies into
    [chan+2156] -- body[12] u16, body[14] count (clamped to 8), body[16] u32,
    then 8-byte entries {u16 a, u16 b, u32 c} from body[20]."""
    ents = list(entries)[:8]
    extra = bytearray(16 + 8 * len(ents))
    struct.pack_into("<H", extra, 8, word12 & 0xFFFF)
    struct.pack_into("<H", extra, 10, len(ents))
    struct.pack_into("<I", extra, 12, word16 & 0xFFFFFFFF)
    for i, (a_, b_, c_) in enumerate(ents):
        struct.pack_into("<HHI", extra, 16 + 8 * i, a_ & 0xFFFF, b_ & 0xFFFF,
                         c_ & 0xFFFFFFFF)
    return build_gs_message(57, seq=seq, body_extra=bytes(extra), ident=ident)


GS_SPAWN_MAP_OFF = 24     # kind-2 record +24/+25 -> [chan+1092/1093] = map0/map1
GS_SPAWN_ZONE_OFF = 26    # kind-2 record +26 -> [chan+1064] = THE ARENA ZONE
GS_TEAM_NONE = 15         # request-31 args >= this are "no team" (255 = none)


def build_gs_spawn(x, y, z, rot=0.0, seq=0, ident=0, zone=0, bmap=(0, 0)):
    """Notify kind 2: the battle spawn.  0x00bc2800 reads floats at record
    +4/+8 (-> [chan+1072/1076]), +12/+16/+20 (-> [chan+1080..1088]) and bytes
    +24/+25/+26, record == body[20] (the same base kind 4 uses).  Which float
    is which axis is NOT read -- the proof only pins that they land.

    KEY: sec 4ft (static, 2026-09-13): byte +26 IS THE ARENA ZONE NUMBER. The
    arm does `sb rec[26] -> [chan+1064]` and `[chan+204] |= 4`, and the ONLY
    readers are the getters behind KerberosNetLobby.get_onlinezone():
    0x0058d7c8 returns [chan+1064] (zone), 0x0058d558 returns map0/map1 --
    [chan+1092/1093] = rec+24/+25, or once facade 0x80 (kind 5) is up the
    table-record copy [chan+1120/1121]. vl_main runs, after the distribution
    window: leaveBriefingRoom() -> get_onlinezone(false) -> KerberosZone.
    exit(zone), and get_onlinezone turns zone 0 into exit(-1) = THE TITLE.
    That is the sec 4ee/4el "OK -> title": we served zone 0. The only other
    writer of [chan+1064] is notify kind 36 (record +1), which we never send.

    KEY: sec 4ga (static + live PINE, 2026-09-13): the LAYOUT. The arm copies
    rec+0..23 to [chan+1068..1091]; getBattleInitPos = get_battle_pos_{x,y,z}_l
    -> 0x00507e00 -> vt+124 0x0058d308, which returns that block's +0/+4/+8 as
    the POSITION, and get_battle_rot_l (0x00507d90) = atan2(+12, +20), a
    FACING vector. We used to write x,y,z at +12..20 (the facing) and rot at
    +4 (the y). `rot` is in degrees -> facing (sin, 0, cos).
    WARNING: Once facade 0x80 (kind 5) is up the getter reads [chan+1096..] instead,
    a copy of the player's OWN record taken at kind-2 time (live: the
    briefing-room spot 2005.5, -10.5, -118.8) -- so kind 5 must arrive AFTER
    ev2045.battlefield has read the spawn (--gs-battle-go-after)."""
    rec = bytearray(32)
    struct.pack_into("<fff", rec, 0, x, y, z)
    _r = math.radians(rot)
    struct.pack_into("<fff", rec, 12, math.sin(_r), 0.0, math.cos(_r))
    rec[GS_SPAWN_MAP_OFF] = bmap[0] & 0xFF
    rec[GS_SPAWN_MAP_OFF + 1] = bmap[1] & 0xFF
    rec[GS_SPAWN_ZONE_OFF] = zone & 0xFF
    return build_gs_notify(2, bytes(4) + bytes(rec), seq=seq, ident=ident)


GS_DOWN_KIND = 25      # 2026-09-23: "down, respawn point" (retail 0x00bcbfa4)
GS_REVIVE_KIND = 13    # 2026-09-23: the respawn revive (retail 0x00bcbbc4)


def build_gs_down(x, y, z, rot=0.0, bmap=(0, 0), seq=0, ident=0, ammo=()):
    """Notify kind 25: a KO'd character is DOWN and will respawn here.

    Retail arm 0x00bcbfa4, read 2026-09-23 from doc_mission3001_slot06. For the
    receiver's OWN character (ident == [chan+0xd8]) it writes the respawn
    block -- payload[6]/[7] -> [chan+1092/1093] (map0/map1, the same bytes
    kind 2 carries), s16 payload[8..13] -> [chan+1068..1076] (position),
    s16 payload[14..19] -> [chan+1080..1088] (facing) -- then SETS the battle
    object's dead bits 0x2000 and 0x400 (0x00599700), and for every character
    pushes action code 25 (state word entry+0x56 := 2). Kind 13 revives only
    a character whose dead bits are BOTH set, so kind 25 must come first.

    2026-09-26: `ammo` = the RESPAWN REFILL, up to 3 (item, qty). For its own
    character the arm hands payload[20..43] (body[36..], `addiu a1, s1, 24`
    at 0x00bc4258) to 0x00be3200 -> 0x00be7de8: 3 x {u32 id, u16 0, u16 qty},
    a zero id ends it, and each qty is SET into the bag (R+868 entry +6, or
    appended); a change raises R+92 bit 0x200000, which rebuilds the arena
    inventory from the bag and reloads the gun (0x00bf0d70 -> 0x00bebd98).
    Proven by execution (doc_ammo_refill_proof). Our old 20-byte payload
    left it empty, so a death never gave ammo back."""
    _r = math.radians(rot)
    ammo = list(ammo)[:3]
    pay = bytearray(20 + (24 if ammo else 0))
    for i, (iid, qty) in enumerate(ammo):
        struct.pack_into("<IHH", pay, 20 + 8 * i, iid & 0xFFFFFFFF, 0,
                         min(qty, 0xFFFF))
    pay[6] = bmap[0] & 0xFF
    pay[7] = bmap[1] & 0xFF

    def clamp(v):
        return max(-32768, min(32767, int(round(v))))
    struct.pack_into("<hhh", pay, 8, clamp(x), clamp(y), clamp(z))
    struct.pack_into("<hhh", pay, 14, clamp(1000 * math.sin(_r)), 0,
                     clamp(1000 * math.cos(_r)))
    return build_gs_notify(GS_DOWN_KIND, bytes(pay), seq=seq, ident=ident)


GS_KILL_EVENT = 9         # notify kind 9: team points + killer + victim
GS_KILL_REQ = 30          # request 30 {killer @body+8, victim @hdr+8, 0 = self}
GS_RESPAWN_KIND = 13      # notify 13: self respawn, HP = max
GS_RESTART_POS_KIND = 3   # notify 3: restart position + [chan+204] |= 0x20
GS_DAMAGE_GATE_KIND = 30  # notify 30: facade |= 0x30 -- the 113 receive gate
GS_PLAYER_LEFT_KIND = 8   # notify 8: a member left the battle
GS_TEAM_SLOTS = 4         # [chan+1340..1347]: four u16 team point slots


def build_gs_kill_event(points, killer, victim, last_one=False, seq9=0,
                        seq=0, ident=0):
    """Notify kind 9 (arm 0x00bc2010, sec 4he): the SCORE message. Record:
    +0..7 four u16 team points -> [chan+1340..1347] (what getCurrentTeamPoint
    and the HUD's 'Team Ifrit N  Team Shiva N' read), +8 u32 killer, +12 u32
    victim, +16 u8, +17 s8 (HUD event 19 when set), +18 bit 0 = 'one kill from
    the target' (HUD 11), +19 u8 sequence. The arm bumps the local kill /
    death counters by comparing killer / victim with the client's own id."""
    rec = bytearray(24)
    for i in range(GS_TEAM_SLOTS):
        struct.pack_into("<H", rec, 2 * i,
                         max(0, min(int(points[i] if i < len(points) else 0),
                                    0xFFFF)))
    struct.pack_into("<II", rec, 8, killer & 0xFFFFFFFF, victim & 0xFFFFFFFF)
    rec[18] = 1 if last_one else 0
    rec[19] = seq9 & 0xFF
    return build_gs_notify(GS_KILL_EVENT, bytes(4) + bytes(rec), seq=seq,
                           ident=ident)


def mission_npc_report(data):
    """2026-09-23: the 1 Hz report (request 24) read WITHOUT its header.
    [(npc id, hp), ...] or None. The controlling client lists every entity it
    controls: count u8 at datagram[87], then 12-byte entries from datagram+88
    {u32 id, u16 HP, s16 x, s16 y, s16 z} (builder 0x00bc8670 / snapshot
    0x00be1e30; measured live on a 184-byte report, 8 robot dogs at HP 100).
    Recognised by its LENGTH (88 + 12 n): the type word is enciphered on the
    longer reports and this rig's game-server key changes per boot, so the
    header is often unreadable while this part is plaintext."""
    if data is None or len(data) < 88 or data[1] != 4:
        return None
    n = data[87]
    if len(data) == 88 + 12 * n + 8:
        # 2026-09-28: some reports carry one 8-byte trailer
        # after the list ({u32 ammo item, u32 count}); they were dropped and
        # a kill was counted a report or two late. Only NPC ids (bit 30)
        # make one of these a report.
        out = [struct.unpack_from("<IH", data, 88 + 12 * k) for k in range(n)]
        return out if n and all(i & 0x40000000 for i, _h in out) else None
    if len(data) != 88 + 12 * n:
        return None
    return [struct.unpack_from("<IH", data, 88 + 12 * k) for k in range(n)]


#: 2026-09-28: a mission NPC's kind 27 (control -> the player) goes out this
#: long after its Add Npc (kind 15), so the two never land in one client frame.
MISSION_CTL_GAP_S = 0.3
#: ...and is sent again when the NPC is still missing from the player's 1 Hz
#: report this long after, up to MISSION_CTL_TRIES sends in all.
MISSION_CTL_CHECK_S = 3.0
MISSION_CTL_TRIES = 4


def gs_kill_report(inner, body):
    """(killer, victim) of a game-server request 30 (sender 0x00bc5660,
    layout 0x0058a3c8, sec 4he): the KILLER is the body's u32 arg at body+8
    (wire+32); the VICTIM rides the inner header's second word, wire+20 =
    inner["u32_20"] (the wrapper 0x00bc57ec substitutes the sender's own id
    for 0, so it is never 0 on the wire). `body` is what gs_request_type()
    returns (wire+24..)."""
    if body is None or len(body) < 12 or inner is None:
        return None
    killer = struct.unpack_from("<I", body, 8)[0]
    victim = inner.get("u32_20", 0) or inner.get("u32_16", 0)
    return killer, victim


def build_gs_team_set(ident, team, slot=0, seq=0):
    """Notify kind 0 = Set Team ID: the entity is the message IDENT (record+4),
    the team is the u16 at body[16]; the arm 0x00bc39bc first looks the entity
    up in the client's battle roster [chan+2144] and bails if absent."""
    return build_gs_notify(0, struct.pack("<H", team & 0xFFFF) + bytes(2),
                           seq=seq, ident=ident)


def build_gs_team_leave(ident, seq=0):
    """Notify kind 1 = the entity (message IDENT) leaves its team: Set Team
    with no new team, so its row counts down. The answer to a leaveTeam (request 33)."""
    return build_gs_notify(1, bytes(4), seq=seq, ident=ident)


def build_gs_add_chara(ident, team, slot=0, seq=0, self_ident=0):
    """Notify kind 31 = add chara: record at body[20]: +0 u32 id, +16 u32,
    +20 u16, +22 byte = TEAM in the HIGH nibble (15 = none -> 0xff) and the
    roster SLOT in the LOW nibble, +23 bit0 -> 0x00bc35a8.  Own id is skipped
    by the arm (0x00bc4514).
    WARNING: the byte is TEAM high, SLOT low; packed the other way round,
    "team 1" writes roster slot 1 over the client's OWN entry. And the arm pre-sets the member's team
    before Set Team runs, so a kind 31 with a team never moves a count: send
    team=None here (0xF) and a kind 0 after it for the team."""
    rec = bytearray(48)
    struct.pack_into("<I", rec, 0, ident & 0xFFFFFFFF)
    t = 0xF if team is None else (team & 0xF)
    rec[22] = (t << 4) | (slot & 0xF)
    return build_gs_notify(31, bytes(4) + bytes(rec), seq=seq, ident=self_ident)


def build_gs_distribution(entries, seq=0, ident=0):
    """Notify kind 20 = the PLAYER DISTRIBUTION ("Player distribution has been
    determined"): u8 count at body[20] (<= 32), then 8-byte entries from
    body[24]: {u32 character id @0, u8 team @4, u8 slot @5}.  The arm
    0x00bc23d8 posts facade 0x1000, calls the team setter 0x00bd4218 for
    every id -- INCLUDING the client's own, which is how the own team and the
    HUD count get set (kinds 31/0 skip self) -- stores own team in [chan+222]
    and own index in [chan+16], and writes every id into the battle roster
    [chan+2144] at its slot.  Team numbering as the client sent in request 31
    (0 = Ifrit); 255 = none."""
    ents = list(entries)[:32]
    payload = bytearray(8 + 8 * len(ents))
    payload[4] = len(ents)
    for i, (cid, team, slot) in enumerate(ents):
        struct.pack_into("<I", payload, 8 + 8 * i, cid & 0xFFFFFFFF)
        payload[8 + 8 * i + 4] = team & 0xFF
        payload[8 + 8 * i + 5] = slot & 0xFF
    return build_gs_notify(20, bytes(payload), seq=seq, ident=ident)


def build_magic_answer(mp, seq=0, ident=0):
    """Message 61 for a request 60: body+4 status 0 (a negative one would deny
    the cast and leave MP alone), body+8 = the new current MP."""
    return build_gs_message(GS_MAGIC_ANS, seq=seq, ident=ident,
                            body_extra=struct.pack("<iI", 0, max(0, int(mp))))


def build_item_use_answer(item, seq=0, ident=0):
    """2026-09-26: message 22 for a request 21 -- body+8 = the item whose
    effect the unit named by `ident` plays (arm 0x00bc503c -> receiveUseItem,
    tools/doc_items.py). body+4 is not read."""
    return build_gs_message(22, seq=seq, ident=ident,
                            body_extra=bytes(4) + struct.pack("<I", item & 0xFFFFFFFF))


GS_MP_KIND = 44


def build_gs_mp_push(mp, full_hp=False, seq=0, ident=0):
    """Notify kind 44 (handler 0x00bc4924): the u32 at body[16] -- HIGH 16 bits
    = the new current MP (always written), low 16 nonzero = also HP to max
    (0x00bdf790, only while HP != 0). Emulated: {90 << 16} MP -> 90, HP kept."""
    return build_gs_notify(GS_MP_KIND,
                           struct.pack("<I", ((max(0, int(mp)) & 0xFFFF) << 16)
                                       | (1 if full_hp else 0)),
                           seq=seq, ident=ident)


def build_gs_message(mtype, seq=0, body_extra=b"", flags=0x01, ident=0,
                     mode_byte=0):
    """One application message on the GAME SERVER channel.

    The channel is 0x009f2b40, its receive handler is 0x00bc4e98, and it is the
    one the item/stat manager feeds from -- `init item number -1` is that
    manager finding the channel unconnected (sec 4cd). CER-48101 is the client
    asking to retry a handshake on it.

    THE FRAMING, measured with an offline run of the client's own code (doc_wire_record_map) rather than read:
    0x0058a0b0 scatters the datagram into a RECORD before 0x00581384 dispatches,
    and the scatter is

        record+16..17  <- wire +14..15   the seq checked against [chan+212]
        record+20..    <- wire +24..     the body, 1:1

    so the u16 message TYPE goes at **body[0]** and the sequence the channel's
    reliable window uses is the FRAMEWORK inner-header seq -- the same field
    every other message here already carries. WARNING: There is no second sequence
    inside the body; an earlier reading of mine put the type at wire+28 and it
    was wrong.

    Proven in an offline run of the client's own code (doc_gsreply_proof): with --gs-connect done first, all
    61 types are ACCEPTED by the client's own handler and all 18 with a real
    handler run. 43 of the 61 share a do-nothing epilogue, so a sweep is safe.

    WARNING: The BODY FORMAT of each message is NOT decoded. This sends the type and
    zeros. That is enough to ask "does any game-server traffic quiet CER-48101",
    which is a different question from "is the payload right".

    WARNING:KEY: CER-48101 IS A 40-SECOND GAME-SERVER TIMEOUT, AND SENDING IS PROBABLY
    NOT ENOUGH TO CLEAR IT (sec 4cq). The client says so itself, one line before
    the error in the emulog: `timeout gameserver 40006`. The check is 0x00bc10d4:

        if ([chan+12] < now_ms() - [chan+224]) -> timeout    ; [chan+12] == 40000

    so `[chan+224]` is a LAST-HEARD stamp, and 0x00bc4e98 refreshes it at
    0x00bc4f40 only after THREE gates:

        (flags & 0x08) == 0  &&  (flags & 0x01) != 0  &&  ([chan+204] & 0x40) != 0

    WARNING:WARNING: Measured offline after a full --gs-connect: **`[chan+204]` is 0**, so the
    third gate fails and NO flags value refreshes the stamp -- the message is
    accepted, dispatched, and the 40 s clock keeps running. That is sec 4cf's
    shape again: the arm accepts and the thing you wanted does not happen.
    0x00bc0260 (what selector 38 reaches) writes [chan+204] = 0 or 0x800, never
    0x40, and nothing in the overlay stores that bit with a literal.

    VERIFIED:KEY: SOLVED -- bit 6 is set by MESSAGE 27 WITH A BODY OF >= 13 BYTES.
    0x00bc1458 (message 27's handler) opens with

        if ([msg+18] < 13) return               ; [msg+18] is the BODY LENGTH
        if (([chan+204] & 0x40) == 0) {
            0x00bc4d90(chan, [msg+16]) ; [chan+204] |= 0x40   ; 0x00bc14bc
        }

    and it is the ONLY site in the whole binary that ORs 0x40 into that field.
    So the full recipe, each step measured in doc_gsreply_proof.py:

        1. --gs-connect            selector 104 + 38  -> endpoint + ready flag
        2. message 27, body >= 13  -> [chan+204] |= 0x40      ARMS the channel
        3. any message thereafter  -> [chan+224] = now_ms()   REFRESHES the stamp

    WARNING: The arming message itself does NOT refresh the stamp: 0x00bc4e98 tests bit
    6 BEFORE dispatching to the handler that sets it, so the first message always
    falls through. It takes two. And without step 2 no number of other messages
    ever refreshes it -- measured: message 42 twice leaves [chan+204] at 0.
    WARNING: A body of 4 (the type alone) fails the length gate silently.
    """
    body = bytearray(4 + len(body_extra))
    struct.pack_into("<H", body, 0, mtype & 0xFFFF)
    body[4:] = body_extra
    mid = bytearray(16)
    mid[0] = GS_INNER_TYPE
    mid[1] = flags & 0xFF
    struct.pack_into("<H", mid, 6, seq & 0xFFFF)
    struct.pack_into("<I", mid, 8, ident & 0xFFFFFFFF)
    pkt = bytearray([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", 0)
    pkt += struct.pack("<I", framing.now_ms() & 0xFFFF)
    pkt += mid + body
    struct.pack_into("<H", pkt, 2, len(pkt))
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(pkt))
    return bytes(pkt)
