"""Arena data read from the user's own files: mission spawns, NPC controllers, team bases and starts, base reports and occupation."""
import os
import struct
from . import gamemsg


# --- the GAME SERVER request / answer ladder (sec 4ea) ------------------------
# [chan+2148] is a STATE, not a flag: 0 = closed, 1 = ready, 2 = a request is
# outstanding and [chan+2152] holds its type.  The client's senders (0x00bc5860
# and siblings) build a 32-byte buffer {u8 130, u8 state, u8 4, u32 handle@4,
# u32 0@8, u16 seq@16, u16 12@18, u16 TYPE@20, u16 session@22, u32 0@24,
# u32 arg@28} and 0x00bc03f8 frames it, so on the wire the body is
# {u16 type, u16 session, u32 0, u32 arg}.  The server->client stubs that put
# [chan+2148] back to 1 are the ANSWERS, type + 1:
#
#   31 -> 32   state/team set (arg byte -> [chan+222]); 32 also queues out 5
#   33 -> 34   (34 queues out 6)
#   36 -> 37
#   47 -> 48   leaveBriefingRoom (native 0x00531830 -> netclient bit 0x20000
#              -> 0x0058b6d0 -> sender 0x00bc6d08)
#   56 -> 57   57 also copies a TEAM LIST into [chan+2156]:
#              body[12] u16, body[14] u16 count (<= 8), body[16] u32, then
#              8-byte entries {u16, u16, u32} from body[20]
#   58 -> 59   59 also adds a userdata entry from [chan+1252]/[chan+1256]
#   60 -> 61   61 also stores body's [s5+8] into [obj+352]
#
# Fire-and-forget from the client: 1 = keepalive every 7 s (answer with our
# own 1, the [chan+224] stamp), 26 = the 1 Hz battle report, 44 = "setup
# received" (sent by the kind-4 handler itself), 30/38/45/53/54/62/64/100 unread.
#
# Server pushes ride message 35, the NOTIFY family: body[12..15] u32 KIND
# (0..54, table 0x00bf2c80), kind-specific payload from body[16] (kind 4 reads
# its record at body[20]).  Named kinds: 2 = battle SPAWN (floats), 3 = restart
# pos, 4 = battle SETUP (the rules record; the client replies with 53),
# 5 = battle START (facade bit 0x80: getBattleInitPos becomes readable),
# 22 = Extinct (entity gone), 27 = NPC control change, 31 = add chara,
# 51 = Reset Mission, 52 = ROUND_INTERVAL_END, 53 = NEW_ROUND_START,
# 54 = QUEST_PHASE.  All of this is emulator-read (doc_gs_battle_proof.py);
# none of it has been seen on a screen.
def load_mission_spawns(path=None):
    """2026-09-23: {zone: {controller id: {count, spawn [[x,y,z]..], ...}}}
    from doc_mission_spawns.json: the mission controllers' spawn nodes out of
    the arena files of patch 20060124_3. That is the game's level data and is
    not shipped here; put a table read out of your own copy beside this
    module. {} when absent (the mission NPCs then have no spawn points)."""
    import json
    path = path or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "doc_mission_spawns.json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


MISSION_SPAWNS = load_mission_spawns()


def npc_controller_payload(ctrl_id, n=None):
    """2026-09-23: notify kind 28's payload naming NPC controller `ctrl_id`.
    The record rides body[20] (payload = 4 pad bytes + record); rec+3 = 3,
    u16 id at rec+12 -> [chan+1324] (sec 4gs add.1). The ids are the arena
    file's table 28 (bzd directory entry 28, 48-byte records, id at +4):
    read from the live mission savestate doc_mission3000_slot03_20260923 --
    z201 carries 1000..1023 (BT), 1100..1123 (TBT), 3000..3005 (missions),
    9000/9001, 9100..9103, i.e. the SITUATION numbering. We always sent id 0,
    which names no controller, so no mission enemy was ever created."""
    rec = bytearray(64)
    # Seen live (fences, no NPCs): the kind-28 arm (retail 0x00bcc128)
    # reads rec[2] = NPC SLOT COUNT (<= 64) and a 64-bit mask at rec+4
    # (0x00bcaf88: slots < count -> [chan+1304] present, mask bits ->
    # [chan+1316]); rec[3] bit0 copies the controller id at rec+12 ->
    # [chan+1324] (0x00bcaf70), bit1 skips the rec[0] 4-byte entry list
    # (0x00bcabd8). Count 0 loaded the controller's objects and no NPC.
    n = max(0, min(64, CONTROLLER_NPCS.get(ctrl_id, 16) if n is None else n))
    rec[2] = n
    struct.pack_into("<Q", rec, 4, (1 << n) - 1)
    rec[3] = 3
    struct.pack_into("<H", rec, 12, ctrl_id & 0xFFFF)
    return bytes(4) + bytes(rec)


#: NPC count per controller (arena bzd table 28, record +8), z201 as read from
#: doc_mission3000_slot03_20260923.p2s. Unlisted ids use 16.
CONTROLLER_NPCS = {3000: 10, 3001: 8, 3002: 4, 9001: 10,
                   9100: 4, 9101: 4, 9102: 16, 9103: 16}
# 2026-09-24 (static RE, retail + proto; not yet live):
# TEAM BASE battles. A base is an ARENA GIMMICK (bzd table 13, type 5), not a
# server object. It is (1) SUPPRESSED at zone load when the table record's
# Base Durability (wire+16) is 0 (retail 0x0066e440 -> zonemgr+688 bit 3),
# (2) created only when the situation's controller (bzd table 28) lists it --
# every 11xx team situation lists exactly its two bases -- and (3) bound to a
# TEAM by notify kind 29 (arm retail 0x00bcc1bc, fill 0x00bcad68, needs
# [chan+2148] == 1), read ONCE at zone setup (0x004ccd90). We sent kind 29
# with a zero record, so no base was ever bound ("I do not see one", live).
# Kind 29 record at body[20]: +1 count (<= 48), +2 bit0 = 0, 16-byte entries
# from +4 {u16 type (1 = team base), u16 team, u16 gimmick instance, ...}.
# Kind 33 (arm retail 0x00bcc2dc): body[16] = the table index, rec+0 = the
# CONTROLLER's chara id (that client owns the base HP and reports it in
# request 24), rec+4 = HP -> what the HUD shows.
#: arena zone -> the two base gimmick instances its 11xx situations list
#: (team 0's first -- INFERRED order); None = no base in that arena.
# LIVE (Jungle, player on team 0 = Ifrit): with (23, 26) the RED base
# (Ifrit's model) was named "Team Shiva's base" -- the order was backwards.
BASE_GIMMICKS = {201: (26, 23), 204: None}
# 2026-09-24 (static RE, table 14 + the 1100 controllers): every arena's base
# list is ordered [g069, g070] and team 0 (Ifrit) is g070 -- the SECOND entry,
# as Jungle proved live. Arenas whose 1100 controller lists NO base get None
# (Kalm used to bind gimmicks 0 / 1, which are not bases there).
BASE_GIMMICKS.update({z: None for z in (203, 205, 207, 208, 209, 210, 211,
                                        217, 231, 233)})
BASE_GIMMICKS_DEFAULT = (1, 0)

# 2026-09-24: TEAM START POINTS. The client never picks a spawn by team (kind 2
# first spawn, kind 25 respawn, both from the server: ev2045.battlefield
# getBattleInitPos / getBattleRestartPos), so each team's point is ours.
# z201 has two type-8 nodes (table 15) next to the bases -- used as-is. Other
# arenas: the team's OWN base (table 14, via the 1100 controller) moved
# TEAM_START_STEP toward the enemy base, at the base's height (INFERRED; not
# checked against the collision floor).
# THE POSITIONS ARE NOT IN THIS FILE. Both tables are the arenas' own level
# data (the base gimmicks' placement and the type-8 start nodes, read out of
# each zone's arena files), so they ship with nothing here: they are read from
# doc_arena_table.json beside this module when that file exists, shaped
#   {"base_positions": {"ZONE": [[x, y, z], [x, y, z]], ...},
#    "team_starts":    {"ZONE": [[x, y, z], [x, y, z]], ...}}
# (base_positions in (g069, g070) order; team_starts as (team 0, team 1)).
# Without it team_start() answers None (the arena spawn is used) and Team Base
# occupation has no spots.
#: zone -> (g069 base, g070 base) world positions
BASE_POSITIONS = {}
#: zone -> (team 0 start, team 1 start) taken straight from the arena data
TEAM_STARTS = {}
ARENA_TABLE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "doc_arena_table.json")


def load_arena_table(path=ARENA_TABLE_PATH):
    """(base positions, team starts) from `path`; ({}, {}) when absent."""
    import json
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return {}, {}

    def pairs(d):
        out = {}
        for z, pts in (d or {}).items():
            try:
                a, b = pts
                out[int(z)] = (tuple(float(v) for v in a),
                               tuple(float(v) for v in b))
            except (TypeError, ValueError):
                continue
        return out
    return pairs(raw.get("base_positions")), pairs(raw.get("team_starts"))


BASE_POSITIONS, TEAM_STARTS = load_arena_table()
TEAM_START_STEP = 150.0


def team_start(zone, team):
    """Team `team`'s start point in arena `zone`, or None (no team data)."""
    if team not in (0, 1):
        return None
    if zone in TEAM_STARTS:
        return TEAM_STARTS[zone][team]
    bp = BASE_POSITIONS.get(zone)
    if bp is None:
        return None
    own, enemy = (bp[1], bp[0]) if team == 0 else (bp[0], bp[1])
    dx, dz = enemy[0] - own[0], enemy[2] - own[2]
    d = (dx * dx + dz * dz) ** 0.5 or 1.0
    step = min(TEAM_START_STEP, d / 3.0)
    return (own[0] + dx / d * step, own[1], own[2] + dz / d * step)
BASE_TYPE_TEAM = 1


def base_gimmicks(zone):
    """The (team 0, team 1) base gimmick instances for arena `zone`, or None."""
    return BASE_GIMMICKS.get(zone, BASE_GIMMICKS_DEFAULT)


def base_objects_payload(gimmicks, teams=(0, 1)):
    """Notify kind 29's payload: one type-1 (team base) entry per gimmick."""
    n = len(gimmicks)
    rec = bytearray(4 + 16 * n)
    rec[1] = n & 0xFF
    for i, (g, team) in enumerate(zip(gimmicks, teams)):
        struct.pack_into("<HHH", rec, 4 + 16 * i, BASE_TYPE_TEAM, team & 0xFFFF,
                         g & 0xFFFF)
    return bytes(4) + bytes(rec)


# LIVE: the controller's request 24 carries the bases, exactly the proto
# builder's layout: count at body+61, then 12-byte entries from body+64 {u32
# HP, u16 index, u16 0, u32 attacker mask}. Jungle: 2 entries, 8000 each; the
# one shot fell 8000 -> 7968 -> 7562 with mask 1 while being hit.
BASE_REPORT_COUNT_OFF, BASE_REPORT_OFF, BASE_REPORT_LEN = 61, 64, 12


def base_report(body):
    """[(index, hp, attacker mask)] from a request-24 body, or []."""
    if body is None or len(body) < BASE_REPORT_OFF:
        return []
    n = body[BASE_REPORT_COUNT_OFF]
    if not 0 < n <= 4 or len(body) < BASE_REPORT_OFF + BASE_REPORT_LEN * n:
        return []
    out = []
    for i in range(n):
        o = BASE_REPORT_OFF + BASE_REPORT_LEN * i
        hp, idx, _z, mask = struct.unpack_from("<IHHI", body, o)
        out.append((idx, hp, mask))
    return out


def base_hp_payload(index, controller, hp):
    """Notify kind 33's payload: table index `index`, its controller, its HP."""
    return (struct.pack("<I", index & 0xFFFFFFFF)
            + struct.pack("<II", controller & 0xFFFFFFFF,
                          max(0, int(hp)) & 0xFFFFFFFF))


# 2026-09-26: TEAM BASE OCCUPATION. SE's January Additional Manual: the team
# that destroys the enemy base and then holds it for a set time wins. After
# the base falls, holding it means standing where the base stood (source:
# April 2006 player blog, the DG Drone 1st exam). The radius and the time
# are OURS (no source prints them; the bzd base gimmick carries no trigger
# radius we have decoded). No client HUD for the hold was found: group 55 has
# only "%s's base has been destroyed!" and the result line "%s's Base
# Captured", and kinds 47/48 are the CAPSULE hold -- so the hold runs on the
# server alone and ends the room with the kind-4 verdict.
BASE_OCCUPY_RADIUS = 100.0      # OURS: horizontal (x/z) distance to the spot
BASE_OCCUPY_S = 10.0            # OURS: seconds of unbroken presence
BASE_POSE_FRESH_S = 2.0         # a 0x83 pose older than this is not "there"


def base_spots(zone):
    """(team 0 base, team 1 base) world positions for arena `zone`, or None.
    BASE_POSITIONS lists (g069, g070) and team 0 owns g070 (see team_start)."""
    bp = BASE_POSITIONS.get(zone)
    return None if bp is None else (bp[1], bp[0])


def base_occupy_tick(room, poses, now, radius=BASE_OCCUPY_RADIUS,
                     hold_s=BASE_OCCUPY_S, fresh_s=BASE_POSE_FRESH_S):
    """Run every destroyed base's occupation. `poses` = {cid: (x, y, z, t)}
    from the members' type-0x83 streams. A living, present member of the
    team that must occupy base i, with a fresh pose within `radius` (x/z) of
    base i's spot, holds it; the hold survives while ANY such member stays
    (the first one keeps the credit), and resets when none is left. `hold_s`
    of unbroken hold ends the room: that team wins, the holder is the
    occupier (the Assault medal). Returns log notes for the changes."""
    notes = []
    if room.over or not room.base_down or room.base_spots is None:
        return notes
    alive = set(room.present()) - set(room.dead_until)
    for idx, team in sorted(room.base_down.items()):
        spot = room.base_spots[idx] if idx < len(room.base_spots) else None
        if spot is None:
            continue
        inside = []
        for m in room.members:
            if m not in alive or room.team_of(m) != team:
                continue
            p = poses.get(m)
            if p is None or now - p[3] > fresh_s:
                continue
            d = ((p[0] - spot[0]) ** 2 + (p[2] - spot[2]) ** 2) ** 0.5
            if d <= radius:
                inside.append((d, m))
        cur = room.occupy.get(idx)
        if not inside:
            if cur is not None:
                room.occupy.pop(idx, None)
                notes.append("team %d's hold on base %d BROKEN after %.1f s "
                             "(nobody on the spot) -- reset"
                             % (team, idx, now - cur[1]))
            continue
        if cur is None:
            cur = room.occupy[idx] = (min(inside)[1], now)
            notes.append("team %d OCCUPYING base %d: 0x%x on the spot "
                         "(%.0f s to hold)" % (team, idx, cur[0], hold_s))
        elif cur[0] not in [m for _d, m in inside]:
            cur = room.occupy[idx] = (min(inside)[1], cur[1])
        if now - cur[1] >= hold_s:
            room.capsule_winner = min(max(team, 0), gamemsg.GS_TEAM_SLOTS - 1)
            room.occupier = cur[0]
            room.over = True
            room.why = ("team %d's base destroyed and occupied by 0x%x"
                        % (idx, cur[0]))
            notes.append("team %d HELD base %d for %.0f s -- WINS (occupier "
                         "0x%x)" % (team, idx, now - cur[1], cur[0]))
            break
    return notes
