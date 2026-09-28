"""Maps and places: the lobby spawn descriptor and map-picker mask (selector 13), the lobby zone, and which arena zone, pieces and spawn each map uses."""

WORLD_SPAWN_SELECTOR_ANS = 13  # phase 30's answer -- and it carries the SPAWN

# The lobby spawn descriptor, proven by running the client's own parser + demux +
# arm over a marked body (an offline run of the client's own code (doc_spawn_body_proof), sec 4dh).  Selector
# 13's arm 0x00bca868 reads these BODY offsets and stores a 28-byte descriptor to
# [0x009f3b80 + 3232], which is what `KerberosNetLobby.getLobbyInitPos()` returns
# to the zone script.  We have always shipped this region as zeros, and that is
# the p(0,0,0) spawn.
SPAWN_OFF_X     = 28      # float32 LE
SPAWN_OFF_Y     = 32
SPAWN_OFF_Z     = 36
SPAWN_OFF_DIR_X = 40
SPAWN_OFF_DIR_Y = 44
SPAWN_OFF_DIR_Z = 48
SPAWN_OFF_INDEX = 52      # two BYTE stores: body[52] low, body[53] high

# KEY: THE MAP-PICKER MASK -- the same selector-13 answer, eight bytes further on.
# (sec 4gv, 2026-09-22.  an offline run of the client's own code (doc_mapmask_proof) re-derives every address
# below out of whatever image you hand it and REFUSES on one it cannot pin.)
#
# The battletable config screen's `Map` row built an EMPTY list for ten days
# while every other row on the same screen worked.  It is not the row, not the
# label, not a request we failed to answer -- opening it sends nothing.  The
# picker's populate function takes its candidates from a 28-entry roster of
# {label msgid, help msgid} records, and for THE MAP ROW ONLY it first asks the
# lobby service for a 64-bit "which maps may this player pick" bitmask:
#
#     if (row.kind == 1)  mask = lobby_service.get_map_mask()   # 8 bytes
#     else                mask = ff ff ff ff ff ff ff ff        # all allowed
#     for (i = 0; roster[i].label; i++)
#         if (i < 64 && (mask[i >> 5] & (1 << (i & 31))))
#             add_row(roster[i])                     # ...otherwise SKIPPED
#
# so a zero mask builds a list with zero rows, and it can only ever affect the
# Map row.  That is exactly the shape seen on a console.
#
# `get_map_mask` returns two words out of the lobby service object (US Viewer
# build: +1668/+1672 of [0x00bf0228]; JP rig: the same two offsets of
# [0x00bf2f88] -- the OFFSETS are stable across builds, the addresses are not),
# and the ONLY writer of those two words is the arm for lobby message 13 --
# this answer.  It copies them straight off the wire at record+92/record+96,
# and record == body + 20, which is cross-checked here by the seven spawn
# fields above: the same arm reads record+48..+73 and those are SPAWN_OFF_X ..
# SPAWN_OFF_INDEX+1 exactly.  So:
LOBBY_MAP_MASK_OFF = 72   # u32 lo at body[72], u32 hi at body[76]

# The roster, in the order the picker walks it -- this IS the index space, and
# it is the same index the battletable record's map byte (BT_OFF_MAP) uses.
# Read out of the client's own table (help id 0x682d, "Selects the map to use
# in this battle."); the config screen's copy carries the size class in the
# label, the browser's copy does not, and both tables are 28 entries in the
# same order.
LOBBY_MAP_NAMES = (
    "Jungle (S-M)", "Deepground (M)", "Kalm (M)", "Wastelands (M)",
    "Sewers (S-M)", "Laboratory (S)", "Training Grounds (L)", "Church (S-M)",
    "Train Graveyard (S)", "Shinra Building (S-M)", "Mako Reactor (S-M)",
    "<KelStr hole>", "Deepground 2", "Test Area (M)", "Warehouse (M)",
    "Bridge (M)", "Shinra Manor (M)", "Base 1 (M)", "Base 2 (M)", "Base 3 (M)",
    "Huge Facility (L)", "Battlefield Ruins (L)", "Canyon (L)",
    "Great Fault (L)", "Desert (L)", "Plateau (L)", "Wreckage (L)",
    "Rooftop (L)")

# WARNING: Index 11 is msgid 0x706c and 0x706c is a HOLE in group 28 -- SE's OWN hole,
# not ours: the disc's lobby.bin has 魔晄炉 there, and SE's patch 20060124_3
# blanked 0x706c/0x706d while renaming 0x706a DG1 -> 魔晄炉前.  The client's
# roster still lists it, so setting bit 11 puts a literal `!!na!!` row in the
# picker.  Leave it clear unless you are deliberately testing that.
LOBBY_MAP_HOLES = (11,)
# 2026-09-23 (design decision): hide the picker maps no shipped zone backs -- 13 Test
# Area (its オンラインテストマップ z200 exists only in the prototype install,
# bzd034) and 17/18/19 Base 1-3 (no base zone ships). A table on one of them
# played in the Jungle. Name them in --lobby-map-mask to show them again.
LOBBY_MAP_HIDDEN = (13, 17, 18, 19)
LOBBY_MAP_MASK_ALL = ((1 << len(LOBBY_MAP_NAMES)) - 1) & ~sum(
    1 << i for i in LOBBY_MAP_HOLES + LOBBY_MAP_HIDDEN)

# Set from --lobby-map-mask at startup.  Module-level so that EVERY path that
# answers selector 13 carries it, not just the one that happens to pass a spawn.
LOBBY_MAP_MASK = LOBBY_MAP_MASK_ALL

# KEY: THE LOBBY ZONE (sec 4hg addendum 4, 2026-09-23).  The world-door answer
# (selector 1 -> 2) is parsed by 0x00bd0310 (lobby-service iface virtual 6,
# reached from the phase machine 0x00bd37d8 at phase 1): record+0x1e ->
# u16 [mgr+0xd94] and mgr+0xe30 |= 0x200.  MEASURED by delivering a marked
# body to the retail client with the service at phase 1: the halfword that
# lands there is body[42..43] (an offline run of the client's own code (doc_lobbyzone_proof)).  We used to
# echo the client's 52-byte session token here, so the field held two key
# bytes (122 live) and z217's lobby-entry fallback -- the route the intro's
# return always takes, because the exit teardown unloads the loader -- loaded
# a zone the install does not have and the zone thread died on the null
# lighting table.  Holding the field at 217 over PINE landed the player.
LOBBY_ZONE = 217
LOBBY_ZONE_OFF = 42

# KEY: THE ARENA ZONE EACH ROSTER MAP IS PLAYED IN (sec 4hb, 2026-09-23).
#
# The picker works, and the chosen map REACHES US -- yet every battle started
# in the Jungle. A live log:
#
#     CREATE -> table 1 (map 9, mode 1, max 12) for 0x0004103c
#     CREATE -> table 2 (map 7, mode 1 [coerced 0->1], max 6) for 0x00041050
#     [gs] sec 4ft: kind 2 serves arena zone 201 map (0, 0)
#
# ...and then we threw the map away.  The record's map byte is DISPLAY ONLY on
# the client -- its one reader is the browser row renderer (sec 4gr.5).  What
# LOADS an arena is notify kind 2's zone byte (rec+26 -> [chan+1064] ->
# get_onlinezone -> KerberosZone.exit(zone)), and that byte was the constant
# --gs-battle-zone.  So the map -> zone lookup is the SERVER's job; nothing on
# the wire does it for us, and this table is that decode.
#
# WARNING: M0/M1 (--gs-battle-map, rec+24/+25) are NOT the map index and must not be
# set from it.  get_onlinezone packs them as exit_l(zonenum, map0, map1), i.e.
# the Zone object's own sub-map fields.  PROOF that they do not choose the
# arena: sec 4gr entered z201 (Jungle) and z208 (church) on two live runs, and
# BOTH carried M0,M1 = 0,0 -- one pair of map bytes, two different maps.  The
# zone byte is the whole selector.  M0/M1 stay at their flag value.
#
# THE MAPPING, measured -- not the `201 + index` that sec 4gr inferred.
# * The client's map roster is 28 records of {label msgid, help msgid, ordinal}
#   (0x00b1231c browser / 0x00b1aaa8 config in a current retail build;
#   0x00afc68c on the old JP rig -- WARNING: addresses are per-image, the roster was
#   re-found structurally in each).  Its third word is just index + 8 and names
#   no zone, so the client cannot tell us.
# * The title's own `data/zone/zonelist.txt` names every zone, and SE prefixed
#   the arenas "マルチ・" (multi-).  Matching the roster's JAPANESE labels
#   (group 28 of RETAIL lobby.bin, doc_patch_20060124_3 -- the English strings
#   are our own port and the two rosters disagree at 14/15) against those:
#
#     idx  roster label   zonelist                     zone  grade
#       0  ジャングル      201 マルチ・ジャングル         201  LIVE (sec 4ft)
#       2  カームの街      203 マルチ・カーム             203  name
#       3  荒野           204 マルチ・荒野               204  name
#       4  下水道         205 マルチ・下水道             205  name
#       7  教会           208 マルチ・カーム教会          208  LIVE (sec 4gr)
#       8  列車墓場       212 マルチ・列車墓場            212  name (exact)
#       9  神羅ビル       213 マルチ・神羅ビル跡          213  name
#      10  魔晄炉前       214 マルチ・魔晄炉前            214  name (exact)
#      12  DG2           216 マルチ・ディープグラウンド２  216  name
#      14  倉庫           209 マルチ・倉庫               209  name (exact)
#      15  ブリッジ       210 マルチ・ブリッジ            210  name (exact)
#      16  神羅屋敷       211 マルチ・神羅屋敷            211  name (exact)
#      20  巨大施設       230 マルチ・巨大施設            230  name (exact)
#      21  戦場跡        231 マルチ・戦場跡              231  name (exact)
#      22  渓谷          232 マルチ・渓谷                232  name (exact)
#      23  大断層        233 マルチ・大断層              233  name (exact)
#      24  砂漠          234 マルチ・砂漠                234  name (exact)
#      25  台地          235 マルチ・台地                235  name (exact)
#      26  残骸          236 マルチ・残骸                236  name (exact)
#      27  屋根          237 マルチ・屋根                237  name (exact)
#
# WARNING: NOT LINEAR.  `zone == 201 + idx` holds for 0..7 and then breaks: the
# roster lists 列車墓場 at 8 while z209 is 倉庫 (roster 14).  The `_qz - 201`
# in the command-41 answer is that same inference; it survives only because
# every --quest-zones default is <= 208.
#
# UNRESOLVED, 8 of 28, deliberately absent -- their labels match no マルチ
# zone, and a guess drops the player into someone else's arena or a stub:
#   1 DG, 5 研究所, 6 大演習場, 11 (SE's own KelStr hole), 13 テスト,
#   17/18/19 基地1/2/3.  Unclaimed arenas: 200, 202, 206, 207, 215, 239.
#   The measurement that would settle them: create a table on each, and read
#   which zone the client asks the patch server for (the patch server logs the fetch), or
#   read its gmap_str name off the loaded zone.
#
# 2026-09-23: 1, 5 and 6 ADDED by the roster ORDER. zonelist.txt runs 201..208
# in roster order (0 Jungle, 2 Kalm, 3 Wastelands, 4 Sewers and 7 Church are
# all decoded and 0/7 live), so the three holes in that run are 202 マルチ・
# ロビー (DG's lobby), 206 マルチ・ＷＲＯ (the lab), 207 マルチ・サバイバル
# (the training ground) -- all three ship full geometry. INFERRED from the run,
# not from a name match: confirm each on screen. Still absent: 11 (the hole),
# 13 テスト (its candidates 200 / 253 are not in the install) and 17/18/19
# 基地1/2/3 (no base zone ships; 215 アスール対策 and 223 lack bzd/gmap).
BT_MAP_ZONES_DEFAULT = ("0:201,1:202,2:203,3:204,4:205,5:206,6:207,7:208,"
                        "8:212,9:213,10:214,"
                        "12:216,14:209,15:210,16:211,20:230,21:231,22:232,"
                        "23:233,24:234,25:235,26:236,27:237")


def parse_map_zones(spec):
    """--battle-map-zones: `IDX:ZONE[,IDX:ZONE...]`, or off/none for an empty
    table.  Returns {roster map index: arena zone}."""
    s = (spec or "").strip().lower()
    if s in ("off", "none"):
        return {}
    if s in ("", "default", "auto"):
        s = BT_MAP_ZONES_DEFAULT
    out = {}
    for part in s.replace(" ", "").split(","):
        if not part:
            continue
        i, sep, z = part.partition(":")
        if not sep:
            raise SystemExit("--battle-map-zones wants IDX:ZONE, got %r" % part)
        i, z = int(i, 0), int(z, 0)
        if not 0 <= i < 64:
            raise SystemExit("--battle-map-zones map index %d is out of range "
                             "(0..63 -- the picker's own bit test)" % i)
        if not 0 < z < 256:
            raise SystemExit("--battle-map-zones zone %d is out of range "
                             "(1..255): kind 2 carries the zone in ONE byte "
                             "(rec+26), and 0 is get_onlinezone's exit(-1) = "
                             "the title" % z)
        out[i] = z
    return out


# WHICH PIECES AN ARENA LOADS ON ARRIVAL (seen live and in a savestate).
#
# The Wastelands drew only the skybox and walking did not bring the terrain
# in; the church's terrain streamed in only once the player walked around.  Slot-4 savestate in z204: m000/model.rfd resident
# (122/128 samples -- a 138-vertex shell spanning +-16,000 = the SKY), m002
# resident, m001 (1.27 MB, the whole terrain, and the piece our spawn stands
# in) ABSENT, 0/128 of its collision.  Kind 2's M0/M1 (rec+24/+25) reach
# get_onlinezone as exit_l(zone, map0, map1), the Zone's own sub-map pair --
# the arena twin of the lobby descriptor `index` that picks the preload piece
# (sec 4dn, live A/B), and SE's ev2045 respawn does Zone.load(201, 1, 3) = the
# Jungle's terrain pieces.  We sent 0,0 everywhere: the church's terrain is
# m002 (streams in on a walk), the Wastelands' is m001 (never does).
# Terrain piece per zone, measured from data/zone/zNNN/m0xx/model.rfd sizes.
# LIVE: z204 at 1,0 draws the Wastelands terrain (M0 IS the piece).
# z201 (Jungle) at 0,0 stayed blank until the player got control (seen live,
# mission 39); its terrain is m001 + m003..m005, and 1,3 is SE's own
# pair -- ev2045.battlefield's respawn does Zone.load(201, 1, 3). LIVE.
# z203 (Kalm) at 0,0 loaded only partially. Kalm spreads
# over m000..m005; the two pieces with the most model vertices within 300 of
# its spawn (-1016.1, 911.1) are m004 (2980) and m001 (802) -> 4,1; the rest
# stream in on movement. z205 (Sewers, unseen) by the same count: m003 (7946),
# m001 (3273) -> 3,1.
# 2026-09-23, every other decoded arena: the two pieces with the most MODEL
# vertices within 300 of its new --zone-spawns point (ZONE_SPAWNS_DEFAULT); a
# second piece under ~2% of the first is left at 0 (m000 loads anyway).
# 2026-09-24: z214 (Mako Reactor) at 1,0 drew textures on the WRONG SURFACES, and the
# software renderer did too. Its savestate: 34 of the 61 slots it uses were never
# uploaded and still held the previous zone's TEX0, the fence and mako_* among them.
# 0,0 was an A/B: the arena went BLACK (terrain piece never loaded), so the pair
# picks the terrain, not the textures. Back to 1,0; the texture fault is open.
ZONE_PIECES_DEFAULT = ("201:1,3;203:4,1;204:1,0;205:3,1;208:2,0;"
                       "202:4,3;206:1,0;207:6,0;209:1,0;210:3,0;211:1,6;"
                       "212:1,0;213:1,4;214:1,0;216:8,0;230:1,2;231:1,0;"
                       "232:1,0;233:1,0;234:1,0;235:1,0;236:1,0;237:1,0")

# The arena SPAWN per zone (kind 2 rec+0/+4/+8, --zone-spawns). 208/203/204/205
# are the sec 4gr.6 points, all visited live (Church "the spawn is good"; Kalm,
# Wastelands, Sewers 09-23). The rest (2026-09-23, never seen): the centre of
# the largest connected FLAT patch of each zone's collision mesh (mapid.rfd,
# up = -y, 40-unit cells, level +-1) whose floor is also VISIBLE (rendered
# model vertices within 8 of that height -- without that test 207/231/237/214
# landed on an invisible catch plane in the sky piece's collision), 2 units
# above the floor. The same picker without the visibility test reproduces the
# live Church point exactly (738.9, -102.0, 1427.0).
ZONE_SPAWNS_DEFAULT = (
    "208:738.9,-102,1427.0;203:-1016.1,-2,911.1;204:-629.7,-8,152.7;"
    "205:-620.9,398,-300.3;"
    "202:1.2,-2.5,-1266.2;206:1.2,-1.9,1.5;207:266.7,-2.0,-497.5;"
    "209:165.8,-2.0,57.9;210:-1625.0,37.2,167.2;211:18.3,81.0,-693.1;"
    "212:100.0,-1.9,0.1;213:-20.5,-1.9,-51.7;214:-459.1,-1.4,-861.1;"
    "216:-104.7,-2.0,574.8;230:474.2,138.0,1420.8;231:-1080.0,-2.0,686.6;"
    "232:-2815.1,602.2,511.5;233:-2723.3,-2.0,-1680.1;"
    "234:-743.7,-2.0,-1138.6;235:264.5,-2.0,-490.1;236:2130.0,-2.0,-1350.0;"
    "237:2264.7,-7.5,730.4")


def parse_zone_pieces(spec):
    """--zone-pieces: `ZONE:M0,M1[;ZONE:M0,M1...]`, or off/none.  Returns
    {arena zone: (map0, map1)} for kind 2's rec+24/+25."""
    s = (spec or "").strip().lower()
    if s in ("off", "none"):
        return {}
    out = {}
    for part in s.replace(" ", "").split(";"):
        if not part:
            continue
        z, sep, mm = part.partition(":")
        m = [int(x, 0) for x in mm.split(",") if x]
        if not sep or not 1 <= len(m) <= 2:
            raise SystemExit("--zone-pieces wants ZONE:M0,M1, got %r" % part)
        m = (m + [0])[:2]
        if not all(0 <= v < 256 for v in m):
            raise SystemExit("--zone-pieces %r: M0/M1 are one byte each" % part)
        out[int(z, 0)] = (m[0], m[1])
    return out


def battle_bmap(zone, zone_pieces, default=(0, 0)):
    """Kind 2's (M0, M1) for arena `zone`: its --zone-pieces entry, else the
    --gs-battle-map default."""
    return tuple(zone_pieces.get(zone, default))


# reasons battle_map_arena can refuse -- named so a test can assert on the
# DECISION and not on the wording of a log line.
ARENA_OK = "ok"
ARENA_NO_ZONE = "no-zone"        # the map has no decoded arena
ARENA_NO_SPAWN = "no-spawn"      # it has one, but nothing would stand on


def battle_map_arena(map_idx, map_zones, default_zone, zone_spawns=(),
                     needs_spawn=True):
    """sec 4hb: (arena zone, why) for a battletable whose record carries
    `map_idx` at BT_OFF_MAP.

    Returns the zone kind 2 should put at rec+26, or `default_zone` when we
    will not follow the map -- `why` is ARENA_OK / ARENA_NO_ZONE /
    ARENA_NO_SPAWN, so the caller decides the wording and a test decides
    nothing.  Pure on purpose: every branch here is reachable from
    doc_udp_test.py with hand-built arguments, including the known-bad ones."""
    z = map_zones.get(map_idx)
    if z is None:
        return default_zone, ARENA_NO_ZONE
    if needs_spawn and z != default_zone and z not in zone_spawns:
        return default_zone, ARENA_NO_SPAWN
    return z, ARENA_OK


def parse_map_mask(spec):
    """--lobby-map-mask: `all`, `none`, a 0x… / decimal mask, or a comma list
    of roster indices.  Returns an int."""
    s = (spec or "").strip().lower()
    if s in ("", "all", "auto"):
        return LOBBY_MAP_MASK_ALL
    if s in ("none", "off"):
        return 0
    if "," in s or s.isdigit() and len(s) <= 2:
        m = 0
        for part in s.split(","):
            part = part.strip()
            if not part:
                continue
            i = int(part, 0)
            if not 0 <= i < 64:
                raise SystemExit("--lobby-map-mask index %d is out of range "
                                 "(0..63)" % i)
            m |= 1 << i
        return m
    return int(s, 0)


def describe_map_mask(mask):
    """The names a mask admits -- so a startup line says what the picker will
    actually show, rather than printing a number nobody can read."""
    out = []
    for i, nm in enumerate(LOBBY_MAP_NAMES):
        if mask & (1 << i):
            out.append("%d:%s" % (i, nm))
    extra = mask >> len(LOBBY_MAP_NAMES)
    if extra:
        out.append("+%d bit(s) past the roster (the client stops at the "
                   "roster's terminator, so they do nothing)"
                   % bin(extra).count("1"))
    return out

# KEY: The getter SUBTRACTS 3.0 from Y (0x0058d2dc, `sub.s`, verified by decode --
# reading it as add.s inverts the whole thing).  So the descriptor's Y is three
# units ABOVE where the player ends up.  Confirmed three ways against measured
# emulog values: descriptors of -3.0 / 0.0 / -1.0 produced actors at -6.0 / -3.0
# / -4.0 in sec 4dd and sec 4df.  --lobby-spawn takes the WORLD position you want
# the player to stand at and this compensation is applied here, once.
SPAWN_Y_BIAS = 3.0

# The room spot sec 4dd measured 18 times as "the correct lobby spot", with the
# facing and index read out of doc_boomerang_slot07's own descriptor.
#
# WARNING: 2026-09-05 (audit): "room" IS THE BRIEFING ROOM, not the lobby.
# (1935.19, -0.052, -42.712) appears VERBATIM in `ev2046_sub.vl_brf2` -- the
# briefing-room script -- as one of sixteen seat positions ringed around
# (1896.8, -1.593).  Every savestate it was measured from was taken with
# selector 38 armed, i.e. with the player parked in that room.  With 38 off the
# zone script runs `vl_main` (the Visual Lobby) and this spot is "the middle of
# nowhere": walkable floor, wrong part of z217.
#
# The lobby's real areas are hard-coded in `vl_main` itself.  Right after it
# reads our descriptor it classifies the position (doc_jclass.py --name ev2046
# --code, bytecode 150..302) and hands the result to quest.handle_event:
#
#     region 0 (EAST wing):    430 < x < 1530   and  -600 < z <  560
#     region 1 (SOUTH wing):  -550 < x <  550   and -1560 < z < -430
#     region 2 (WEST wing):  -1550 < x < -400   and  -600 < z <  560
#     region 3: anywhere else  (the briefing-room spot lands HERE)
#
# and `mm_z217.gmap_exec` places the four map-screen anchors ID_PLACE_0..3 at
# (679.6, -3.4) / (1.7, -632.2) / (-679.8, -6.1) / (-0.9, 632.2) -- one per
# wing, inside those rectangles.  `quest.ev` (the east wing's opening event)
# stands the PLAYER actor at (900, 0, 145) facing +x, so that spot is floor by
# construction; the wing anchors are floor by intent.  Heading is derived from
# the facing vector (0x00507ee8 feeds dirX/dirZ to an atan2), not from `index`.
SPAWN_ROOM = (1935.19, 0.0, -42.712, -0.695, 0.0, 0.719, 11)
SPAWN_PRESETS = {
    "room":  SPAWN_ROOM,                                         # briefing seat
    # index: LIVE 2026-09-05 the east spawn landed exactly (emulog
    # copyMatrixFromActor p(900,0,145)) but the wing did not RENDER -- a void
    # with the interaction debug boxes -- until the player walked across a
    # boundary, at which point the engine streamed z217/m001 + m003. At spawn
    # it had loaded only m000/m013/m011, the same set as at the briefing seat,
    # where index was 11 and m011 IS the briefing room. So `index` is read
    # here as the piece to preload: 1 for the east wing. HYPOTHESIS under
    # test -- if the wing renders at spawn, it holds.
    "east":  (900.0, 0.0, 145.0, 1.0, 0.0, 0.0, 1),              # quest.ev's spot
    "east-anchor": (679.649, 0.0, -3.434, -1.0, 0.0, 0.0, 1),    # ID_PLACE_0
    "south": (1.729, 0.0, -632.189, 0.0, 0.0, 1.0, 11),          # ID_PLACE_1
    "west":  (-679.842, 0.0, -6.105, 1.0, 0.0, 0.0, 11),         # ID_PLACE_2
    "north": (-0.886, 0.0, 632.181, 0.0, 0.0, -1.0, 11),         # ID_PLACE_3
}
