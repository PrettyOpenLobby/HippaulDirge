#!/usr/bin/env python3
"""Dirge of Cerberus MISSION MODE -- the per-player mission ledger (2026-09-23).

WHAT SE'S OWN TEXT SAYS MISSION MODE IS (retail patch 20060124_3, the lobby
string table's battle-system briefer text ID_BT_SETU_MS_00 / ID_BT_SETU_MSJ_00):

  * "A mode for special duties outside Normal / Squad Battle. A typical mission
    is the Promotion Exam. You cannot raise your rank without clearing it.
    Gather the rank points set for the rank you seek, speak to an area's
    promotion exam instructor, and attempt the exam."
  * "Some missions cannot be attempted again once cleared; others can be taken
    any time. Some you must fight alone, and some you may attempt with others;
    to try with others, you recruit participants as in any other battle."
  * "To obtain new mission information: speak often with comrades inside
    Deepground; gather rank points and raise your rank."

and the INSTRUCTOR scene (quest_scr003.ev_n07, event ids 1000-1029; NPCs 8/9/10
replay it at +30/+60/+90) says, on the granting branch, "DG Drone 2nd Promotion
Exam was added to Missions -- go to Battle Entry and select the mission".

So the server owns a per-player list of TAKEN missions. The retail Battle
Entry menu (lobby.pex record table 0x00b120a8, resume savestate 2026-09-22)
has two mission rows:
    action 2  28:91 "Accept Mission"       -> the mission-list window
                                             (selector 159 -> 160, quest ids)
    action 6  28:244 "Missions Recruiting" -> the battletable list (window
                                             kind 6, filter 0x00aa3b78 shows
                                             every row for kinds 4 and 6)
The 159 -> 160 list / command 41 pick / Start -> mission 38 chain is docudp's
(sec 4gr, live). What was missing is the LEDGER: the list was one static
`--solo-quests` set for everyone and the instructors always played their
greeting, so no exam was ever "added to Missions".

WHAT THE INSTRUCTOR SAYS, decoded from ev_n07's lookupswitch (event -> branch
-> dialogue keys), all four instructors share the shape:
    +0   ID_KY_YOYAKU_H  "standing by for an operation?"  (holds a reservation)
    +1   ID_KY_DR_03_A   the first-meeting tutorial (13 lines)
    +2   ID_KY_MISH_A    "never halt your advance / I will teach you"
    +3   ID_KY_DR_03_NORU  DG Drone 2nd exam ADDED TO MISSIONS   <- grant
    +5   ID_KY_DR_03_BT03  "take part in three battles or more first"
    +6   ID_KY_DR_03_MADA  "you have not yet entered a battle"
    then one 3-event tier per held rank 2..8, k = rank - 2:
    +7+3k  rank chatter (DR_02_A, DR_01_A, SC_03_A, SC_02_A, SC_01_A, TR_03_A,
           TR_02_A)
    +8+3k  ID_KY_SH_TR_x  "you need N rank points"  (A..G)
    +9+3k  ID_KY_SH_TST_x "I authorize the exam -- added to Missions" <- grant
    +28  ID_KY_TR_01_A   Trooper 1st chatter (nothing above it: exams 9-15
         are "Not yet implemented" in the shipped mission table)
The rank-point figures are the instructor's own lines (ID_KY_SH_TR_A..G_01_01):
4000 / 7000 / 11000 / 15000 / 19000 / 23000 / 28000; the first exam wants
three battles instead. The exam each tier grants is read off the dialogue
("DG Drone 1st Promotion Exam was added ...") and matches doc_stats'
EXAM_PROMOTIONS (quest -> rank it promotes to).

VERIFIED: PROVEN STATIC 2026-09-23 (ev_n08 / ev_n09 / ev_n10 decoded the same way):
NPCs 8/9/10 keep the +30/+60/+90 shift on EVERY offset this module serves --
+0 YOYAKU, +2 MISH, +3 NORU, +5 BT03, +6 MADA, +7 rank chatter, +8/+9 SH_TR_A /
SH_TST_A ... +27 SH_TST_G, +28 TR_01 -- each lands on the same dialogue family
with the NPC's own letter (B / C / D). NPCs 9 and 10 have no +4 case at all
(their switch sends it to the default); +4 is never served here.
WARNING: INFERRED, not yet confirmed on a console: (a) that a rank-2..8 player who already holds the
exam should hear the rank chatter (+7+3k) rather than the tutorial; (b) the
reservation "standby" line is never served (docudp does not tell this module
about reservations).
OURS (SE's server logic is lost): an exam stays in the list until cleared or
until the rank it promotes to is reached some other way. 2026-09-24: the base
`--solo-quests` set is gated by RANK CLASS per the Lifestream archive (see
RANK TABS below): a fresh Drone sees the Drone tab only, Beginner's Course
first; Scout and Trooper tabs open with the class.
"""
import sys

# rank HELD (1-based, doc_stats.RANK_CODES) -> (exam quest id, rank points
# needed, battles needed). Quest ids name KelStr group 47 index id-1.
#: WARNING: 2026-09-24: quest ids are the RETAIL group 47 (the client players run).
#: The disc's table had 3 = Scout 3rd / 4 = Scout 2nd / 28 = Trooper 3rd and this
#: ladder was built from it; retail reorders them, and its own objectives
#: (group 49) agree with the Lifestream archive: 28 = Scout 3rd (Sewer, collect
#: 5 capsules, 3 KOs), 3 = Scout 2nd (Church, 3 Commanders), 4 = Trooper 3rd
#: (Jungle, 3 capsules).
EXAMS = {
    1: (1, 0, 3),        # DG Drone 2nd Class Examination   (3 battles)
    2: (2, 4000, 0),     # DG Drone 1st Class Examination
    3: (28, 7000, 0),    # DG Scout 3rd Class Examination
    4: (3, 11000, 0),    # DG Scout 2nd Class Examination
    5: (6, 15000, 0),    # DG Scout 1st Class Examination
    6: (4, 19000, 0),    # DG Trooper 3rd Class Examination
    7: (7, 23000, 0),    # DG Trooper 2nd Class Examination
    8: (8, 28000, 0),    # DG Trooper 1st Class Examination
}
EXAM_QUESTS = frozenset(q for q, _, _ in EXAMS.values()) | frozenset(range(9, 16))
#: quest -> the rank it promotes to (mirrors doc_stats.EXAM_PROMOTIONS)
EXAM_TARGET = {q: r + 1 for r, (q, _, _) in EXAMS.items()}

#: instructor lnpc number -> its event base (NPC 7's ids are 1000..1029)
INSTRUCTORS = {7: 1000, 8: 1030, 9: 1060, 10: 1090}
EV_STANDBY, EV_TUTORIAL, EV_CHATTER, EV_GRANT_FIRST = 0, 1, 2, 3
EV_NEED_BATTLES, EV_NO_BATTLES = 5, 6
EV_TIER0, EV_TOP = 7, 28          # tiers of three from +7; +28 = Trooper 1st chatter
LEDGER_KEY = "quests_open"        # the career field holding granted exams


def instructor_event(npc, career, reserved=False):
    """(event id, exam quest to GRANT or None, note) for a walk-up to
    instructor `npc` by a player with career `career` (doc_stats shape:
    rank / rp / battles / quests_open)."""
    base = INSTRUCTORS[npc]
    rank = max(1, int(career.get("rank", 1) or 1))
    rp = int(career.get("rp", 0) or 0)
    battles = int(career.get("battles", 0) or 0)
    held = set(int(q) for q in career.get(LEDGER_KEY, []) or [])
    if reserved:
        return base + EV_STANDBY, None, "standby (holds a reservation)"
    if battles == 0:
        return base + EV_NO_BATTLES, None, "no battle fought yet"
    if rank >= 9:
        return base + EV_TOP, None, "rank %d: no exam above Trooper 1st" % rank
    quest, need_rp, need_battles = EXAMS[rank]
    if rank == 1:
        if battles < need_battles:
            return base + EV_NEED_BATTLES, None, \
                "%d of %d battles for exam %d" % (battles, need_battles, quest)
        if quest in held:
            return base + EV_CHATTER, None, "exam %d already taken" % quest
        return base + EV_GRANT_FIRST, quest, "GRANT exam %d (3 battles fought)" % quest
    k = rank - 2
    if quest in held:
        return base + EV_TIER0 + 3 * k, None, "exam %d already taken" % quest
    if rp < need_rp:
        return base + EV_TIER0 + 1 + 3 * k, None, \
            "%d of %d rank points for exam %d" % (rp, need_rp, quest)
    return base + EV_TIER0 + 2 + 3 * k, quest, \
        "GRANT exam %d (%d rank points >= %d)" % (quest, rp, need_rp)


# ── MISSION SCORING (2026-09-23) ─────────────────────────────────────────
# SE's own victory / defeat lines, retail lobby table groups 49 / 50, index =
# quest id - 1 (doc_msgid -s doc_retail_lobby_20260923.p2s --group 49/50).
# kind: "most" = "Defeat/Collect as many ... as possible" (judged at the
# clock), "kill" = defeat N, "capsule" = collect N, "base" = capture the base.
# ko = "Suffer N KOs" (0 = time limit only). WHAT IS MEASURED: the client
# reports a death as game-server request 30 only from the kel CHARACTER table
# (retail builder 0x00bcd1a8, its five callers 0x00beed44..0x00befaf8 are the
# character HP paths) -- so a PLAYER's KO reaches us, and a mission enemy's
# death very likely does NOT. "most" missions can therefore be judged today;
# kill / capsule / base need a report we have not seen (see npc_kill()).
OBJECTIVES = {
    1: ("kill", 10, 1),    # Defeat 10 Beast Soldiers
    2: ("base", 0, 0),     # Breach the defenses and capture the enemy's base
    3: ("kill", 3, 1),     # Defeat 3 DG Commanders
    4: ("capsule", 3, 1),  # Collect 3 mako capsules
    5: ("base", 0, 3),
    6: ("kill", 5, 1),
    7: ("kill", 12, 1),
    8: ("base", 0, 1),
    16: ("capsule", 7, 0),
    18: ("kill", 1, 6),    # Defeat the Dual Horn
    19: ("most", 0, 3),    # Defeat as many Bizarre Bugs as possible
    20: ("most", 0, 0),    # ... DG Commanders as possible
    21: ("most", 0, 3),    # ... DG Snipers as possible
    22: ("base", 0, 0),
    23: ("capsule", 7, 4),
    24: ("capsule", 7, 0),
    25: ("capsule", 7, 0),
    26: ("kill", 5, 12),   # Defeat 5 Dual Horns
    27: ("most", 0, 3),    # Collect as many mako capsules as possible
    28: ("capsule", 5, 3),
    29: ("most", 0, 1),    # ... DG Soldiers and SOLDIERs ("1 total KO")
    30: ("base", 0, 1),
    31: ("kill", 30, 0), 32: ("kill", 50, 0), 33: ("kill", 100, 0),
    34: ("kill", 50, 0), 35: ("kill", 50, 0),
    36: ("kill", 2, 3),    # Defeat the DG Soldier and Beast Soldier
    37: ("kill", 50, 0), 38: ("kill", 100, 0),
    39: ("kill", 5, 0),    # Beginner's Course I
    40: ("kill", 3, 0),    # Beginner's Course II
    41: ("most", 0, 1),
    42: ("base", 0, 5),
    43: ("kill", 100, 10),
}
WHY_OBJECTIVE = "mission objective"
WHY_KO = "mission KO limit"
WHY_QUIT = "player quit"          # docudp: the solo player returned to the lobby


# ── PER-MISSION SETUP (2026-09-24) ───────────────────────────────────────
# SE's quest -> (arena, situation, enemies, players) table was SERVER data and
# is lost. Sources, in order of weight:
#   1. The Lifestream's archive of the 2006 online missions (Wayback copy of
#      thelifestream.net/dirge-of-cerberus/multiplayer-archives/online-missions/
#      pages 1-7, 2022-11-28): per mission the MAP, "Maximum Participants",
#      objective, defeat conditions, time limit, supplies, enemies seen.
#      Its Japanese-derived names map to our US rows: Sniper Threat = 21
#      Sniping Menace, Steel Wall = 22 Iron Curtain, Stolen Capsules! = 23,
#      Collector's Mind (Lv.2/Lv.3) = 16/24/25, Pest Control = 19,
#      Green Encounter = 27, Forest of Grudge = 30, The Consequence of
#      Betrayal = 36, Dual Horn Battlefield = 18.
#   2. The client: each arena's situation model sets = bzd table 20, record
#      4 + (sit - 3000) (records 0..3 = PvP sets), SE patch 20060124_3; the
#      kind-15 NPC TYPE is an INDEX into that list (live). Controller
#      spawn counts (doc_mission_spawns.json) back several matches up:
#      Jungle 3000 has 10 spawn points = the Drone 2nd exam's 10 Beast
#      Soldiers.
# MODEL CODES (the client has no name table):
#   e102 = DG soldier (live)            e030 = Beast Soldier / hound (live;
#          Jungle 3000 = exam 1 "10 Beast Soldiers" = e030 alone, x10 spawns)
#   e028 = DG Sniper (+ w005, a rifle) -- Wastelands 3004 is the only set
#          with sniper + DG soldier + beast, the archive's Sniper Threat mix
#   e015 = DG Commander -- in every commander-exam arena's set
#   e038 / e040 = Bizarre Bugs -- Jungle Elite's distractors (Jungle 3003),
#          and e038 is in the Sewers' bug sets
#   e042 = SOLDIER -- beside e102 in Kalm 3005, the Double Attack set
#   e019 e020 e039 e069 = the Wastelands beasts: Dual Horn, its Guard /
#          Crimson hounds, and Green Encounter's two Cactuar kinds. Which is
#          which is a GUESS.
# confidence: "live" = played and won; "high" = archive map + a unique set;
# "low" = a guess worth a look. "capsule" / "base" missions get enemies but
# CANNOT be won yet (no capsule / base report is decoded).
SITUATION_SETS = {
    (201, 3000): ["e030", "w010"],
    (201, 3001): ["e030", "w010", "w003", "e102"],
    (201, 3002): ["w003", "w004", "e036", "o099", "g056", "e102"],
    (201, 3003): ["e038", "e040", "e015", "w003"],
    (201, 3004): ["w003", "e102"],
    (203, 3001): ["w003", "o099", "e030", "w010", "e102"],
    (203, 3003): ["o099", "w003", "e037", "e102"],
    (203, 3004): ["o099", "w003", "e102"],
    (203, 3005): ["o099", "w003", "e042", "e030", "w010", "e102"],
    (204, 3000): ["o099", "e015", "w003", "e030", "w010"],
    (204, 3002): ["o099", "e019", "e039", "e069"],
    (204, 3003): ["o099", "e019", "e020", "e039"],
    (204, 3004): ["o099", "e030", "w010", "e028", "w005", "w003", "e102"],
    (204, 3005): ["o099", "e020", "e019"],
    (204, 3007): ["o099", "w003", "e102"],
    (205, 3002): ["e038", "e042", "e046"],
    (205, 3003): ["e042", "e102", "o099", "w003"],
    (205, 3004): ["e102", "w003"],
    (208, 3001): ["w003", "e030", "w010", "e042", "e015"],
    (208, 3002): ["w003", "w010", "e015", "e042", "e102"],
    (208, 3003): ["w003", "e030", "w010", "e042", "e102"],
    (208, 3006): ["w003", "e102"],
}
# quest -> (zone, situation, enemy codes spawned at once, confidence)
# (a dead enemy is replaced 5 s later, so a "defeat N" count is reachable)
MISSION_SETUP = {
    1: (201, 3000, ["e030", "e030"], "high"),        # Jungle: 10 Beast Soldiers
    3: (208, 3001, ["e015", "e015", "e030"], "high"),  # Church: 3 Commanders + beasts
    5: (208, 3003, ["e102", "e102", "e030"], "low"),   # Church base: not winnable
    6: (204, 3000, ["e015", "e015"], "high"),        # Wastelands: 5 Commanders
    7: (208, 3002, ["e015"], "high"),                # Church: 12 Commanders, one at a time
    18: (204, 3002, ["e019", "e039", "e069"], "low"),  # Dual Horn + hounds
    19: (205, 3002, ["e038", "e038", "e046"], "low"),  # Sewer: Bizarre Bugs
    20: (201, 3003, ["e015", "e015", "e038"], "high"),  # Jungle: soldiers + bugs
    21: (204, 3004, ["e028", "e028", "e102", "e030"], "high"),  # snipers + others
    23: (203, 3003, ["e102", "e102"], "low"),        # Kalm capsules: not winnable
    26: (204, 3005, ["e019", "e020"], "low"),        # 5 Dual Horns
    27: (204, 3003, ["e020", "e039"], "low"),        # Cactuars: capsules
    28: (205, 3003, ["e102", "e102"], "high"),       # Sewer capsules: not winnable
    29: (203, 3005, ["e102", "e102", "e042"], "high"),  # Kalm: DG Soldiers + SOLDIER
    30: (201, 3002, ["e102", "e102"], "low"),        # Jungle base: not winnable
    31: (208, 3006, ["e102", "e102"], "high"),       # Map Exercise Church
    32: (201, 3004, ["e102", "e102"], "high"),       # Map Exercise Jungle
    33: (204, 3007, ["e102", "e102"], "high"),       # Map Exercise Wastelands
    34: (205, 3004, ["e102", "e102"], "high"),       # Map Exercise Sewers
    35: (203, 3004, ["e102", "e102"], "high"),       # Map Exercise Kalm
    36: (203, 3001, ["e102", "e030"], "high"),       # Kalm: soldier + beast soldier
    39: (201, 3001, ["e102", "e102"], "live"),       # Beginner's Course I
    40: (201, 3001, ["e102", "e102", "e030"], "live"),  # Course II + hound
}
# "Maximum Participants" per the archive (the mission screen's limit, command
# 29 answer body[37]). Unlisted quests: 1. WARNING: A second player joining a
# mission is UNTESTED end to end.
MAX_PLAYERS = {
    1: 1, 2: 1, 3: 1, 4: 1, 5: 2, 6: 1, 7: 1, 8: 1, 16: 1, 18: 3, 19: 1,
    20: 3, 21: 3, 22: 6, 23: 4, 24: 1, 25: 1, 26: 6, 27: 3, 28: 1, 29: 2,
    30: 2, 31: 1, 32: 1, 33: 1, 34: 1, 35: 1, 36: 3, 39: 1, 40: 1,
}
# archive maps for rows with no enemy set above (zone numbers as served)
# 2026-09-24: + the map exercises 37 Train Graveyard (z212) / 38 Battlefield
# Ruins (z231) -- both arenas have a spawn now (ZONE_SPAWNS_DEFAULT)
ARCHIVE_ZONES = {2: 204, 4: 201, 8: 203, 16: 208, 22: 205, 24: 205, 25: 203,
                 37: 212, 38: 231}
# 2026-09-24: the TIME LIMIT per mission, seconds, from the Lifestream
# online-missions archive ("Time Limit | 5 Minutes", ...). None of these were
# encoded before: a mission ran on whatever the client's record carried (600 s
# live) or --gs-battle-length. 3/4/28 are matched by CONTENT (our client's
# objective text), which the archive files under rotated exam names. Unlisted
# quests keep the record's own limit.
MISSION_TIME = {
    1: 300, 2: 300, 3: 600, 4: 300, 5: 540, 6: 300, 7: 480, 8: 600,
    16: 600, 18: 420, 19: 300, 20: 300, 21: 300, 22: 300, 23: 480, 24: 900,
    25: 420, 26: 600, 27: 480, 28: 270, 29: 300, 30: 300, 31: 3600, 36: 480,
    39: 3600, 40: 3600,
}


def mission_setup(quest):
    """(zone, situation, [kind-15 types], players) for `quest`, or None."""
    row = MISSION_SETUP.get(quest)
    if row is None:
        return None
    zone, sit, codes, _conf = row
    models = SITUATION_SETS[(zone, sit)]
    return zone, sit, [models.index(c) for c in codes], players(quest)


#: 2026-09-26: each mission's "Initial Supplies" (Lifestream archive,
#: online-missions/2..4). Retail topped the player up per MISSION; there is no
#: general enemy ammo drop in the archive (Silent Killing's 9 bullets were
#: "fewer bullets than there were enemies"). Unlisted quests and PvP tables get
#: the standard 36 handgun / 18 rifle / 60 machine gun. The archive's "??" for
#: Trooper 2nd's rifle rounds is read as the standard 18.
HANDGUN, RIFLE, MG = 0x62300000, 0x62300001, 0x62300002
POTION = 0x69320000                # the ONLINE Potion (category 0x6932)
STANDARD_SUPPLIES = ((HANDGUN, 36), (RIFLE, 18), (MG, 60))
SUPPLIES = {
    39: ((HANDGUN, 300), (POTION, 3)),                   # Beginner's Course I
    40: ((HANDGUN, 300), (POTION, 3)),                   # Beginner's Course II
    7: ((HANDGUN, 54), (RIFLE, 18), (MG, 120), (POTION, 3)),  # Trooper 2nd exam
}
SUPPLY_ITEMS = frozenset((HANDGUN, RIFLE, MG, POTION))


def supplies(quest, standard=STANDARD_SUPPLIES):
    """The (item, quantity) pairs a player starts `quest` with (None = PvP)."""
    return SUPPLIES.get(quest, standard)


BULLET_CATEGORY = 0x6230           # item id >> 16 of every bullet


def respawn_refill(start, held=None):
    """2026-09-26: the (item, qty) rows kind 25 carries on a KO (<= 3; the
    client SETS each qty into the bag, 0x00be7de8).

    Retail (ameblo 2006-04-03, the 03-24 update): a respawn refills BULLETS
    only, and only up to the battle-start count when the player holds fewer.
    Potions (Beginner's Courses) are not refilled.

    `start` = the battle's supplies (`supplies(quest)`), `held` = the server's
    supplies ledger {item: qty} (world-door bag, minus request 44 per battle,
    plus grants and pickups) or None. The ledger only learns what was FIRED
    at the battle end (request 44), so in-battle use is unknown here. The safe
    rule (OURS): each row is max(ledger, battle-start). It never SETS a
    quantity below what the ledger says the player holds (a pickup is never
    cut back) and never below the battle-start issue; when the ledger is
    above the issue it can give back rounds fired before the KO."""
    held = held or {}
    rows = []
    for iid, qty in start:
        if (iid >> 16) != BULLET_CATEGORY:
            continue
        rows.append((iid, max(int(qty), int(held.get(iid, 0)))))
    return tuple(rows[:3])


def time_limit(quest):
    """The archive's time limit for `quest` in seconds, or None (keep the
    record's)."""
    return MISSION_TIME.get(quest)


def players(quest):
    return MAX_PLAYERS.get(quest, 1)


def objective(quest):
    """(kind, target, ko_limit) for `quest`; unknown quests read as a kill
    mission with no target (never won by a count, lost at the clock)."""
    return OBJECTIVES.get(quest, ("kill", 0, 0))


def describe(quest):
    kind, n, ko = objective(quest)
    what = {"most": "as many as possible, judged at the time limit",
            "kill": "defeat %d" % n, "capsule": "collect %d capsules" % n,
            "base": "capture the base"}[kind]
    return "%s%s" % (what, (", lost at %d KO(s)" % ko) if ko else "")


def ko_out(quest, deaths):
    """True when the player's KOs reach the mission's KO limit."""
    ko = objective(quest)[2]
    return bool(ko and deaths >= ko)


# 2026-09-24: CAPSULE missions (16, 23, 24, 25, exams 4 / 28, and 27 "collect
# as many mako capsules as possible"). How SE placed them is not decoded (the
# client's own drop tables, bzd table 22, carry capsule records, but who drops
# them is unknown); the server PLACES them as field items (notify kind 10, like
# Team Capsule) and the mission is won when the players hold the target.
#: quests whose "as many as possible" count is capsules, not kills
CAPSULE_MOST = frozenset((27,))
#: how many capsules a CAPSULE_MOST mission's field gets
CAPSULE_MOST_FIELD = 15


def capsule_setup(quest):
    """(capsules to place, target to win) for a capsule mission, else None.
    Target 0 = no count wins it (a CAPSULE_MOST mission ends on the clock)."""
    kind, n, _ = objective(quest)
    if kind == "capsule" and n > 0:
        return n, n
    if quest in CAPSULE_MOST:
        return CAPSULE_MOST_FIELD, 0
    return None


def capsules_end(quest, held):
    """True when the capsules the players hold complete a capsule mission."""
    cs = capsule_setup(quest)
    return bool(cs and cs[1] and held >= cs[1])


def npc_kill_ends(quest, npc_kills):
    """True when a reported enemy-kill count completes a 'kill' mission."""
    kind, n, _ = objective(quest)
    return kind == "kill" and n > 0 and npc_kills >= n


def verdict(quest, over, why, deaths):
    """'w' / 'l' for a mission room. A KO-limit end loses; an objective end
    wins; a clock end wins only a 'most' mission ("as many as possible" has
    no failure but the KO limit and time is the only way it ends)."""
    if (ko_out(quest, deaths) or (why or "").startswith(WHY_KO)
            or (why or "").startswith(WHY_QUIT)):
        return "l"
    if over and (why or "").startswith(WHY_OBJECTIVE):
        return "w"
    if objective(quest)[0] == "most" and over:
        return "w"
    return "l"


# ── RANK TABS (2026-09-24) ────────────────────────────────────────────────
# SE filed every mission under a rank class, the client's "Mission: DG <class>"
# tabs (L2 / R2; thresholds 0/3/6/9/12/15 at lobby.pex 0x00b12158). Source:
# the Lifestream online-missions archive, pages 2 (Drone), 3 (Scout), 4
# (Trooper), Wayback copies; pages 5-7 (Commander / General / Tsviet) hold only
# content added after this build (the Commander 3rd exam arrived Feb 27). Each
# tab's order is the archive's, which puts Beginner's Course right after the
# exams. Names: Pest Control = 19 Exterminators, Green Encounter = 27 Jade
# Encounters, Forest of Grudge = 30, The Consequence of Betrayal = 36, Sniper
# Threat = 21, Steel Wall = 22, Stolen Capsules! = 23, Dual Horn Battlefield
# = 18. Exams sit on the tab of the rank they are TAKEN at (the archive lists
# the Scout 3rd exam under Drone and the Trooper 3rd under Scout, which is
# exactly that). Other missions have no unlock condition in the archive: being
# in the class is the gate.
CLASS_DRONE, CLASS_SCOUT, CLASS_TROOPER = 0, 1, 2
TAB_MISSIONS = {
    CLASS_DRONE: [39, 40, 31, 32, 33, 34, 35, 37, 38, 16, 18, 21, 22, 29],
    CLASS_SCOUT: [5, 23, 20, 24, 26],
    CLASS_TROOPER: [19, 25, 27, 30, 36],
}
#: retail group 47/48 index 16: name "Reserved", description "Undecided"
PLACEHOLDER_QUESTS = frozenset({17})
MISSION_CLASS = {q: c for c, qs in TAB_MISSIONS.items() for q in qs}
TAB_ORDER = {q: i for qs in TAB_MISSIONS.values() for i, q in enumerate(qs)}


def rank_class(rank):
    """0 Drone / 1 Scout / 2 Trooper ... for a 1-based held rank."""
    return (max(1, int(rank or 1)) - 1) // 3


def list_rank(quest):
    """The 0-based rank byte a retail 148 entry carries for `quest`: the rank
    an exam is TAKEN at, else the first rank of the mission's class, so each
    sits on its class's "Mission: DG <class>" tab. Unknown quests -> Drone."""
    for held, (q, _, _) in EXAMS.items():
        if q == quest:
            return held - 1
    return 3 * MISSION_CLASS.get(quest, CLASS_DRONE)


def mission_class(quest):
    return list_rank(quest) // 3


def grant(career, quest):
    """Add `quest` to the career's open exams (idempotent). True if added."""
    held = career.setdefault(LEDGER_KEY, [])
    if quest in held:
        return False
    held.append(quest)
    return True


def settle(career, quest):
    """Drop a cleared exam from the ledger (doc_stats calls this after a
    promotion). True if it was there."""
    held = career.get(LEDGER_KEY) or []
    if quest in held:
        held.remove(quest)
        return True
    return False


def mission_list(career, base_ids):
    """The quest ids selector 160 should list for this player: the exams the
    ledger holds (first, and only while their promotion is still ahead of the
    held rank), then `base_ids` minus every exam (the always-available
    missions). Duplicates dropped.

    2026-09-24: only the exam for the rank HELD is listed (a ledger written
    before the retail 3/4/28 fix may hold the wrong one), and the base set is
    gated by rank class and ordered by tab: a mission shows once the player's
    class reaches its tab (lower tabs stay), in the archive's order; quests
    with no known tab keep their given order at the end of the Drone tab."""
    rank = max(1, int(career.get("rank", 1) or 1))
    cls = rank_class(rank)
    out = []
    current = EXAMS.get(rank, (None,))[0]
    for q in career.get(LEDGER_KEY, []) or []:
        q = int(q)
        if q != current:
            continue                       # promoted past it, or a stale id
        if q not in out:
            out.append(q)
    base = [q for q in base_ids
            if q not in EXAM_QUESTS and q not in PLACEHOLDER_QUESTS
            and mission_class(q) <= cls]
    pos = {q: i for i, q in enumerate(base)}
    base.sort(key=lambda q: (mission_class(q), q not in TAB_ORDER,
                             TAB_ORDER.get(q, pos[q])))
    for q in base:
        if q not in out:
            out.append(q)
    return out


# ── ARGENTO'S STORY CHAIN (lnpc 4), 2026-09-24 ───────────────────────────
# quest_scr003.ev_n04, retail (doc_jdis -s doc_retail_lobby_20260923.p2s):
# tableswitch 300..305 at 30, every branch read to its end --
#   300 ID_AR_LOCK_01     "The hour has not yet come. When fate's gears turn,
#                          may we meet again..."
#   301 ID_AR_YOYAKU_01   the standby brush-off (holds a reservation)
#   302 the walk-up cutscene + ID_AR_FIRST_01..05 "do you seek to be the
#       strongest?"; OK -> FIRST_07/08 + checkQuestEvent(4, 2) (@1333);
#       anything else -> FIRST_06 "farewell" and NOTHING is sent
#   303 goto 1961: a silent no-op (never served)
#   304 FIRST_05 alone (the question again); OK -> 07/08 + (4, 2) (@1574)
#   305 ID_AR_MIS01_01..07: "first, advance one rank as a soldier; then see
#       these operations succeed: seek the Mako within the church; fell the
#       two-horned beast in the wastes; raid (奇襲, ambush) a certain enemy
#       stronghold. When all is ended, return to me."
# The scene calls NO rank / quest native and never reportQuestEventDone: the
# SERVER alone knows where a player stands, exactly like the instructors.
# The three operations are SE's own mission descriptions (retail KelStr group
# 48, index = quest - 1), one match each:
#   16 Collector's Mind  "mako capsules have been hidden in the area around
#                         the church"
#   18 Dual Horn Duel    "defeat one of the Dual Horns often seen roaming the
#                         wastelands"
#   22 Iron Curtain      "test your unit's ability to successfully AMBUSH the
#                         enemy's stronghold"
# (the old "5 / 17 / 22" note read 0-based indexes; retail renamed 5 "Assault
# Mission").
# WARNING: INFERRED: (a) 300 is the "chain complete" answer -- FIRST_08 points to "the
# White Emperor at road's end" (Weiss; the Tsviet exam, quest 15, is "Not yet
# implemented" in this build and arrived in the Aug 2006 update), so "the hour
# has not come" is what a finished MIS01 has left; (b) Argento does not ADD
# missions to the list (his lines never say "added to Missions", unlike the
# instructors) -- 16/18/22 stay in the base --solo-quests set; (c) a decline is
# invisible to us (FIRST_06 sends nothing), so "met" is recorded when 302 is
# served and every later walk-up before an accept asks again with 304.
ARGENTO = 4
AR_LOCK, AR_STANDBY, AR_FIRST, AR_SILENT, AR_ASK, AR_MISSIONS = range(300, 306)
AR_ACCEPT_B = 2                   # the b both ev_n04 accept arms send
ARGENTO_QUESTS = (16, 18, 22)
ARGENTO_KEY = "argento"           # career field: {"met": 1, "rank": held at accept}


def argento_progress(career):
    """(rank goal met, [chain quests cleared], [chain quests still open]) for
    a career that has accepted; the rank goal is one above the rank held at
    the accept."""
    st = career.get(ARGENTO_KEY) or {}
    rank = max(1, int(career.get("rank", 1) or 1))
    rank_ok = "rank" in st and rank > int(st["rank"])
    done = career.get("quests") or {}
    cleared = [q for q in ARGENTO_QUESTS if int(done.get(str(q), 0) or 0) > 0]
    return rank_ok, cleared, [q for q in ARGENTO_QUESTS if q not in cleared]


def argento_event(career, b=0, reserved=False):
    """(event id, new ARGENTO_KEY value to store or None, note) for a command
    26 to Argento with sub-code `b` from a player with career `career`."""
    st = dict(career.get(ARGENTO_KEY) or {})
    rank = max(1, int(career.get("rank", 1) or 1))
    if b == AR_ACCEPT_B:
        if "rank" in st:
            return AR_MISSIONS, None, "accepted again (chain open since rank %d)" \
                % st["rank"]
        st.update(met=1, rank=rank)
        return AR_MISSIONS, st, "ACCEPTED at rank %d: goal rank %d + quests %s" \
            % (rank, rank + 1, list(ARGENTO_QUESTS))
    if reserved:
        return AR_STANDBY, None, "standby (holds a reservation)"
    if not st.get("met"):
        st["met"] = 1
        return AR_FIRST, st, "first meeting (the question)"
    if "rank" not in st:
        return AR_ASK, None, "met, never accepted: asks again"
    rank_ok, cleared, left = argento_progress(career)
    if rank_ok and not left:
        return AR_LOCK, None, "chain COMPLETE (rank %d > %d, %s cleared)" \
            % (rank, st["rank"], cleared)
    return AR_MISSIONS, None, "chain open: rank %d (goal > %d)%s, cleared %s, left %s" \
        % (rank, st["rank"], "" if rank_ok else " NOT MET", cleared, left)


def _selftest():
    fails = []

    def check(name, cond):
        if not cond:
            fails.append(name)
        print("  %s %s" % ("ok  " if cond else "FAIL", name))

    def career(rank=1, rp=0, battles=0, held=()):
        return {"rank": rank, "rp": rp, "battles": battles,
                LEDGER_KEY: list(held)}

    # the first exam: no battles -> MADA, 1-2 battles -> BT03, 3 -> NORU grant
    check("no battle -> +6", instructor_event(7, career())[0] == 1006)
    check("two battles -> +5", instructor_event(7, career(battles=2))[0] == 1005)
    ev, q, _ = instructor_event(7, career(battles=3))
    check("three battles -> +3 grants exam 1", (ev, q) == (1003, 1))
    check("exam 1 held -> +2 chatter",
          instructor_event(7, career(battles=3, held=(1,)))[:2] == (1002, None))
    # the tiers: rank 2 needs 4000 for exam 2 (1008 / 1009), rank 8 -> 1026/1027
    check("rank 2, 3999 rp -> +8", instructor_event(7, career(2, 3999, 5))[:2] == (1008, None))
    check("rank 2, 4000 rp -> +9 grants exam 2",
          instructor_event(7, career(2, 4000, 5))[:2] == (1009, 2))
    check("rank 2 holding exam 2 -> +7", instructor_event(7, career(2, 9000, 5, (2,)))[0] == 1007)
    check("rank 6 -> Trooper 3rd = quest 4 at +21 (retail order)",
          instructor_event(7, career(6, 19000, 5))[:2] == (1021, 4))
    check("rank 3 -> Scout 3rd = quest 28, rank 4 -> Scout 2nd = quest 3",
          instructor_event(7, career(3, 7000, 5))[:2] == (1012, 28)
          and instructor_event(7, career(4, 11000, 5))[:2] == (1015, 3))
    check("rank 8, 28000 -> +27 grants exam 8",
          instructor_event(7, career(8, 28000, 5))[:2] == (1027, 8))
    check("rank 9 -> +28 (nothing above)", instructor_event(7, career(9, 0, 5))[0] == 1028)
    check("NPC 10 is +90", instructor_event(10, career(battles=3))[0] == 1093)
    check("standby wins", instructor_event(7, career(battles=3), reserved=True)[0] == 1000)
    # every granted event is in doc_npc's own table for that NPC
    try:
        import doc_npc
        ok = True
        for npc in INSTRUCTORS:
            for c in (career(), career(battles=2), career(battles=3),
                      career(2, 0, 5), career(2, 4000, 5), career(8, 28000, 5),
                      career(9, 0, 5)):
                ok &= instructor_event(npc, c)[0] in doc_npc.NPC_EVENTS[npc]
        check("every served event is in doc_npc.NPC_EVENTS", ok)
    except ImportError:
        print("  skip doc_npc cross-check (not importable)")
    # the ledger
    c = career(battles=3)
    check("grant adds once", grant(c, 1) and not grant(c, 1) and c[LEDGER_KEY] == [1])
    check("list = held exams first, then base minus exams",
          mission_list(c, [1, 2, 3, 16, 17, 30, 99]) == [1, 16, 99])
    # rank tabs (the Lifestream archive): a fresh Drone sees the Drone tab only,
    # Beginner's Course first; a Scout adds the Scout tab; a Trooper everything
    base = [1, 2, 3, 4, 5, 6, 7, 8] + list(range(16, 37)) + [39, 40]
    drone = mission_list({"rank": 1}, base)
    check("fresh Drone: Beginner's Course I/II lead the list",
          drone[:2] == [39, 40])
    check("fresh Drone: no Scout / Trooper missions (5, 23, 19, 30 hidden)",
          not set(drone) & {5, 20, 23, 24, 26, 19, 25, 27, 30, 36})
    check("fresh Drone: the Drone tab in archive order",
          drone == [39, 40, 31, 32, 33, 34, 35, 16, 18, 21, 22, 29])
    scout = mission_list({"rank": 4}, base)
    check("Scout 3rd: Drone tab kept, Scout tab added, Trooper still hidden",
          set(drone) <= set(scout) and {5, 20, 23, 24, 26} <= set(scout)
          and not set(scout) & {19, 25, 27, 30, 36})
    check("Trooper 3rd: all three tabs", {19, 25, 27, 30, 36} <= set(mission_list({"rank": 7}, base)))
    check("148 rank byte: Drone 0, Scout 3, Trooper 6; exams at the rank taken",
          (list_rank(16), list_rank(23), list_rank(30), list_rank(28), list_rank(4))
          == (0, 3, 6, 2, 5))
    check("a stale ledger exam (quest 3 held at rank 3 from the disc order) is hidden",
          3 not in mission_list({"rank": 3, LEDGER_KEY: [3]}, base)
          and mission_list({"rank": 3, LEDGER_KEY: [28]}, base)[0] == 28)
    check("settle removes", settle(c, 1) and c[LEDGER_KEY] == [] and not settle(c, 1))
    c2 = career(3, 0, 5, held=(2,))            # promoted past exam 2 elsewhere
    check("stale exam hidden", mission_list(c2, [2, 16]) == [16])
    check("a career without the field lists the base set",
          mission_list({"rank": 1}, [1, 16]) == [16])
    # scoring
    check("'most' mission wins at the clock", verdict(19, True, "time limit", 0) == "w")
    check("'most' mission loses at its KO limit", verdict(19, True, "time limit", 3) == "l")
    check("'kill' mission loses at the clock", verdict(1, True, "time limit", 0) == "l")
    check("'kill' mission wins on the objective",
          verdict(1, True, WHY_OBJECTIVE + ": 10 kills", 0) == "w")
    check("KO-limit end loses even with no deaths tallied",
          verdict(19, True, WHY_KO + ": 3", 0) == "l")
    check("a quit loses even an 'as many as possible' mission",
          verdict(19, True, WHY_QUIT + " the mission", 0) == "l")
    check("capsule missions place their target; 27 places a field, no target",
          capsule_setup(16) == (7, 7) and capsule_setup(4) == (3, 3)
          and capsule_setup(28) == (5, 5)
          and capsule_setup(27) == (CAPSULE_MOST_FIELD, 0)
          and capsule_setup(1) is None and capsule_setup(19) is None)
    check("capsules_end at the target only",
          capsules_end(16, 7) and not capsules_end(16, 6)
          and not capsules_end(27, 99) and not capsules_end(1, 50))
    check("npc_kill_ends at the target only for kill missions",
          npc_kill_ends(1, 10) and not npc_kill_ends(1, 9)
          and not npc_kill_ends(19, 500) and not npc_kill_ends(2, 50))
    check("every listed default mission has an objective",
          all(q in OBJECTIVES for q in list(range(1, 9)) + list(range(16, 37)) + [39, 40]
              if q != 17))
    # the per-mission setup
    check("every MISSION_SETUP enemy code is in its situation's model set",
          all(c in SITUATION_SETS[(z, st)]
              for z, st, cs, _c in MISSION_SETUP.values() for c in cs))
    check("Course I/II keep the live types (3,3 / 3,3,0 in 201:3001)",
          mission_setup(39) == (201, 3001, [3, 3], 1)
          and mission_setup(40) == (201, 3001, [3, 3, 0], 1))
    check("archive participant limits (Double Attack 2, Steel Wall 6, exams 1)",
          players(29) == 2 and players(22) == 6 and players(26) == 6
          and players(1) == 1 and players(32) == 1 and players(99) == 1)
    check("every set-up mission has an objective",
          all(q in OBJECTIVES for q in MISSION_SETUP))
    # Argento's chain
    a = {"rank": 2, "quests": {}}
    ev, st, _ = argento_event(a)
    check("Argento: first walk-up -> 302 and records met", ev == 302 and st == {"met": 1})
    a["argento"] = st
    check("Argento: met, no accept -> 304 (asks again), nothing stored",
          argento_event(a)[:2] == (304, None))
    ev, st, _ = argento_event(a, b=2)
    check("Argento: (4, 2) accept -> 305 and stores the rank held",
          ev == 305 and st == {"met": 1, "rank": 2})
    a["argento"] = st
    check("Argento: accepted, nothing done -> 305", argento_event(a)[0] == 305)
    check("Argento: a second accept changes nothing", argento_event(a, b=2)[:2] == (305, None))
    a["quests"] = {"16": 1, "18": 2, "22": 1}
    check("Argento: all three cleared but rank not raised -> still 305",
          argento_event(a)[0] == 305)
    a["rank"] = 3
    check("Argento: rank raised + 16/18/22 cleared -> 300 (chain complete)",
          argento_event(a)[0] == 300)
    a["quests"] = {"16": 1, "18": 1, "5": 1, "17": 1}
    check("Argento: quests 5/17 are NOT the chain (22 still open) -> 305",
          argento_event(a)[0] == 305 and argento_progress(a)[2] == [22])
    check("Argento: standby wins on a walk-up",
          argento_event({"argento": {"met": 1}}, reserved=True)[0] == 301)
    try:
        import doc_npc
        check("every Argento event is in doc_npc.NPC_EVENTS[4]",
              all(e in doc_npc.NPC_EVENTS[ARGENTO] for e in range(300, 306)))
        check("the accept b is the one doc_npc.FOLLOWUP knows",
              doc_npc.FOLLOWUP.get((ARGENTO, AR_ACCEPT_B)) == AR_MISSIONS)
    except ImportError:
        print("  skip doc_npc cross-check (not importable)")
    # EXAM_TARGET agrees with doc_stats.EXAM_PROMOTIONS where both speak
    try:
        import doc_stats
        check("EXAM_TARGET == doc_stats.EXAM_PROMOTIONS on shared quests",
              all(doc_stats.EXAM_PROMOTIONS[q] == r for q, r in EXAM_TARGET.items()))
    except ImportError:
        print("  skip doc_stats cross-check (not importable)")
    print("doc_missions selftest: %s" % ("ALL PASS" if not fails else "FAIL %s" % fails))
    return not fails


if __name__ == "__main__":
    sys.exit(0 if _selftest() else 1)
