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
    # 2026-10-05: EX-POTION's Drone table says 50 for 38; our client's own
    # group-49 line says "Defeat 100 DG soldiers", and the client wins
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
#   1. source: the Lifestream fan archive of the 2006 online missions: per
#      mission the MAP, the maximum participants, objective, defeat conditions, time limit, supplies, enemies seen.
#      Its Japanese-derived names map to our US rows: Sniper Threat = 21
#      Sniping Menace, Steel Wall = 22 Iron Curtain, Stolen Capsules! = 23,
#      Collector's Mind (Lv.2/Lv.3) = 16/24/25, Pest Control = 19,
#      Green Encounter = 27, Forest of Grudge = 30, The Consequence of
#      Betrayal = 36, Dual Horn Battlefield = 18.
#   2. The client (2026-10-05, retail patch 20060124_3, MEASURED): a
#      situation LOADS the models of zNNN/brd.bin "Res_<sit>" (ev2045_sub
#      mdlResLoad -> loadchr_bzd); that is SITUATION_SETS. The kind-15 NPC
#      TYPE indexes the zone's CHARACTER table (bzd.bin table 0, 524-byte
#      records: model at +0x20, weapon after it, name +0x9a = group 54) --
#      that is CHARDEF, and npc_type() picks the type. A type whose model the
#      set does not load gets a name plate, HP bar and lock-on but NO BODY
#      (live 10-05, the Dual Horn). The 09-23 reading -- type = index into
#      bzd table 20's list -- only ever worked by coincidence (z201 3001,
#      index 3 = e102 in both).
# MODEL CODES = the in-game names (group 54 via CHARDEF +0x9a):
#   e102 DG Soldier   e015 DG Commander   e028 DG Sniper (+ w005)
#   e037 SOLDIER      e030 Beast Soldier  e020 Dual Horn
#   e019 / e039 Guard Hound   e069 Cactuar / Cactuar King   e038 Bizarre Bug
#   e040 Epiolnis     e041 Sahagin        e042 Red Saucer   e046 Bull Head
#   e047 Sweeper      e026 Twin Sentry
# confidence: "live" = played and won; "high" = archive map + a unique set;
# "low" = a guess worth a look. "capsule" / "base" missions get enemies but
# CANNOT be won yet (no capsule / base report is decoded).
SITUATION_SETS = {
    (201, 3000): ['e030', 'w010'],
    (201, 3001): ['e030', 'w010', 'w003', 'e102'],
    (201, 3002): ['w003', 'w004', 'e036', 'o099', 'g056', 'e102'],
    (201, 3003): ['e038', 'e040', 'e015', 'w003'],
    (201, 3004): ['w003', 'e102'],
    (201, 3005): [],
    (203, 3000): ['w003', 'o099', 'e037', 'e015', 'e102'],
    (203, 3001): ['w003', 'o099', 'e030', 'w010', 'e102'],
    (203, 3002): ['o099', 'w003', 'e030', 'w010', 'e102'],
    (203, 3003): ['o099', 'w003', 'e037', 'e102'],
    (203, 3004): ['o099', 'w003', 'e102'],
    (203, 3005): ['o099', 'w003', 'e042', 'e030', 'w010', 'e102'],
    (204, 3000): ['o099', 'e015', 'w003', 'e030', 'w010'],
    (204, 3001): ['o099', 'e019', 'e039', 'e015', 'w003', 'w004'],
    (204, 3002): ['o099', 'e019', 'e039', 'e069'],
    (204, 3003): ['o099', 'e019', 'e020', 'e039'],
    (204, 3004): ['o099', 'e030', 'w010', 'e028', 'w005', 'w003', 'e102'],
    (204, 3005): ['o099', 'e020', 'e019'],
    (204, 3006): ['o099', 'e019', 'e039', 'e069'],
    (204, 3007): ['o099', 'w003', 'e102'],
    (204, 3008): ['o099', 'e028', 'w005', 'w003', 'g048', 'e102'],
    (205, 3000): ['e038', 'e042'],
    (205, 3001): ['e026', 'e046', 'e042', 'e102', 'w003'],
    (205, 3002): ['e038', 'e042', 'e046'],
    (205, 3003): ['e042', 'e102', 'o099', 'w003'],
    (205, 3004): ['e102', 'w003'],
    (208, 3000): ['w003', 'e030', 'w010', 'e042', 'e015'],
    (208, 3001): ['w003', 'w010', 'e015', 'e042', 'e102'],
    (208, 3002): ['w003', 'e030', 'w010', 'e042', 'e102'],
    (208, 3003): ['e042'],
    (208, 3004): ['e015', 'w010', 'w003', 'e030'],
    (208, 3005): ['w003', 'e102'],
    (212, 3000): ['w003', 'e102'],
    (212, 3001): ['w003', 'e015', 'e102'],
    (212, 3002): ['w003', 'e102', 'e015'],
    (212, 3003): ['e042'],
    (212, 3004): ['e015', 'w010', 'w003', 'e030'],
    (212, 3006): ['w003', 'e030', 'w010', 'e042', 'e015'],
    (231, 3000): ['w003', 'e102'],
    (231, 3001): ['w003', 'e102'],
    (231, 3002): ['w003', 'e039', 'e102'],
}
#: 2026-10-05: NOT a cap -- the brd u32 beside each code is a bitmask of the
#: 8 model variant sub-files the loader reads (static RE, loadchr 0x49cdc8;
#: e102 = 2 = variant 1). Kept as the raw brd data.
SITUATION_CAPS = {
    (201, 3000): {'e030': 1},
    (201, 3001): {'e030': 1, 'e102': 2},
    (201, 3002): {'e036': 1, 'e102': 2},
    (201, 3003): {'e038': 1, 'e040': 1, 'e015': 2},
    (201, 3004): {'e102': 2},
    (201, 3005): {},
    (203, 3000): {'e037': 1, 'e015': 2, 'e102': 2},
    (203, 3001): {'e030': 1, 'e102': 2},
    (203, 3002): {'e030': 1, 'e102': 2},
    (203, 3003): {'e037': 1, 'e102': 2},
    (203, 3004): {'e102': 2},
    (203, 3005): {'e042': 1, 'e030': 1, 'e102': 2},
    (204, 3000): {'e015': 2, 'e030': 1},
    (204, 3001): {'e019': 1, 'e039': 1, 'e015': 2},
    (204, 3002): {'e019': 1, 'e039': 1, 'e069': 1},
    (204, 3003): {'e019': 1, 'e020': 1, 'e039': 1},
    (204, 3004): {'e030': 1, 'e028': 1, 'e102': 2},
    (204, 3005): {'e020': 1, 'e019': 1},
    (204, 3006): {'e019': 1, 'e039': 1, 'e069': 1},
    (204, 3007): {'e102': 2},
    (204, 3008): {'e028': 1, 'e102': 2},
    (205, 3000): {'e038': 1, 'e042': 1},
    (205, 3001): {'e026': 1, 'e046': 1, 'e042': 1, 'e102': 2},
    (205, 3002): {'e038': 1, 'e042': 1, 'e046': 1},
    (205, 3003): {'e042': 1, 'e102': 2},
    (205, 3004): {'e102': 2},
    (208, 3000): {'e030': 1, 'e042': 1, 'e015': 2},
    (208, 3001): {'e015': 2, 'e042': 1, 'e102': 2},
    (208, 3002): {'e030': 1, 'e042': 1, 'e102': 2},
    (208, 3003): {'e042': 1},
    (208, 3004): {'e015': 2, 'e030': 1},
    (208, 3005): {'e102': 2},
    (212, 3000): {'e102': 2},
    (212, 3001): {'e015': 2, 'e102': 2},
    (212, 3002): {'e102': 2, 'e015': 2},
    (212, 3003): {'e042': 1},
    (212, 3004): {'e015': 2, 'e030': 1},
    (212, 3006): {'e030': 1, 'e042': 1, 'e015': 2},
    (231, 3000): {'e102': 2},
    (231, 3001): {'e102': 2},
    (231, 3002): {'e039': 1, 'e102': 2},
}
CHARDEF = {
    201: (
        ('e040', ()),   # type 0  Epiolnis
        ('o099', ()),   # type 1  -
        ('e038', ()),   # type 2  Bizarre Bug
        ('e102', ('w003',)),   # type 3  DG Soldier
        ('e030', ()),   # type 4  Beast Soldier
        ('e047', ()),   # type 5  Sweeper
        ('e036', ('w004',)),   # type 6  -
        ('e030', ()),   # type 7  Beast Soldier
        ('e015', ('w003',)),   # type 8  DG Commander
        ('e030', ()),   # type 9  Beast Soldier
        ('e102', ('w003',)),   # type 10  DG Soldier
        ('e036', ('w004',)),   # type 11  DG General
        ('e102', ('w003',)),   # type 12  DG Soldier
        ('e102', ('w003',)),   # type 13  DG Soldier
        ('e102', ('w003',)),   # type 14  DG Soldier
        ('e102', ('w003',)),   # type 15  DG Soldier
        ('e102', ('w003',)),   # type 16  DG Soldier
        ('e102', ('w003',)),   # type 17  DG Soldier
    ),
    203: (
        ('e047', ()),   # type 0  Sweeper
        ('e026', ()),   # type 1  Twin Sentry
        ('e042', ()),   # type 2  Red Saucer
        ('e046', ()),   # type 3  Bull Head
        ('e041', ()),   # type 4  Sahagin
        ('e015', ('w003',)),   # type 5  DG Commander
        ('e102', ('w003',)),   # type 6  DG Soldier
        ('e036', ('w004',)),   # type 7  DG General
        ('e037', ()),   # type 8  SOLDIER
        ('e102', ('w003',)),   # type 9  DG Soldier
        ('e030', ()),   # type 10  Beast Soldier
        ('e102', ('w003',)),   # type 11  DG Soldier
        ('e046', ()),   # type 12  Bull Head
        ('e026', ()),   # type 13  Twin Sentry
        ('e037', ()),   # type 14  SOLDIER
        ('e015', ('w003',)),   # type 15  DG Commander
        ('e036', ('w004',)),   # type 16  DG General
        ('e047', ()),   # type 17  Sweeper
        ('e102', ('w003',)),   # type 18  DG Soldier
        ('e041', ()),   # type 19  Sahagin
        ('e102', ('w003',)),   # type 20  DG Soldier
        ('e102', ('w003',)),   # type 21  DG Soldier
        ('e030', ()),   # type 22  Beast Soldier
        ('e030', ()),   # type 23  Beast Soldier
        ('e102', ('w003',)),   # type 24  DG Soldier
        ('e102', ('w003',)),   # type 25  DG Soldier
        ('e102', ('w003',)),   # type 26  DG Soldier
        ('e102', ('w003',)),   # type 27  DG Soldier
        ('e102', ('w003',)),   # type 28  DG Soldier
        ('e102', ('w003',)),   # type 29  DG Soldier
        ('e102', ('w003',)),   # type 30  DG Soldier
        ('e042', ()),   # type 31  Red Saucer
        ('e030', ()),   # type 32  Beast Soldier
        ('e102', ('w003',)),   # type 33  DG Soldier
        ('e102', ('w003',)),   # type 34  DG Soldier
        ('e102', ('w003',)),   # type 35  DG Soldier
        ('e102', ('w003',)),   # type 36  DG Soldier
        ('o099', ()),   # type 37  -
    ),
    204: (
        ('o099', ()),   # type 0  -
        ('e020', ()),   # type 1  Dual Horn
        ('e020', ()),   # type 2  Dual Horn
        ('e020', ()),   # type 3  Dual Horn
        ('e039', ()),   # type 4  Guard Hound
        ('e019', ()),   # type 5  Guard Hound
        ('e015', ('w003',)),   # type 6  DG Commander
        ('e028', ('w005',)),   # type 7  DG Sniper
        ('e028', ('w005',)),   # type 8  DG Sniper
        ('e102', ('w003',)),   # type 9  DG Soldier
        ('e102', ('w003',)),   # type 10  DG Soldier
        ('e020', ()),   # type 11  Dual Horn
        ('e030', ()),   # type 12  Beast Soldier
        ('e015', ('w003',)),   # type 13  DG Commander
        ('e015', ('w003',)),   # type 14  DG Commander
        ('e015', ('w003',)),   # type 15  DG Commander
        ('e015', ('w003',)),   # type 16  DG Commander
        ('e102', ('w003',)),   # type 17  DG Soldier
        ('e102', ('w003',)),   # type 18  DG Soldier
        ('e039', ()),   # type 19  Guard Hound
        ('e019', ()),   # type 20  Guard Hound
        ('e039', ()),   # type 21  Guard Hound
        ('e019', ()),   # type 22  Guard Hound
        ('e102', ('w003',)),   # type 23  DG Soldier
        ('e102', ('w003',)),   # type 24  DG Soldier
        ('e069', ()),   # type 25  Cactuar
        ('e069', ()),   # type 26  Cactuar King
        ('e069', ()),   # type 27  Cactuar
        ('e069', ()),   # type 28  Cactuar King
    ),
    205: (
        ('e038', ()),   # type 0  Bizarre Bug
        ('e046', ()),   # type 1  Bull Head
        ('e042', ()),   # type 2  Red Saucer
        ('e046', ()),   # type 3  Bull Head
        ('e046', ()),   # type 4  Bull Head
        ('e026', ()),   # type 5  Twin Sentry
        ('e102', ('w003',)),   # type 6  DG Soldier
        ('e102', ('w003',)),   # type 7  DG Soldier
        ('e102', ('w003',)),   # type 8  DG Soldier
        ('e000', ()),   # type 9  -
        ('e102', ('w003',)),   # type 10  DG Soldier
        ('e102', ('w003',)),   # type 11  DG Soldier
        ('e042', ()),   # type 12  Red Saucer
        ('e038', ()),   # type 13  Bizarre Bug
        ('e102', ('w003',)),   # type 14  DG Soldier
        ('e102', ('w003',)),   # type 15  DG Soldier
        ('o099', ()),   # type 16  -
    ),
    208: (
        ('e042', ()),   # type 0  Red Saucer
        ('e030', ()),   # type 1  Beast Soldier
        ('e015', ('w003',)),   # type 2  DG Commander
        ('e102', ('w003',)),   # type 3  DG Soldier
        ('e102', ('w003',)),   # type 4  DG Soldier
        ('e037', ()),   # type 5  SOLDIER
        ('e102', ('w003',)),   # type 6  DG Soldier
        ('e030', ()),   # type 7  Beast Soldier
        ('e030', ()),   # type 8  Beast Soldier
        ('e042', ()),   # type 9  Red Saucer
        ('e047', ()),   # type 10  Sweeper
        ('e030', ()),   # type 11  Beast Soldier
        ('e015', ('w003',)),   # type 12  DG Commander
        ('e030', ()),   # type 13  Beast Soldier
        ('e015', ('w003',)),   # type 14  DG Commander
        ('e015', ('w003',)),   # type 15  DG Commander
        ('e102', ('w003',)),   # type 16  DG Soldier
        ('e102', ('w003',)),   # type 17  DG Soldier
        ('e102', ('w003',)),   # type 18  DG Soldier
        ('e030', ('w003',)),   # type 19  Beast Soldier
        ('e102', ('w003',)),   # type 20  DG Soldier
        ('e102', ('w003',)),   # type 21  DG Soldier
        ('e015', ('w003',)),   # type 22  DG Commander
        ('e102', ('w003',)),   # type 23  DG Soldier
        ('e102', ('w003',)),   # type 24  DG Soldier
        ('e015', ('w003',)),   # type 25  DG Commander
        ('e042', ()),   # type 26  Red Saucer
        ('e000', ()),   # type 27  -
        ('o099', ()),   # type 28  -
        ('e047', ()),   # type 29  Sweeper
    ),
    212: (
        ('o099', ()),   # type 0  -
        ('e026', ()),   # type 1  Twin Sentry
        ('e042', ()),   # type 2  Red Saucer
        ('e046', ()),   # type 3  Bull Head
        ('e041', ()),   # type 4  Sahagin
        ('e015', ('w003',)),   # type 5  DG Commander
        ('e102', ('w003',)),   # type 6  DG Soldier
        ('e015', ('w003',)),   # type 7  DG General
        ('e037', ()),   # type 8  SOLDIER
        ('e102', ('w003',)),   # type 9  DG Soldier
        ('e030', ()),   # type 10  Beast Soldier
        ('e102', ('w003',)),   # type 11  DG Soldier
        ('e015', ('w003',)),   # type 12  DG Commander
        ('e015', ('w003',)),   # type 13  DG Commander
        ('e102', ('w003',)),   # type 14  DG Soldier
        ('e102', ('w003',)),   # type 15  DG Soldier
        ('e102', ('w003',)),   # type 16  DG Soldier
        ('e102', ('w003',)),   # type 17  DG Soldier
        ('e102', ('w003',)),   # type 18  DG Soldier
        ('e015', ('w003',)),   # type 19  DG Commander
    ),
    231: (
        ('o099', ()),   # type 0  -
        ('e026', ()),   # type 1  Twin Sentry
        ('e042', ()),   # type 2  Red Saucer
        ('e046', ()),   # type 3  Bull Head
        ('e041', ()),   # type 4  Sahagin
        ('e015', ('w003',)),   # type 5  DG Commander
        ('e102', ('w003',)),   # type 6  DG Soldier
        ('e036', ('w004',)),   # type 7  DG General
        ('e037', ()),   # type 8  SOLDIER
        ('e102', ('w003',)),   # type 9  DG Soldier
        ('e030', ()),   # type 10  Beast Soldier
        ('e102', ('w003',)),   # type 11  DG Soldier
        ('e102', ('w003',)),   # type 12  DG Soldier
        ('e102', ('w003',)),   # type 13  DG Soldier
        ('e102', ('w003',)),   # type 14  DG Soldier
        ('e019', ()),   # type 15  Guard Hound
        ('e039', ()),   # type 16  Guard Hound
    ),
}


#: 2026-10-05: each CHARDEF row's MAX HP (bzd table 0 +0x30, u16; static RE
#: scratchpad re-headshot/). Kind 15 carries the NPC's HP and we sent a flat
#: 100 for every enemy (--npc-spawn-hp): live, Dual Horn Duel's Dual Horn
#: (22000 here) fell like a soldier. Same zones and order as CHARDEF.
CHARDEF_HP = {
    201: (3000, 1000, 45, 800, 280, 4760, 800, 320, 1450, 80, 680, 2500, 600, 400, 200, 150, 180, 200),
    203: (4500, 250, 45, 90, 1000, 1500, 380, 3500, 550, 200, 90, 100, 100, 800, 650, 1600, 3500, 2000, 80, 150, 640, 640, 500, 90, 100, 165, 165, 60, 100, 100, 6000, 100, 1500, 100, 150, 180, 330, 1000),
    204: (1000, 18000, 10000, 22000, 100, 300, 1800, 450, 130, 70, 70, 11000, 100, 620, 1800, 620, 1750, 800, 400, 50, 300, 80, 480, 100, 100, 120, 60, 120, 100),
    205: (90, 250, 70, 200, 190, 1800, 150, 150, 1700, 5000, 450, 450, 70, 180, 100, 100, 1000),
    208: (91, 100, 1650, 330, 350, 850, 300, 90, 540, 91, 800, 100, 1200, 10, 1000, 1400, 550, 450, 270, 100, 100, 100, 1650, 100, 350, 750, 91, 1000, 1000, 800),
    212: (1000, 250, 45, 90, 1000, 1500, 100, 2000, 550, 200, 90, 100, 980, 980, 400, 270, 220, 220, 220, 1000),
    231: (1000, 250, 45, 90, 1000, 1500, 120, 3500, 550, 200, 90, 120, 500, 500, 500, 300, 10000),
}


# quest -> (zone, situation, enemy codes spawned at once, confidence)
# (a dead enemy is replaced 5 s later, so a "defeat N" count is reachable)
MISSION_SETUP = {
    # 2026-10-05: 2 at once (1 was mostly searching; 3 swarmed the player,
    # live 18:40Z; the situation has 12 fixed Beast Soldier spawn groups)
    1: (201, 3000, ["e030"] * 2, "high"),            # Jungle: 10 Beast Soldiers
                                                     # (one at a time: e030 cap 1)
    # 2026-10-05: 3 / 5 / 7 / 18 / 26 / 27 / 29 / 31 moved -- their situation's
    # brd set did not load the model they asked for (208:3003 loads e042 only,
    # 208 has no Res_3006, e020 is the Dual Horn, e037 is the SOLDIER)
    3: (208, 3004, ["e015", "e015", "e030"], "high"),  # Church: 3 Commanders + beasts
    # 2026-10-05: the 2006 player wiki (Mission page): the base at A7 is
    # defended by DG Commanders, sniped from inside the church
    5: (208, 3001, ["e015", "e015", "e102"], "low"),  # Church base (3001 has the
                                                     # base AND its capture zone)
    6: (204, 3000, ["e015", "e015"], "high"),        # Wastelands: 5 Commanders
    7: (208, 3001, ["e015"], "high"),                # Church: 12 Commanders, one at a time
    # 2026-10-05: the wiki and two 2006 blogs: the Dual Horn comes with blue
    # and red wolves (Guard Hounds), shot for ammo drops; only the Dual Horn
    # counts (KILL_TARGETS)
    18: (204, 3003, ["e020", "e019", "e039"], "high"),  # "defeat ONE Dual Horn"
    # 2026-10-05 (archive "Pest Control": only the sewer's insects): no Bull Head
    19: (205, 3002, ["e038"], "high"),               # Sewer: Bizarre Bugs
    # archive: "as many DG Soldiers", the bugs a distraction; no Jungle set
    # loads e102 with e038, so Commanders stand in for the soldiers
    20: (201, 3003, ["e015", "e015", "e038"], "low"),  # Jungle: soldiers + bugs
    21: (204, 3004, ["e028", "e102", "e102", "e030"], "high"),  # sniper + others
                                                     # (e028 cap 1, e102 cap 2)
    23: (203, 3003, ["e102", "e102"], "low"),        # Kalm capsules: not winnable
    # 2026-10-05: + a hound (wiki: wolves alongside; fc2 blog: "1 red dog")
    26: (204, 3005, ["e020", "e019"], "high"),       # 5 Dual Horns, one at a time
    # 2026-10-05: 3006 (not 3002) is the Wastelands' Cactuar set -- every
    # e069 spawn group is there; 3002's groups are hounds + soldiers it never
    # loads
    27: (204, 3006, ["e069"], "low"),                # Green Encounter: Cactuar; capsules
    28: (205, 3003, ["e102", "e102"], "high"),       # Sewer capsules: not winnable
    29: (203, 3003, ["e102", "e102", "e037"], "high"),  # Kalm: DG Soldiers + SOLDIER
    # 2026-10-05: wiki: soldiers at the cave, a General at the base
    30: (201, 3002, ["e102", "e102", "e036"], "low"),  # Jungle base
    31: (208, 3005, ["e102", "e102"], "high"),       # Map Exercise Church
    32: (201, 3004, ["e102", "e102"], "high"),       # Map Exercise Jungle
    33: (204, 3007, ["e102", "e102"], "high"),       # Map Exercise Wastelands
    34: (205, 3004, ["e102", "e102"], "high"),       # Map Exercise Sewers
    35: (203, 3004, ["e102", "e102"], "high"),       # Map Exercise Kalm
    # 2026-10-05: wiki + fc2 blog: fast targets plus small red/pink guard
    # robots -- 3005 is the Kalm set that also loads the Red Saucer (e042);
    # only the soldier and beast soldier count (KILL_TARGETS)
    36: (203, 3005, ["e102", "e030", "e042"], "high"),  # Kalm: soldier + beast + robots
    # 2026-10-05: the archive puts both Beginner's Courses in the Battlefield
    # Ruins (they were served, and won live, in the Jungle). Course I: 5
    # DG Soldiers; Course II: 3 DG Soldiers "while avoiding the Guard Hound"
    # -- 231:3002 is the Ruins set that loads the hound (e039)
    # Course I: "We have stationed special DG Soldiers" -- all 5 at once, one
    # per 231:3001 pool point (the archive: "Defeat 5 DG Soldiers")
    39: (231, 3001, ["e102"] * 5, "high"),          # Beginner's Course I
                                                     # (types: MISSION_TYPES)
    40: (231, 3002, ["e039", "e102", "e102", "e102"], "high"),  # Course II:
                                                     # the hound + 3 moving soldiers
    # 2026-09-29: the missions that had NO enemies (archive + table 20; each
    # situation is one of its arena's that HAS spawn nodes)
    4: (201, 3001, ["e102", "e102", "e030"], "high"),  # Trooper 3rd: capsules,
                                                       # DG Soldiers + Beast Soldiers
    # 2026-10-05: 203:3001 -- the all-DG-Soldier set with 8 capsule generators
    # (3003 has none; capsules sat on a ring around the start)
    25: (203, 3001, ["e102", "e102"], "high"),       # Collector's Mind Lv.3:
                                                        # "a lot of DG Soldiers"
    37: (212, 3001, ["e102", "e102"], "high"),       # Map Exercise Train Graveyard
    # 2026-10-05: 231:3000, the Ruins' plain soldier set (3001 is Course I's
    # head-only range)
    38: (231, 3000, ["e102", "e102"], "high"),       # Map Exercise Battlefield Ruins
    # base assaults: the archive names no enemies -- DG soldiers from the only
    # set with spawn nodes on each map
    2: (204, 3000, ["e015", "e030"], "low"),         # Drone 1st: Wastelands base
                                                     # (3000 is the one with a base)
    8: (203, 3000, ["e102", "e102", "e015"], "low"),  # Trooper 1st: Kalm base
    # 2026-10-05: wiki: the base on the high point is guarded by Twin Sentry
    # turrets, with DG Soldiers, Red Saucers and Bull Heads respawning. Two
    # turrets ride the normal spawn nodes (SE's fixed turret placement is not
    # decoded)
    22: (205, 3001, ["e026", "e026", "e102", "e042", "e046"], "low"),  # Iron Curtain
    # 16 / 24 (Collector's Mind I / II): the archive lists capsules and no
    # enemies -- left without
}
# 2026-10-05: BASE MISSIONS (static RE + MEASURED retail bzd, scratchpad
# re-basemission/). A mission base is the PvP Team Base gimmick: the client
# creates the situation controller's table-14 rows [a, a+count) at zone load,
# SKIPS every base-class row while the record's Base Durability (wire+16) is
# 0 (retail 0x0066e440 -> zonemgr+0x2b0 |= 8), takes the owner from the
# placement byte +0x50, and binds it with notify kind 29 (HP = that same
# Base Durability). We sent 0 and no kind 29 -> "no base on the map" (live
# 10-05, Iron Curtain). quest -> (table-14 row = the gimmick instance kind 29
# names, owning team, the base's world position). Every one is a g056 owned
# by team 1 (the enemy side); no mission has a base for the players.
MISSION_BASES = {
    30: (21, 1, (1850.0, -11.5, -567.5)),      # Forest of Enmity, z201:3002
    22: (54, 1, (-624.6, 283.5, -343.8)),      # Iron Curtain, z205:3001
    8: (7, 1, (-806.3, -11.5, 1538.4)),        # Trooper 1st exam, z203:3000
    2: (2, 1, (-1666.3, -14.3, -134.9)),       # Drone 1st exam, z204:3000
    5: (69, 1, (300.7, -272.0, 1602.7)),       # Church base, z208:3001
}
#: the Base Durability a base mission's record carries (the client's base HP);
#: retail's value is unknown, Team Base's live 8000 is the one we have seen
MISSION_BASE_HP = 8000


# "Maximum Participants" per the archive (the mission screen's limit, command
# 29 answer body[37]). Unlisted quests: 1. WARNING: A second player joining a
# mission is UNTESTED end to end.
#: 2026-10-05: the map exercises' caps from EX-POTION's 2006 Drone mission
#: table (ex-potion.com/dcff7/mdgd.html): Church 1, Jungle 3, Wastelands 3,
#: Sewers 2, Kalm 3, Train Graveyard 2, Battlefield Ruins 4.
MAX_PLAYERS = {
    1: 1, 2: 1, 3: 1, 4: 1, 5: 2, 6: 1, 7: 1, 8: 1, 16: 1, 18: 3, 19: 1,
    20: 3, 21: 3, 22: 6, 23: 4, 24: 1, 25: 1, 26: 6, 27: 3, 28: 1, 29: 2,
    30: 2, 31: 1, 32: 3, 33: 3, 34: 2, 35: 3, 36: 3, 37: 2, 38: 4, 39: 1,
    40: 1,
}
# archive maps for rows with no enemy set above (zone numbers as served)
# 2026-09-24: + the map exercises 37 Train Graveyard (z212) / 38 Battlefield
# Ruins (z231) -- both arenas have a spawn now (ZONE_SPAWNS_DEFAULT)
ARCHIVE_ZONES = {2: 204, 4: 201, 8: 203, 16: 208, 22: 205, 24: 205, 25: 203,
                 37: 212, 38: 231}
# 2026-09-24: the TIME LIMIT per mission, seconds, from the Lifestream
# online-missions fan archive (each mission's time limit). None of these were
# encoded before: a mission ran on whatever the client's record carried (600 s
# live) or --gs-battle-length. 3/4/28 are matched by CONTENT (our client's
# objective text), which the archive files under rotated exam names. Unlisted
# quests keep the record's own limit.
MISSION_TIME = {
    1: 300, 2: 300, 3: 600, 4: 300, 5: 540, 6: 300, 7: 480, 8: 600,
    16: 600, 18: 420, 19: 300, 20: 300, 21: 300, 22: 300, 23: 480, 24: 900,
    25: 420, 26: 600, 27: 480, 28: 270, 29: 300, 30: 300, 31: 3600, 36: 480,
    39: 3600, 40: 3600,
    # 2026-10-05, archive: "most if not all maps had a standard time limit
    # set to 60 minutes" (the map exercises; 31 had it already)
    32: 3600, 33: 3600, 34: 3600, 35: 3600, 37: 3600, 38: 3600,
}


def npc_type(zone, sit, code):
    """2026-10-05: the kind-15 TYPE that draws model `code` in (zone, sit):
    the first index of the zone's CHARACTER table (bzd table 0, CHARDEF) whose
    model is `code` and whose weapon models the situation's brd set also
    loads; None when none does. The type is NOT an index into the situation's
    model list (the old models.index(code)): live 10-05 type 1 in z204 drew a
    name plate "Dual Horn" (chardef[1] = e020) with no body, because Res_3002
    never loads e020 -- and most rows named a model their set never loads."""
    loaded = set(SITUATION_SETS.get((zone, sit), ()))
    if code not in loaded:
        return None
    for i, row in enumerate(CHARDEF.get(zone, ())):
        if row[0] == code and set(row[1]) <= loaded:
            return i
    return None


#: 2026-10-05 (static RE, scratchpad re-headshot/): explicit kind-15 types,
#: in the controller's pool-node order, where the first chardef row of a model
#: is the wrong enemy. The arena's spawn-group table (client bzd table 25,
#: named by each pool type-4 node's u16 at +0x48) gives the Beginner's Courses
#: z231 rows 12 / 13 / 14: HEAD-ONLY DG Soldiers (hit-part table 2: head x10,
#: every other part 0; damage mask 0x48 zeroes melee; HP 500), 12 / 13 standing,
#: 14 moving. Type 6, the first e102 row, takes body damage. Offline: the
#: client's own damage routine 0x681130 -> body 0 on all 12 parts for 12-14.
MISSION_TYPES = {
    39: [12, 12, 13, 13, 14],     # "special DG Soldiers ... only head damage"
    40: [16, 14, 14, 14],         # the Guard Hound + 3 moving head-only soldiers
}


def npc_hp(zone, t, default):
    """The kind-15 HP for chardef type `t` of `zone`: its own max HP
    (CHARDEF_HP), else `default` (--npc-spawn-hp)."""
    hps = CHARDEF_HP.get(zone, ())
    return hps[t] if 0 <= t < len(hps) and hps[t] else default


def can_draw(zone, sit, t):
    """True when chardef type `t` of `zone` draws in situation `sit`: its
    model and weapon models are all in the situation's brd set."""
    defs = CHARDEF.get(zone, ())
    loaded = set(SITUATION_SETS.get((zone, sit), ()))
    return (0 <= t < len(defs) and defs[t][0] in loaded
            and set(defs[t][1]) <= loaded)


def group_type(zone, sit, group, rng=None):
    """2026-10-05: the kind-15 type a spawn group (doc_mission_spawns
    "pool_groups" entry: [flag, [[type, weight], ...]]) fields in (zone,
    sit): a weighted pick among its drawable types (weight 0 only when none
    weighs more), None when it has none (the node stays empty)."""
    import random
    rng = rng or random
    pairs = [(t, w) for t, w in (group[1] if group else ()) if can_draw(zone, sit, t)]
    live = [(t, w) for t, w in pairs if w > 0] or pairs
    if not live:
        return None
    if len(live) == 1:
        return live[0][0]
    return rng.choices([t for t, _w in live], [max(w, 1) for _t, w in live])[0]


def kill_target_type(quest, zone, t):
    """True when chardef type `t` is (one of) `quest`'s named kill target."""
    want = KILL_TARGETS.get(quest)
    defs = CHARDEF.get(zone, ())
    return bool(want) and 0 <= t < len(defs) and defs[t][0] in want


def mission_setup(quest):
    """(zone, situation, [kind-15 types], players) for `quest`, or None. A
    model the situation cannot draw is left out (selftest keeps that empty).
    MISSION_TYPES overrides the first-row lookup with the arena's own types."""
    row = MISSION_SETUP.get(quest)
    if row is None:
        return None
    zone, sit, codes, _conf = row
    if quest in MISSION_TYPES:
        return zone, sit, list(MISSION_TYPES[quest]), players(quest)
    types = [npc_type(zone, sit, c) for c in codes]
    return zone, sit, [t for t in types if t is not None], players(quest)


#: 2026-09-26: each mission's initial supplies (source: Lifestream fan
#: archive, online missions). Retail topped the player up per MISSION; there
#: is no general enemy ammo drop in the archive (Silent Killing's 9 bullets
#: were fewer than its enemies). Unlisted quests and PvP tables get
#: the standard 36 handgun / 18 rifle / 60 machine gun. The archive gives no
#: figure for Trooper 2nd's rifle rounds, which is read as the standard 18.
HANDGUN, RIFLE, MG = 0x62300000, 0x62300001, 0x62300002
POTION = 0x69320000                # the ONLINE Potion (category 0x6932)
#: 2026-10-05 (static RE, scratchpad re-bomb/): the Bomb Fragment, a thrown
#: grenade -- in this build (item record, use script 0x18 -> RequestBomb ->
#: status bit 0x40 echoed by kind 43), never handed out until now. 3 a stack.
BOMB = 0x69320008
PHOENIX_DOWN = 0x69320004
STANDARD_SUPPLIES = ((HANDGUN, 36), (RIFLE, 18), (MG, 60))
#: 2026-10-05: Beginner's Course I / II per the 2006 player wiki (dc.jpn.org
#: Mission page, "H(300), ポ(3), フ(1)"): 300 handgun rounds, 3 Potions and 1
#: Phoenix Down each. The 3 Bomb Fragments are Course III's (a later mission),
#: so Course II no longer gets them.
SUPPLIES = {
    39: ((HANDGUN, 300), (POTION, 3), (PHOENIX_DOWN, 1)),  # Beginner's Course I
    40: ((HANDGUN, 300), (POTION, 3), (PHOENIX_DOWN, 1)),  # Beginner's Course II
    7: ((HANDGUN, 54), (RIFLE, 18), (MG, 120), (POTION, 3)),  # Trooper 2nd exam
}
SUPPLY_ITEMS = frozenset((HANDGUN, RIFLE, MG, POTION, BOMB, PHOENIX_DOWN))


def supplies(quest, standard=STANDARD_SUPPLIES):
    """The (item, quantity) pairs a player starts `quest` with (None = PvP)."""
    return SUPPLIES.get(quest, standard)


BULLET_CATEGORY = 0x6230           # item id >> 16 of every bullet


def respawn_refill(start, held=None):
    """2026-09-26: the (item, qty) rows kind 25 carries on a KO (<= 3; the
    client SETS each qty into the bag, 0x00be7de8).

    Retail (source: April 2006 player blog, on the March update): a respawn refills BULLETS
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
#: 2026-10-05: capsule missions with NO enemies -> (zone, situation) whose
#: item generators hand out Mako Capsules (doc_item_generators): the record
#: carries the situation and the capsules go on those generators. Not in
#: MISSION_SETUP, which would spawn an enemy set.
CAPSULE_SITUATIONS = {
    16: (208, 3003),     # Collector's Mind: 10 capsule generators in Church 3003
    24: (205, 3002),     # Collector's Mind Lv.2: 12 in Sewers 3002
}


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


#: 2026-10-05: the enemy a "kill" mission names (SE's objective lines above).
#: Only a kill of one of these models counts; a quest not listed counts any
#: enemy (its line names none, or the map exercises' "defeat N enemies").
KILL_TARGETS = {
    1: frozenset(("e030",)),            # Defeat 10 Beast Soldiers
    3: frozenset(("e015",)),            # Defeat 3 DG Commanders
    6: frozenset(("e015",)),            # Defeat 5 DG Commanders
    7: frozenset(("e015",)),            # Defeat 12 DG Commanders
    18: frozenset(("e020",)),           # Defeat the Dual Horn
    26: frozenset(("e020",)),           # Defeat 5 Dual Horns
    36: frozenset(("e102", "e030")),    # Defeat the DG Soldier and Beast Soldier
    # "as many as possible" missions count only their named enemy too
    19: frozenset(("e038",)),           # Bizarre Bugs
    20: frozenset(("e015",)),           # "DG Soldiers" (Commanders stand in)
    21: frozenset(("e028",)),           # the snipers (archive: "normal DG
                                        # soldiers and Beast Soldiers ... would
                                        # not count")
    29: frozenset(("e102", "e037")),    # DG Soldiers and SOLDIERs
    40: frozenset(("e102",)),           # 3 DG Soldiers, not the Guard Hound
}


def kill_counts(quest, npc_type):
    """True when killing a kind-15 `npc_type` counts toward `quest`'s target.
    An unknown type (None: a request-30 report) counts."""
    want = KILL_TARGETS.get(quest)
    if want is None or npc_type is None:
        return True
    row = MISSION_SETUP.get(quest)
    defs = CHARDEF.get(row[0], ()) if row else ()
    return 0 <= npc_type < len(defs) and defs[npc_type][0] in want


def npc_kill_ends(quest, npc_kills):
    """True when a reported enemy-kill count completes a 'kill' mission."""
    kind, n, _ = objective(quest)
    return kind == "kill" and n > 0 and npc_kills >= n


def verdict(quest, over, why, deaths, won_base=None):
    """'w' / 'l' for a mission room. A KO-limit end loses; an objective end
    wins; a clock end wins only a 'most' mission ("as many as possible" has
    no failure but the KO limit and time is the only way it ends).
    `won_base` = for a room the BASE ended ("team N's base destroyed", with
    or without the occupation), whether this player's side is the one that
    took it. The battle room words that end its own way (battleroom
    base_report / arenadata.base_occupy_tick), so a "base" mission -- exams
    2 and 8 among them -- never matched WHY_OBJECTIVE and always lost."""
    if (ko_out(quest, deaths) or (why or "").startswith(WHY_KO)
            or (why or "").startswith(WHY_QUIT)):
        return "l"
    if over and (why or "").startswith(WHY_OBJECTIVE):
        return "w"
    if over and won_base is not None and "base destroyed" in (why or ""):
        return "w" if won_base else "l"
    if objective(quest)[0] == "most" and over:
        return "w"
    return "l"


# ── RANK TABS (2026-09-24) ────────────────────────────────────────────────
# SE filed every mission under a rank class, the client's "Mission: DG <class>"
# tabs (L2 / R2; thresholds 0/3/6/9/12/15 at lobby.pex 0x00b12158). Source:
# the Lifestream online-missions fan archive, its Drone, Scout and Trooper
# pages; the later pages (Commander / General / Tsviet) hold only
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
    check("a 'base' mission (exam 2) wins when the players' side took the base",
          verdict(2, True, "team 1's base destroyed", 0, won_base=True) == "w"
          and verdict(2, True, "team 1's base destroyed and occupied by 0x10",
                      0, won_base=True) == "w")
    check("a 'base' mission loses when the players' own base fell",
          verdict(2, True, "team 0's base destroyed", 0, won_base=False) == "l")
    check("a base end without a known side still loses (old callers)",
          verdict(2, True, "team 1's base destroyed", 0) == "l")
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
    _t3 = mission_setup(3)[2]           # [Commander, Commander, Beast Soldier]
    check("a kill mission counts only the enemy it names",
          kill_counts(3, _t3[0]) and not kill_counts(3, _t3[2])
          and kill_counts(3, None) and kill_counts(31, 3))
    check("every kill target is a model its mission spawns",
          all(set(MISSION_SETUP[q][2]) & w for q, w in KILL_TARGETS.items())
          and all(any(kill_counts(q, t) for t in mission_setup(q)[2])
                  for q in KILL_TARGETS))
    check("every listed default mission has an objective",
          all(q in OBJECTIVES for q in list(range(1, 9)) + list(range(16, 37)) + [39, 40]
              if q != 17))
    # the per-mission setup
    # 2026-10-05: no per-model cap check -- the brd u32 SITUATION_CAPS holds is
    # a model VARIANT bitmask (loadchr 0x49cdc8), not an instance count (the
    # instance pool 0x644e40 is shared); see doc-arena-node-types-corrected
    check("every SITUATION_SETS row has its caps",
          set(SITUATION_CAPS) == set(SITUATION_SETS))
    check("every MISSION_SETUP enemy code is in its situation's model set",
          all(c in SITUATION_SETS[(z, st)]
              for z, st, cs, _c in MISSION_SETUP.values() for c in cs))
    # 2026-10-05: the Courses moved to the archive's Battlefield Ruins
    # (they were LIVE in the Jungle as 201:3001 types 3, 3 / 3, 3, 4)
    check("Course I: the 5 HEAD-ONLY soldiers (231:3001, chardef 12/13/14)",
          mission_setup(39) == (231, 3001, [12, 12, 13, 13, 14], 1))
    check("Course II: the Guard Hound + 3 moving head-only soldiers (16, 14 x3)",
          mission_setup(40) == (231, 3002, [16, 14, 14, 14], 1)
          and CHARDEF[231][16][0] == "e039")
    check("enemy HP from the chardef: Dual Horn Duel's Dual Horn (its spawn group's "
          "type 3) 22000, Course I's "
          "head-only soldiers 500; an unknown type keeps the flag's value",
          npc_hp(204, 3, 100) == 22000 and CHARDEF[204][3][0] == "e020"
          and npc_hp(231, 12, 100) == 500 and npc_hp(231, 99, 100) == 100
          and all(len(CHARDEF_HP[z]) == len(CHARDEF[z]) for z in CHARDEF))
    check("every MISSION_TYPES type draws the model its row names, one per code",
          all(len(ts) == len(MISSION_SETUP[q][2])
              and [CHARDEF[MISSION_SETUP[q][0]][t][0] for t in ts] == MISSION_SETUP[q][2]
              and all(set(CHARDEF[MISSION_SETUP[q][0]][t][1])
                      <= set(SITUATION_SETS[MISSION_SETUP[q][:2]])
                      for t in ts)
              for q, ts in MISSION_TYPES.items()))
    check("every set-up row draws ALL its models (no code its brd set cannot load)",
          all(len(mission_setup(q)[2]) == len(r[2]) for q, r in MISSION_SETUP.items()))
    check("every type draws the model its row asked for",
          all([CHARDEF[r[0]][t][0] for t in mission_setup(q)[2]] == list(r[2])
              for q, r in MISSION_SETUP.items()))
    check("Dual Horn Duel: z204 situation 3003, type 1 = e020 (the Dual Horn)",
          mission_setup(18)[:2] == (204, 3003) and mission_setup(18)[2][0] == 1
          and CHARDEF[204][1][0] == "e020")
    check("Dual Horn Duel: the hounds come along but do not count",
          len(mission_setup(18)[2]) == 3
          and [kill_counts(18, t) for t in mission_setup(18)[2]] == [True, False, False])
    check("TWIN: the Dual Horn cannot be drawn in 204:3002 (its set has no e020)",
          npc_type(204, 3002, "e020") is None)
    check("archive participant limits (Double Attack 2, Steel Wall 6, exams 1)",
          players(29) == 2 and players(22) == 6 and players(26) == 6
          and players(1) == 1 and players(99) == 1)
    check("map exercise caps (EX-POTION): Church 1, Jungle 3, Wastelands 3, "
          "Sewers 2, Kalm 3, Train Graveyard 2, Ruins 4",
          [players(q) for q in (31, 32, 33, 34, 35, 37, 38)] == [1, 3, 3, 2, 3, 2, 4])
    check("Beginner's Courses: 300 HG + 3 Potions + 1 Phoenix Down, no bombs",
          supplies(39) == supplies(40) == ((HANDGUN, 300), (POTION, 3), (PHOENIX_DOWN, 1))
          and PHOENIX_DOWN in SUPPLY_ITEMS)
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
