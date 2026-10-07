#!/usr/bin/env python3
"""Dirge of Cerberus CAREER STATS + MEDALS -- the server-side tally (2026-09-13).

Nothing on this server has ever scored a DoC match: the battle ends with an
all-zero result record (notify kind 4), the Ranking menu serves 0 for everyone,
the Status screen reads Rank Points -1 / 0, and the POL Viewer's DoC profile
leaves Rank and Ranking Points empty ("no match has ever been scored", a
long-standing known gap). This module is the one place a character's career lives, so every
surface reads the same numbers:

  * the Ranking menu     -> push_rankings() writes doc_rank's "ind" categories
  * the Status screen    -> career() (wire placement: see the world-door notes)
  * the battle result    -> record_battle() returns what was awarded
  * the POL Viewer       -> viewer_fields() = (rank 1..16, ranking points)

WHAT IS SE'S, read out of the shipped string tables (the client's online string table):

  RANK LADDER  group 30 [13..28], 1-based on the wire (0 and >16 both render
               DGD-3, doc-user-record-decoded):
                 1 DGD-3  2 DGD-2  3 DGD-1  4 DGSC-3 5 DGSC-2 6 DGSC-1
                 7 DGT-3  8 DGT-2  9 DGT-1 10 DGC-3 11 DGC-2 12 DGC-1
                13 DGG-3 14 DGG-2 15 DGG-1 16 TSV
  PROMOTION    is by EXAMINATION, not by points: quest N's name is 47:(N-1) and
               its reward 51:(N-1) -- "Promotion to DG Drone 2nd Class" etc.
               Quest 28 is the Trooper 3rd Class exam (SE added it later; its
               slot sits among the missions).
  QUEST REWARDS group 51: fixed Rank Points (+10 .. +120) and Gil (300 ..
               2000); five say "(Based on Performance)" (QUEST_RP / QUEST_GIL).
  MEDALS       group 60 [16..39] names, [40..63] the award rules, one per medal,
               read out of SE's 20060124_3 lobby.bin (the January 2006 launch
               build every served client runs since the 09-22 retail rebase):
               BT Conquest / BT Medal of Honor / BT Medal of Dishonor (BT 1st,
               2nd, most KO'd), Team Merit (TBT: kills - KOs), Survivor (TDM:
               most kills among those standing at the end), Slayer (TBT/TDM:
               most kills), Assault (TBS: entered the destroyed enemy base and
               won), Capsule Seeker (TCP: most capsule CARRIERS KO'd), Last
               Capsule (TCP), Flag Carrier / First Flag (TFL), Leader Slayer
               (TLD), Base Attack (TBS), two Reserved, the tournament and weekly
               medals (31..38) and a Reserved. See MEDALS below.
               WARNING: 2026-09-26: this module used to carry the 2005 BETA set
               (Medal of Dishonor, First Attack, Iron Seal, Healer, Seeker, FA,
               Survival, five class medals, seven chevrons) -- the English of
               the disc/prototype string table. The launch client names those
               slots differently, so every medal we paid was shown as another.

WHAT IS OURS (SE's server logic is lost; every number here is a PLACEHOLDER in
the same sense as doc_shop's prices, and each is a module constant):
  * the Rank Points a battle pays (RP_*), the "Kill Rate" formula, the tie
    and zero rules of the "most" medals (MOST_NEEDS_ONE), the BT runner-up
    order, the Last Capsule reading.
  * the per-player battle inputs (kills, KOs, heals, ...) are NOT yet read off
    the wire -- until the client's own report (game-server request 44, the reply
    to kind 4) is decoded, a battle records only who played, which side won and
    how long it lasted.
"""
import os
import struct
import time

RANK_MIN, RANK_MAX = 1, 16
RANK_CODES = ("DGD-3", "DGD-2", "DGD-1", "DGSC-3", "DGSC-2", "DGSC-1",
              "DGT-3", "DGT-2", "DGT-1", "DGC-3", "DGC-2", "DGC-1",
              "DGG-3", "DGG-2", "DGG-1", "TSV")
RANK_NAMES = ("DG Drone 3rd Class", "DG Drone 2nd Class", "DG Drone 1st Class",
              "DG Scout 3rd Class", "DG Scout 2nd Class", "DG Scout 1st Class",
              "DG Trooper 3rd Class", "DG Trooper 2nd Class",
              "DG Trooper 1st Class", "DG Commander 3rd Class",
              "DG Commander 2nd Class", "DG Commander 1st Class",
              "DG General 3rd Class", "DG General 2nd Class",
              "DG General 1st Class", "Tsviets")

#: quest id -> the rank its examination promotes to (51:(N-1) "Promotion to ...")
# 2026-09-24: retail group 47 order (28 = Scout 3rd, 3 = Scout 2nd, 4 = Trooper
# 3rd); the disc's order had 3/4/28 shifted (doc_missions.EXAMS).
EXAM_PROMOTIONS = {1: 2, 2: 3, 28: 4, 3: 5, 6: 6, 4: 7, 7: 8, 8: 9, 9: 10,
                   10: 11, 11: 12, 12: 13, 13: 14, 14: 15, 15: 16}
#: quest id -> fixed Rank Points / Gil = the reward text the client SHOWS,
#: group 51 index N-1. WARNING: MEASURED: SE's 20060124_3 lobby.bin and
#: every served lobby.bin since the 09-22 retail rebase (20260923_8 listfit,
#: 20260924 dg2fit / victoryfit) read 51:4 "+30", 51:22 "2000 Gil", 51:30..34
#: "1000 Gil" ... The old values here (250/50/100/50/150/200 RP, 3000 and
#: 1500 Gil, "???" for 21/29/35) were the PRE-rebase English text (US-preview
#: rows), so the server paid what no player's screen said. "Based on
#: Performance" ones (19 gil, 20/21/27/29 RP) pay the battle rates instead.
QUEST_RP = {5: 30,      # Assault Mission         (archive +30, agrees)
            16: 10,     # Collector's Mind        (archive +10, agrees)
            18: 40,     # Dual Horn Battlefield   (archive +40, agrees)
            22: 50,     # Steel Wall              (archive Aug-2006 +95)
            24: 15,     # Collector's Mind Lv.2   (archive +15, agrees)
            25: 20,     # Collector's Mind Lv.3   (archive +20, agrees)
            26: 60,     # Dual Horn Family        (archive +60, agrees)
            30: 50,     # Forest of Grudge        (archive Aug-2006 +65)
            36: 35,     # Consequence of Betrayal (archive +35, agrees)
            # 41-43: SE's unnamed test missions (Train Graveyard Mission,
            # Devastated Church 2, Desert Test Mission), their own text
            41: 100, 42: 120, 43: 100}
#: SOURCED twice: the client's text and the Lifestream fan archive's mission
#: pages agree on every one. Beginner Course 3 (1000), Treasure
#: Retrieval Order! (1500), Sahagin Dance? (1000), Cactus Dance? (3000), Way of
#: Justice (3000), D-1 (4000), Last Banban-G (6000) and Green Mission (by
#: performance) are later missions -- not in our build's group 47.
QUEST_GIL = {23: 2000,                  # Stolen Capsules! (51:22)
             31: 1000, 32: 1000, 33: 1000, 34: 1000, 35: 1000,  # Map Exercises
             37: 1000, 38: 1000,        # Map Exercise Train Graveyard / Ruins
             39: 300, 40: 500}          # Beginner's Course I / II
#: NOT paid, on purpose: 51:9 "+10 Rank Points" and 51:10 "3000 Gil" sit on
#: quests 10 / 11, the DG Commander 2nd / 1st exams (47:9 / 47:10) -- SE's Jan
#: text for those three rows (51:8 says "Promotion to DG Scout 3rd Class") does
#: not match the exams; the exams promote (EXAM_PROMOTIONS). 51:16 "Gil" is
#: quest 17, "Reserved" (doc_missions.PLACEHOLDER_QUESTS).
# 27 Green Encounter / 29 Double Attack: rank points by performance (fan
# archive and client 51:26 / 51:28 agree)
QUEST_PERFORMANCE_RP = (20, 21, 27, 29)
QUEST_PERFORMANCE_GIL = (19,)

# group-60 index -> medal name (the index is SE's own; 16..39). 2026-09-26
# MEASURED: SE's 20060124_3 data/etc/lobby.bin group 60 (doc_kelstr.py), the
# served English being an offline run of the client's own code (doc_rebase_lobby_en). The rule
# after each is SE's own sentence, 60:[index + 24], with its mode tags.
MEDALS = {
    16: "BT Conquest Medal",       # [40] winner of an individual battle (BT)
    17: "BT Medal of Honor",       # [41] runner-up of an individual battle (BT)
    18: "BT Medal of Dishonor",    # [42] KO'd the most in an individual battle (BT)
    19: "Team Merit Medal",        # [43] highest kills minus KOs (TBT, GBT)
    20: "Survivor Medal",          # [44] most kills among the survivors (TDM, GDM)
    21: "Slayer",                  # [45] most enemies defeated (TBT TDM GBT GDM)
    22: "Assault Medal",           # [46] entered the destroyed enemy base and
                                   #      brought victory (TBS, GBS)
    23: "Capsule Seeker Medal",    # [47] most capsule carriers KO'd, making
                                   #      them drop (TCP, GCP)
    24: "Last Capsule Medal",      # [48] obtained the last mako capsule (TCP, GCP)
    25: "Flag Carrier Medal",      # [49] carried flags back for the most points (TFL)
    26: "First Flag Medal",        # [50] carried a flag back fastest (TFL)
    27: "Leader Slayer Medal",     # [51] KO'd the enemy leader most (TLD, GLD)
    28: "Base Attack Medal",       # [52] attacked the base most boldly (TBS, GBS)
    29: "Reserved", 30: "Reserved",                     # 予備 [53] [54]
    31: "Individual Tournament Winner",                 # [55]
    32: "Team Tournament Winner",                       # [56]
    33: "Team Tournament Runner-up",                    # [57]
    34: "Team Tournament 3rd Place",                    # [58]
    35: "Weekly Rank Points 1st",                       # [59]
    36: "Weekly Defeats 1st",                           # [60]
    37: "Weekly Team Wins 1st",                         # [61]
    38: "Weekly Solo Wins 1st",                         # [62]
    39: "Reserved",                                     # [63]
}
M_BT_CONQUEST, M_BT_HONOR, M_BT_DISHONOR, M_TEAM_MERIT, M_SURVIVOR, M_SLAYER, \
    M_ASSAULT, M_CAPSULE_SEEKER, M_LAST_CAPSULE, M_FLAG_CARRIER, M_FIRST_FLAG, \
    M_LEADER_SLAYER, M_BASE_ATTACK = range(16, 29)
#: The Results window's medals PER MODE. MEASURED the launch
#: client's own table, retail lobby_rel 0x00b18d20 (doc_modules/lobby_rel.bin,
#: base 0x00AA0000), three s8 medal ids per mode row, -1 = none:
#:   [3 5] [4 5] [6 12] [7 8] [11] [9 10] [3 5] [0 1 2] [0 1 2]
#: (the prototype's 0x00afa348 table, which its Results window 0x00ac04c4
#: indexes by mode * 3, is the same list). The row -> mode NAME pairing is
#: INFERRED from SE's own tags in 60:[40..52] -- every row lists exactly the
#: medals whose sentence names that mode. No row lists 13/14 (Reserved) or
#: 15+ (tournament / weekly): those are not battle medals.
MODE_MEDALS = {
    "TBT": (M_TEAM_MERIT, M_SLAYER),
    "TDM": (M_SURVIVOR, M_SLAYER),
    "TBS": (M_ASSAULT, M_BASE_ATTACK),
    "TCP": (M_CAPSULE_SEEKER, M_LAST_CAPSULE),
    "TLD": (M_LEADER_SLAYER,),
    "TFL": (M_FLAG_CARRIER, M_FIRST_FLAG),
    "BT": (M_BT_CONQUEST, M_BT_HONOR, M_BT_DISHONOR),
}
#: OURS: a "most X" medal needs X > 0 and a UNIQUE leader (a tie awards
#: nobody); Team Merit's kills - KOs must be > 0 as well.
MOST_NEEDS_ONE = True
#: 2026-09-26: the medal counts a career holds were paid under the 2005 beta
#: rules until now, into slots the launch client names differently (an Iron
#: Seal showed as BT Medal of Dishonor, the Drone chevron every career got
#: as "Team Tournament 3rd Place"). A career without this tag has its old
#: counts MOVED to "medals_2005" (kept, not shown) the first time it is read.
MEDAL_SET = "20060124"

#: doc_rank Individual category -> how to read it off a career (sec 4gl names).
#: Categories 7..17 are the PROTOTYPE's medal tabs (its label table 0x00af58a0
#: names group-60 entries 16, 19, 20, 21, 28, 30, 23, 25, 27, 29 by tab
#: position); the launch client's Ranking has no medal tab at all (retail
#: label table 0x00b149e4 holds only 43:24.. = 0xac18..0xac26, MEASURED
#: 2026-09-26). Kept for the prototype and the web board, by index.
RANK_TABS = {
    0: lambda c: c["rp"],
    1: lambda c: c["bt"]["w"],
    2: lambda c: win_rate(c["bt"]),
    3: lambda c: c["tbt"]["w"],
    4: lambda c: win_rate(c["tbt"]),
    5: lambda c: c["kills"],
    6: lambda c: kill_rate(c),
    7: lambda c: medal_count(c, 16), 8: lambda c: medal_count(c, 19),
    9: lambda c: medal_count(c, 20), 10: lambda c: medal_count(c, 21),
    11: lambda c: medal_count(c, 23), 12: lambda c: medal_count(c, 25),
    14: lambda c: medal_count(c, 28), 15: lambda c: medal_count(c, 29),
    16: lambda c: medal_count(c, 30), 17: lambda c: medal_count(c, 27),
}

# PLACEHOLDER economy (SE's is lost)
RP_WIN, RP_DRAW, RP_LOSS = 30, 15, 10
RP_PER_KILL = 5
RP_MIN_SECONDS = 30          # a battle shorter than this pays nothing
HISTORY_MAX = 20
RP_MAX = 0x7FFFFFFF

#: PvP GIL (2026-09-26). SOURCED for ONE mode: player guide (FFCheats), tips
#: page, a 2-player Team Base Battle gil recipe: the loser ends with 9300 and
#: the winner 1000 more, with both players holding 9 Chocobo Coins (9000). So a TBR battle paid 300 for a loss and 1300 for a win.
#: OURS: the same two amounts for every PvP mode (no source gives another
#: mode's) and the loss rate for a draw (no source).
BATTLE_GIL = {"w": 1300, "l": 300, "d": 300}
#: CHOCOBO COINS (item 0x67300001). SOURCED: player guide (FFCheats), tips
#: page: each coin picked up is worth 1000 gil, up to 9; and the recipe above (9 coins
#: = 9000 of the 9300). MEASURED on our build: the client's item property row
#: for 0x67300001 (0x01fa8144 + 24*171) has +14 u16 = 9 (the carry cap, as
#: Potion's 3) and +16 u16 = 1000 -- the only nonzero word there in the whole
#: 474-row table, read as the coin's gil value (INFERRED). Paid at the end of
#: every battle / mission, win or lose (OURS for a lost mission: the guides say
#: the coins pay out at the end and say nothing about failing).
COIN_ITEM = 0x67300001
COIN_GIL = 1000
COIN_CAP = 9
#: SOURCED: the PlayOnline Additional Manual (see Stats.record_leave)
LEAVE_RP_PENALTY = 10

MODES = ("BT", "TBT", "FA", "MISSION")

# ---------------------------------------------------------------------------
# THE WEEKLY MEDALS (2026-09-26). SE's sentences, 20060124_3 lobby.bin group 60
# (doc_kelstr.py; English = an offline run of the client's own code (doc_rebase_lobby_en)):
#   [35] 週間ランクポイント１位   [59] 週間ランキングポイントをもっとも稼いだ者に
#                                    与えられる勲章。 "earned the most weekly
#                                    ranking points"
#   [36] 週間撃破数１位           [60] 週間撃破数をもっとも稼いだ者に ...
#                                    撃破数 = ENEMIES DEFEATED (60:[43] sets it
#                                    against 戦闘不能回数, times KO'd)
#   [37] 週間チーム戦勝利数１位   [61] 週間チーム戦勝利回数を ... team battle wins
#   [38] 週間個人戦勝利数１位     [62] 週間個人戦勝利回数を ... individual wins
# They are medal ids 19..22 (index - MEDAL_BASE): not battle medals, no holder
# slot in the kind-4 record. They reach the client through the world door's
# medal mask (LOGIN_MEDAL_MASK_OFF, bit n = id n, 24 ids) and the career
# record's per-id counts (+168 + 4*id, id < MEDAL_IDS) -- both carry 19..22.
# The four are the weekly form of the Ranking menu's own categories (RANK_TABS
# 0 rank points, 5 kills, 3 TBT wins, 1 BT wins), so each reads the SAME
# number the career keeps:
#   rp      net rank points that week: every change to c["rp"] -- battle and
#           quest pay, and the leave penalty as a negative (OURS: 稼いだ is
#           "earned"; the ranking it mirrors is the net total)
#   kills   enemies defeated, battles and missions (c["kills"] counts both)
#   team_w  wins in a team battle: every table tallied as TBT (TBT TDM TCP TLD
#           TFL) or FA (TBS); a cleared mission is not a battle win
#   solo_w  wins in an individual battle (BT)
# OURS (SE's server logic is lost): the week runs Monday 00:00 JST to the next
# (WEEK_START, docudp --week-start); a tie awards nobody and a count must be
# above zero (WEEKLY_NEEDS_ONE, the MOST_NEEDS_ONE rule); no minimum battles.
# history is capped (HISTORY_MAX), so the week keeps its own running tallies:
# data["weekly"][week start epoch][key], closed once into data["weeks_closed"].
# ---------------------------------------------------------------------------
WEEK_SECS = 7 * 86400
WEEK_START = "mon 00:00 +09:00"
WEEKLY_MEDALS = (("rp", 35), ("kills", 36), ("team_w", 37), ("solo_w", 38))
TEAM_WIN_MODES = ("TBT", "FA")
SOLO_WIN_MODES = ("BT",)
WEEKLY_NEEDS_ONE = True
_WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def parse_week_start(spec):
    """"mon 00:00 +09:00" -> the week's phase in seconds (0..WEEK_SECS): a
    week starts at every epoch t with t % WEEK_SECS == phase. ValueError on a
    malformed spec."""
    parts = str(spec).strip().lower().split()
    if len(parts) not in (2, 3) or parts[0][:3] not in _WEEKDAYS:
        raise ValueError("week start %r: want 'mon 00:00 +09:00'" % (spec,))
    day = _WEEKDAYS.index(parts[0][:3])
    hh, mm = (int(x) for x in parts[1].split(":"))
    tz = parts[2] if len(parts) == 3 else "+00:00"
    if tz[0] not in "+-" or not (0 <= hh < 24 and 0 <= mm < 60):
        raise ValueError("week start %r: want 'mon 00:00 +09:00'" % (spec,))
    th, tm = (int(x) for x in tz[1:].split(":"))
    off = (th * 3600 + tm * 60) * (-1 if tz[0] == "-" else 1)
    # epoch 0 = Thursday 1970-01-01 00:00 UTC
    return ((day - 3) % 7 * 86400 + hh * 3600 + mm * 60 - off) % WEEK_SECS


def week_of(t, phase):
    """The start (epoch seconds) of the week holding time `t` -- the week id."""
    t = int(t)
    return t - (t - phase) % WEEK_SECS


def new_week_tally():
    return {f: 0 for f, _idx in WEEKLY_MEDALS}


def coin_gil(coins):
    """Gil for the Chocobo Coins a player holds at the end: 1000 each, at
    most 9 count."""
    return COIN_GIL * max(0, min(int(coins or 0), COIN_CAP))


def win_rate(wld):
    """The Status screen's rate: (W + D/2) / battles, 0 with no battles."""
    n = wld["w"] + wld["l"] + wld["d"]
    return (wld["w"] + wld["d"] / 2.0) / n if n else 0.0


def kill_rate(c):
    """OURS: kills / (kills + KOs) -- a 0..1 ratio, so it always fits the
    renderer's u32 / 10^9 (which caps at 4.2949)."""
    n = c["kills"] + c["kos"]
    return c["kills"] / float(n) if n else 0.0


def medal_count(c, idx):
    return int(c["medals"].get(str(idx), 0))


def clamp_rank(r):
    try:
        r = int(r)
    except (TypeError, ValueError):
        return RANK_MIN
    return min(max(r, RANK_MIN), RANK_MAX)


# ---------------------------------------------------------------------------
# THE WIRE (MEASURED 2026-09-13 offline against the client's own store routine,
# ALL PASS -- byte routes run through the client's own code; the LABEL of each
# value is read off the page renderers, i.e. inferred)
#
#   WORLD DOOR (selector 2), setUserData src = body[44] -> self record R:
#     body[56..59] u32  -> R+732  MEDAL-EARNED BITMASK, bit n = medal id n
#     body[68..71] s32  -> R+740  RANK POINTS (Status page 0, "%d")
#     body[131]    u8   -> R+763  RANK, 1-based 1..16 (the page-0 ladder)
#   CAREER RECORD = the answer (140) to selector 139, which the Status window
#   sends EVERY time it opens (arm 0x00bcd4e0 -> 0x00bc9f98, state 44 -> 2).
#   272-B record rec+k <- body[12+k] (k < 44), body[16+k] (44..163),
#   body[24+k] (164..263), body[28+k] (264..267); body[56..59], [180..187] and
#   [288..291] are skipped by the scatter.
#     +0 W  +4 L  +36 battles      page 1 row 2 "W - L" (D = total - W - L)
#     +8, +12                      page 1 rows 0/1, and page 0's ratio row
#                                  "%s(%d/%d)" -- OURS: kills / KOs
#     +20 W  +40 played            page 1 row 10 -- OURS: missions
#     {played, W, D} triples for mode TYPES 1 (+44) 2 (+56) 3 (+68) 4 (+80)
#       6 (+92) 8 (+116) 9 (+128)  page 1 rows 3..9 -- MEASURED 09-13: type
#                                  1 = TBT, 2 = TDM, 3 = TBS (FA), 4 = TCP,
#                                  6 = TFL, 8 = TBR, 9 = TFR; labels authored
#                                  in PS2-0010 20260913_F (lobby 28:252..272)
#     +164                         page 1 row 11 -- OURS: MVP
#     +168 + 4*id                  MEDAL COUNT per medal id (0..23); shown
#                                  only if the id's BIT is set; >= 10000
#                                  prints 9999
#     +264 / +266 u16              rank-ladder marker masks ($m03 / $m04) --
#                                  meaning unknown, sent 0
#   Medal id n = group-60 entry 16+n (BT Conquest Medal 0 .. Reserved 23;
#   see MEDALS -- the 09-13 labels were the 2005 beta names); "Medals Earned" = the number of SET BITS.
# ---------------------------------------------------------------------------
CAREER_REQ, CAREER_ANS = 139, 140
CAREER_REC_LEN = 268
LOGIN_MEDAL_MASK_OFF = 56
LOGIN_RP_OFF = 68
LOGIN_RANK_OFF = 131
#: 2026-10-01: the Status window's "Public / Anonymous" setting (manual p.36
#: 公開設定). The client sends lobby command 6 (Anonymous) / 7 (Public) and
#: flips its own copy at once; the self record keeps it at R+0x2fa bit 0x04 =
#: world-door body[129] (the byte that also carries the reservation 0x01 and
#: the novice mark 0x40), a peer's at user-record wire+30. MEASURED on the
#: retail lobby (re-visibility/rt_vis_proof.py). No client code hides another
#: player's record on that bit: the server must (selector 140).
LOGIN_FLAGS_OFF = 129
PRIVATE_BIT = 0x04
MEDAL_BASE = 16                  # group-60 index of medal id 0
MEDAL_IDS = 24
# 2026-09-13 MEASURED (an offline run of the client's own code (doc_statuspage2_rows) runs the page
# renderer 0x00ac8d90): the rows label +44 TBT, +56 TDM, +68 TBS (Base Siege =
# FA's core destroy), +80 TCP, +92 TFL, +116 TBR, +128 TFR. BT is a separate mode
# family with no row on this page; the old {"BT": 44, "TBT": 56} put Solo
# results on the Team Battle row and Team Battle results on Deathmatch.
MODE_TRIPLES = {"TBT": 44, "FA": 68}


def career_body_offset(k):
    """Where record byte k rides in the 140 answer body."""
    if k < 44:
        return 12 + k
    if k < 164:
        return 16 + k
    if k < 264:
        return 24 + k
    return 28 + k


def medal_mask(c):
    m = 0
    for idx, n in (c.get("medals") or {}).items():
        mid = int(idx) - MEDAL_BASE
        if 0 <= mid < MEDAL_IDS and n > 0:
            m |= 1 << mid
    return m


def career_record(c):
    """The 268-byte career record for one career dict."""
    rec = bytearray(CAREER_REC_LEN)

    def put(off, v):
        struct.pack_into("<I", rec, off, max(0, min(int(v), 0xFFFFFFFF)))
    w = sum(c[m]["w"] for m in ("bt", "tbt", "fa"))
    l_ = sum(c[m]["l"] for m in ("bt", "tbt", "fa"))
    d = sum(c[m]["d"] for m in ("bt", "tbt", "fa"))
    put(0, w)
    put(4, l_)
    put(36, w + l_ + d)
    put(8, c["kills"])
    put(12, c["kos"])
    put(20, c["missions"]["cleared"])
    put(40, c["missions"]["cleared"] + c["missions"]["failed"])
    for mode, off in MODE_TRIPLES.items():
        t = c[mode.lower()]
        put(off, t["w"] + t["l"] + t["d"])
        put(off + 4, t["w"])
        put(off + 8, t["d"])
    put(164, c.get("mvp", 0))
    for idx, n in (c.get("medals") or {}).items():
        mid = int(idx) - MEDAL_BASE
        if 0 <= mid < MEDAL_IDS:
            put(168 + 4 * mid, n)
    return bytes(rec)


def career_body(c, subchannel=7):
    """The 140 answer body carrying career_record(c)."""
    rec = career_record(c)
    body = bytearray(career_body_offset(CAREER_REC_LEN - 1) + 1)
    body[0] = subchannel & 0xFF
    body[1] = CAREER_ANS
    for k in range(CAREER_REC_LEN):
        body[career_body_offset(k)] = rec[k]
    return bytes(body)


def apply_login(body, c):
    """Write the medal mask, rank points and rank into a selector-2 answer body
    (a bytearray), padding it out if it is short."""
    need = LOGIN_RANK_OFF + 1
    if len(body) < need:
        body += bytes(need - len(body))
    struct.pack_into("<I", body, LOGIN_MEDAL_MASK_OFF, medal_mask(c))
    struct.pack_into("<i", body, LOGIN_RP_OFF, min(max(0, int(c["rp"])), RP_MAX))
    body[LOGIN_RANK_OFF] = clamp_rank(c["rank"])
    if c.get("private"):
        body[LOGIN_FLAGS_OFF] |= PRIVATE_BIT
    return body


# ---------------------------------------------------------------------------
# THE BATTLE RESULT = game-server notify KIND 4, record at body[20] (MEASURED
# 2026-09-13 byte by byte through arm 0x00bc1760, run offline in the
# emulator). The client's result windows read a 740-byte copy.
#   +0  u8   OUTCOME: bit0 set = WIN; bit0 and bit1 clear = LOSE; 2 = DRAW
#            (isBattleWin2 > 0 / == 0 / < 0 -> act_win / act_lose / act_draw).
#            WARNING: an all-zero record is a LOSS.
#   +8  u32  RANK POINTS, the NEW TOTAL: the client shows value - R+740 (the
#            world door's body[68]) as the gain and stores the value.
#   +16 u32  GIL, the NEW TOTAL, same rule against R+744 (world door body[52]).
#            WARNING: The zero record we used to send set BOTH to 0 on screen.
#   +20 u32  OR'd into R+732 = the MEDAL-EARNED mask (bit n = medal id n)
#   +2 / +6 / +24 / +26  u16 the RESULTS SCREEN's rank-point counts: Enemies
#            Defeated, Times KO'd, Teammate KO'd, Kill Streak Bonus
#            (results_rp; the client multiplies them by its own weights)
#   +28 u8   BATTLE TYPE: bit4 = team battle (the team RP rows), bit5 = a
#            mission's "Reward" page (bit5+bit6 = "S..D Rank Reward"), neither
#            = individual BT. bit1 / bit2 / bit3 = the win banner "%s Wins by
#            Kill Count" / "by Mako Capsule Count" / "%s's Base Captured"
#   +29 u8   WINNER: BT = the winner's roster slot; team = the team (0/1)
#   +30..43  14 award-holder ROSTER SLOTS; 0xFF (>= 32) = nobody. WARNING: 0 names
#            roster slot 0 -- so zeros hand them all to the first player.
#            MEASURED: holder h IS MEDAL ID h (label table
#            0x00afca68 = group 60 [16+h]: 0 BT Conquest .. 12 Base Attack,
#            13 Reserved); every battle medal (MODE_MEDALS) is an id <= 12, so
#            all of them have a holder slot, and 15..23 (tournament / weekly)
#            are not battle medals. The arm turns slot n into roster[n]'s
#            character id at block+632+4h.
#   +44 u8   RANK, written to R+763 only if 1..254
#   +46 u16  "Score"
#   +48 u32 / +52 u32  item REWARD id / quantity (added to the bag)
#   +60/+124/+188/+252  four u16[32] per-roster-slot columns, TRANSPOSED into
#            16-byte player records (block+120+16n: +0 charid, +4 col +60,
#            +6 col +124, +8 col +252 (s16 rank points), +10 col +188,
#            +12 team). Roster = selector 38's order, self LAST.
#   +316..327  the MODE BLOCK, the team rows' counts (mode_block)
#   +328 u8  players in the battle -> "Battle Scale Bonus Factor"
# 2026-10-01: these are the RETAIL offsets, MEASURED by an offline run of the
# retail arm 0x00BC9610 (doc_capsule_church_slot07_20260924.p2s, every byte
# 0..399 set alone; re-rp/retail_kind4_map.py). The 09-13 map above was the
# pre-retail build: from +44 on everything sat 4 bytes later (rank +48,
# score +50, item +52/+56, columns +64.., block +320, count +332) and there
# were 15 holder slots -- on the retail client our rank landed in "Score"
# and the item id in its quantity.
# ---------------------------------------------------------------------------
RESULT_LEN = 400
RES_OUTCOME, RES_RP_TOTAL, RES_GIL_TOTAL, RES_MEDALS = 0, 8, 16, 20
RES_KILLS, RES_KOS, RES_TEAM_KOS, RES_STREAK = 2, 6, 24, 26
RES_TYPE, RES_WINNER = 28, 29
RES_TYPE_KILLS, RES_TYPE_CAPSULES, RES_TYPE_BASE = 0x02, 0x04, 0x08
RES_TYPE_TEAM, RES_TYPE_REWARD = 0x10, 0x20
RES_HOLDERS, RES_HOLDER_COUNT = 30, 14
RES_RANK, RES_SCORE, RES_ITEM, RES_ITEM_QTY = 44, 46, 48, 52
RES_COLUMNS = (60, 124, 188, 252)       # kills, KOs, mode value, rank points
RES_MODE_BLOCK, RES_MODE_BLOCK_LEN, RES_PLAYERS = 316, 12, 328
RES_SLOTS = 32
OUTCOME_CODES = {"w": 1, "l": 0, "d": 2, "void": 2}


def mode_block(mode, block=None):
    """The 12-byte MODE BLOCK (record +316) for mode byte `mode`, from the
    same keys results_rp reads, so the screen's rows are the rows we paid."""
    b = block or {}
    g = lambda k: int(b.get(k, 0) or 0) & 0xFFFF
    out = bytearray(RES_MODE_BLOCK_LEN)
    if mode == 1:
        struct.pack_into("<H", out, 0, g("team_kills"))
    elif mode == 2:
        struct.pack_into("<H", out, 0, g("survivors"))
    elif mode == 3:
        out[0] = g("base_flags") & 0xFF
        out[1] = 1 if g("base_attack") else 0
        struct.pack_into("<HH", out, 2, g("own_base_hp"), g("enemy_base_left"))
    elif mode == 4:
        struct.pack_into("<HHIH", out, 0, g("carriers_killed"),
                         g("capsule_obtained"),
                         int(b.get("hold_ms", 0) or 0) & 0xFFFFFFFF,
                         g("capsules_end"))
    elif mode == 5:
        struct.pack_into("<HHH", out, 0, g("leaders_killed"),
                         g("leader_points_lost"), g("leader_points_earned"))
    elif mode == 6:
        struct.pack_into("<6H", out, 0, g("flag_carriers_killed"),
                         g("flags_returned"), g("flags_taken"),
                         g("flag_obtained"), g("flag_points_earned"),
                         g("flag_points_lost"))
    return bytes(out)


def result_record(outcome, rp_total, gil_total, mask, rank, score=0,
                  item=(0, 0), holders=None, columns=None, counts=None,
                  rtype=0, winner=None, mode=None, block=None, players=0):
    """The 400-byte kind-4 record (the RETAIL layout, see above). `outcome`
    is 'w' / 'l' / 'd' (or 'void'). `holders` = {medal id 0..13
    (group-60 index - MEDAL_BASE): roster slot}; `columns` = one (kills,
    kos, mode value, rank points) per roster slot, in the RECIPIENT's roster
    order (selector 38: the others, then itself). `counts` = (kills, kos,
    team_kos, streak) for the recipient's own rank-point rows, `rtype` the
    +28 battle-type bits, `winner` the +29 byte, `mode` / `block` the mode
    block, `players` the battle-scale count."""
    rec = bytearray(RESULT_LEN)
    rec[RES_OUTCOME] = OUTCOME_CODES.get(outcome, 2)
    for off, v in zip((RES_KILLS, RES_KOS, RES_TEAM_KOS, RES_STREAK),
                      counts or ()):
        struct.pack_into("<H", rec, off, max(0, min(int(v), 0xFFFF)))
    rec[RES_TYPE] = rtype & 0xFF
    if winner is not None:
        rec[RES_WINNER] = winner & 0xFF
    if mode is not None:
        rec[RES_MODE_BLOCK:RES_MODE_BLOCK + RES_MODE_BLOCK_LEN] = mode_block(mode, block)
    rec[RES_PLAYERS] = max(0, min(int(players or 0), 0xFF))
    struct.pack_into("<I", rec, RES_RP_TOTAL, max(0, min(int(rp_total), RP_MAX)))
    struct.pack_into("<I", rec, RES_GIL_TOTAL,
                     max(0, min(int(gil_total), 0x7FFFFFFF)))
    struct.pack_into("<I", rec, RES_MEDALS, mask & 0xFFFFFF)
    rec[RES_HOLDERS:RES_HOLDERS + RES_HOLDER_COUNT] = b"\xff" * RES_HOLDER_COUNT
    for h, slot in (holders or {}).items():
        if 0 <= h < RES_HOLDER_COUNT and 0 <= slot < RES_SLOTS:
            rec[RES_HOLDERS + h] = slot
    for n, row in enumerate((columns or [])[:RES_SLOTS]):
        for col, v in zip(RES_COLUMNS, row):
            if col == RES_COLUMNS[3]:   # rank points gained: signed
                struct.pack_into("<h", rec, col + 2 * n,
                                 max(-0x8000, min(int(v), 0x7FFF)))
            else:
                struct.pack_into("<H", rec, col + 2 * n,
                                 max(0, min(int(v), 0xFFFF)))
    # 2026-10-05 (live + offline run of the retail gate 0x00ABE6BC, scratchpad
    # re-promo/): 0 = no promotion. The Rank page shows only for +44 in 1..15
    # and the arm writes 1..254 to R+763, so clamping 0 up to 1 printed
    # "Promotion: DG Drone 3rd Class" and demoted the client's rank copy
    rec[RES_RANK] = 0 if not rank else clamp_rank(rank)
    struct.pack_into("<H", rec, RES_SCORE, max(0, min(int(score), 0xFFFF)))
    struct.pack_into("<II", rec, RES_ITEM, item[0] & 0xFFFFFFFF,
                     item[1] & 0xFFFFFFFF if item[0] else 0)
    return bytes(rec)


def result_board(recipient, members, summaries):
    """(holders, columns) for `recipient`'s kind-4 record. `members` = the
    room's member ids in the order selector 38 was built from; `summaries` =
    {member id: record_battle summary} (a member with none gets a zero row).
    The roster is the recipient's own: the others, then itself (selector 38,
    0x00bcb838). A medal several players won names the recipient if it is
    one of them, else the first winner in roster order."""
    order = [m for m in members if m and m != recipient][:RES_SLOTS - 1]
    order.append(recipient)
    columns, holders = [], {}
    for n, m in enumerate(order):
        s = summaries.get(m) or {}
        columns.append((s.get("kills", 0), s.get("kos", 0), 0, s.get("rp", 0)))
        for idx in s.get("medals", []):
            h = idx - MEDAL_BASE
            if 0 <= h < RES_HOLDER_COUNT and (h not in holders or m == recipient):
                holders[h] = n
    return holders, columns


def new_career(name="", rid=0):
    return {"name": name, "id": rid, "rank": RANK_MIN, "rp": 0,
            "battles": 0, "bt": {"w": 0, "l": 0, "d": 0},
            "tbt": {"w": 0, "l": 0, "d": 0}, "fa": {"w": 0, "l": 0, "d": 0},
            "missions": {"cleared": 0, "failed": 0}, "quests": {},
            # 2026-09-23: the MISSION LEDGER (doc_missions.py) -- exam quests an
            # instructor has "added to Missions" and the player has not cleared
            "quests_open": [],
            "kills": 0, "kos": 0, "heals": 0, "mvp": 0, "fa_bases": 0,
            "play_secs": 0, "medals": {}, "medal_set": MEDAL_SET,
            "private": False,
            "history": []}


def migrate_medals(c):
    """A career whose medal counts predate MEDAL_SET (paid under the 2005 beta
    rules): move them to "medals_2005" -- kept, never sent -- and start the
    launch-build counts empty. Returns True when it moved anything."""
    if c.get("medal_set") == MEDAL_SET:
        return False
    old = c.get("medals") or {}
    if old:
        c["medals_2005"] = dict(old)
    c["medals"] = {}
    c["medal_set"] = MEDAL_SET
    return bool(old)


def award_medals(mode, rows, winner):
    """Judge one finished battle. `rows` = per-player dicts with at least `key`
    and `team`, optionally kills / kos / left / survived / base_capture /
    base_damage / carrier_kos / last_capsule / leader_kills / flag_points /
    first_flag. `winner` = the winning team (in BT every player is its own
    team), or None for a draw. `mode` is the table's own mode (TDM / TCP /
    ... stay themselves here; MISSION pays no medal -- every sentence in
    60:[40..52] names a battle mode). Returns {key: [medal index, ...]}.

    Each rule is SE's own sentence from group 60 [40..52] (launch build), and
    a medal is only judged in a mode its sentence names (MODE_MEDALS, which
    is also the client's own per-mode Results list). A "most" medal needs
    someone to compare with, a count above zero and a unique leader (OURS,
    MOST_NEEDS_ONE)."""
    out = {r["key"]: [] for r in rows}
    allowed = MODE_MEDALS.get(mode, ())

    def give(key, medal):
        if key is not None and medal in allowed and medal not in out[key]:
            out[key].append(medal)

    def leader(value, among=None):
        pool = rows if among is None else among
        if len(rows) < 2 or not pool:
            # "the most" needs someone to compare with --
            # a solo mission handed out a "most KO'd" medal for one KO.
            return None
        vals = [(value(r), r["key"]) for r in pool]
        best = max(v for v, _k in vals)
        if MOST_NEEDS_ONE and best <= 0:
            return None
        top = [k for v, k in vals if v == best]
        return top[0] if len(top) == 1 else None

    def num(field):
        return lambda r: int(r.get(field, 0) or 0)

    def won(r):
        return winner is not None and r.get("team") == winner

    if mode == "BT":
        # [40] "the winner of an individual battle", [41] "the runner-up",
        # [42] "KO'd the most". Runner-up = the best of the rest by kills,
        # then fewest KOs (OURS: the order SE ranked by is lost); needs a
        # winner and a unique second.
        for r in rows:
            if won(r):
                give(r["key"], M_BT_CONQUEST)
        if winner is not None:
            rest = [r for r in rows if not won(r) and not r.get("left")]
            order = sorted(((num("kills")(r), -num("kos")(r)), r["key"])
                           for r in rest)
            if order and (len(order) == 1 or order[-1][0] != order[-2][0]):
                give(order[-1][1], M_BT_HONOR)
        give(leader(num("kos")), M_BT_DISHONOR)
    # [43] Team Merit: "the highest number of defeats minus times KO'd"
    give(leader(lambda r: num("kills")(r) - num("kos")(r)), M_TEAM_MERIT)
    # [45] Slayer: "defeated the most enemies"
    give(leader(num("kills")), M_SLAYER)
    # [44] Survivor: "the most defeats among those who survived to the end".
    # `survived` = still standing when it ended (docudp: not eliminated, not
    # gone); a row without it falls back to "never KO'd and still there".
    standing = [r for r in rows if r.get("survived", "kos" in r
                                         and r["kos"] == 0 and not r.get("left"))]
    give(leader(num("kills"), standing), M_SURVIVOR)
    for r in rows:
        # [46] Assault: "infiltrated the destroyed enemy base and brought
        # victory" = the member whose occupation won it (Team Base, 3f0e84a3)
        if won(r) and r.get("base_capture"):
            give(r["key"], M_ASSAULT)
        # [48] Last Capsule: "obtained the last mako capsule" (docudp: the
        # pick-up that completed the hold that won it -- INFERRED reading)
        if r.get("last_capsule"):
            give(r["key"], M_LAST_CAPSULE)
        # [50] First Flag: "carried back a flag the fastest" (no flag mode on
        # this server: nothing fills `first_flag`)
        if r.get("first_flag"):
            give(r["key"], M_FIRST_FLAG)
    # [47] Capsule Seeker: "defeated the most capsule carriers and made them drop"
    give(leader(num("carrier_kos")), M_CAPSULE_SEEKER)
    # [51] Leader Slayer: "defeated the enemy team's leader the most times"
    give(leader(num("leader_kills")), M_LEADER_SLAYER)
    # [52] Base Attack: "attacked the base most boldly" -- `base_damage` is
    # NOT filled yet (base hits send no request; the controller's request-24
    # attacker mask is undecoded)
    give(leader(num("base_damage")), M_BASE_ATTACK)
    # [49] Flag Carrier: "carried back flags and earned the most points"
    give(leader(num("flag_points")), M_FLAG_CARRIER)
    return out


# ---------------------------------------------------------------------------
# 2026-10-01: SE's OWN rank-point formula, the one the retail Results screen
# computes (lobby_rel F = 0x00ABF890, weights at 0x00B16AD0, the 7-way mode
# switch at 0x00B1DDB0, the medal RP table at 0x00B1AC68). MEASURED by
# emulation: a Python copy matched the client's function on 570 random inputs
# (scratchpad re-rp/rp_ref.py). The client draws its breakdown from the counts
# we send and caps its running total at the total we send, so the server has
# to pay exactly this or the screen and the career disagree.
# Index = the table's mode byte (wire+110, BT_MODE_NAMES): 0/1 Team Kill (and
# individual BT), 2 Survival, 3 Base, 4 Capsule, 5 Leader, 6 Flag.
# (enemies defeated, times KO'd, teammate KO'd, kill streak, team won, team lost)
RESULT_WEIGHTS = {0: (4, -2, -3, 2, 10, -5), 1: (4, -2, -3, 2, 10, -5),
                  2: (4, -2, -3, 4, 20, -10), 3: (2, -1, -3, 0, 20, -10),
                  4: (2, -1, -3, 0, 20, -10), 5: (3, -1, -3, 0, 30, -15),
                  6: (2, -1, -3, 0, 20, -10)}
#: medal id (group-60 index - MEDAL_BASE) -> the rank points its Results page
#: adds; ids not listed add nothing
MEDAL_RP = {0: 40, 1: 15, 2: -10}
MEDAL_RP.update({i: 15 for i in range(3, 13)})


def _tdiv(n, d):
    """C's signed division (truncates toward zero), as the client's `div`."""
    q = abs(n) // abs(d)
    return q if (n >= 0) == (d >= 0) else -q


def _s32(v):
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


def battle_scale(players):
    """The "Battle Scale Bonus Factor" in thousandths: 1.0 for two players,
    +0.1 for each one more, at most 2.0."""
    return min(1000 + 100 * max(int(players) - 2, 0), 2000)


def results_rp(mode, team_battle, outcome, kills=0, kos=0, team_kos=0,
               streak=0, players=2, base_hp=0, block=None):
    """The rank points the Results screen's breakdown adds up to, before the
    medal pages (medals_rp). `mode` = the mode byte; `team_battle` = the
    record's team flag (rec+28 bit 4; False = individual BT, whose screen has
    no win / loss row); `outcome` 'w' / 'l' / 'd'. `block` holds the mode's
    own counts, all optional: team_kills (1), survivors (2), base_flags /
    base_attack / own_base_hp / enemy_base_left (3, with the table's base HP),
    carriers_killed / hold_ms / capsule_obtained / capsules_end (4),
    leaders_killed / leader_points_lost / leader_points_earned (5),
    flag_carriers_killed / flags_returned / flags_taken / flag_obtained /
    flag_points_earned / flag_points_lost (6). May be negative."""
    b = block or {}
    g = lambda k: int(b.get(k, 0) or 0)
    pm = lambda n, m, cap=0x7FFFFFFF: min(_tdiv(_s32(n * m), 1000), cap)
    w = RESULT_WEIGHTS.get(mode, RESULT_WEIGHTS[1])
    tot = 0
    for wt, n in zip(w[:4], (kills, kos, team_kos, streak)):
        tot += int(n) * wt
    if mode == 1:
        tot += pm(g("team_kills"), 300)
    elif mode == 2:
        tot += g("survivors") * 3
    elif mode == 3:
        tot += (8 * (g("base_attack") != 0) + 5 * (g("base_flags") & 1)
                + pm(int(base_hp) - g("enemy_base_left"), 3))
        if g("base_flags") & 4:
            tot += pm(g("own_base_hp"), 3)
    elif mode == 4:
        tot += (g("carriers_killed") * 5 + pm(g("hold_ms") // 1000, 10, 100)
                + 5 * (g("capsule_obtained") != 0) + g("capsules_end") * 3)
    elif mode == 5:
        tot += (g("leaders_killed") * 5 + g("leader_points_earned")
                + pm(g("leader_points_lost"), -200))
    elif mode == 6:
        tot += (g("flag_carriers_killed") * 2 + g("flags_returned") * 5
                + g("flags_taken") * 3
                + (g("flag_carriers_killed") * 5 if g("flag_obtained") & 1 else 0)
                + g("flag_points_earned") * 5 - g("flag_points_lost"))
    if team_battle:
        tot += w[4] if outcome == "w" else (w[5] if outcome == "l" else 0)
    return _tdiv(_s32(tot * battle_scale(players)), 1000)


def medals_rp(medals):
    """What the Results screen's medal pages add for these group-60 indexes."""
    return sum(MEDAL_RP.get(int(m) - MEDAL_BASE, 0) for m in medals)


def battle_rp(outcome, kills, seconds):
    if seconds < RP_MIN_SECONDS:
        return 0
    base = {"w": RP_WIN, "d": RP_DRAW, "l": RP_LOSS}[outcome]
    return base + RP_PER_KILL * max(0, int(kills))


class Stats:
    """Careers keyed by docudp's wallet key (`member:N/0x<charid>`, the shop's
    and the rankings' key), in one JSON file rewritten whole on change -- the
    doc_shop / doc_rank shape."""

    def __init__(self, store):
        if isinstance(store, str):
            raise TypeError("a file path is not a store any more: pass "
                            "docdb.store('stats') or None")
        self.store = store
        self.data = {}
        # the clock a battle / leave is stamped with and a week is judged by,
        # and the week's phase (parse_week_start); docudp sets both
        self.clock = time.time
        self.week_phase = parse_week_start(WEEK_START)
        self.load()

    def load(self):
        """Read the store. A database that cannot be reached raises
        (docdb.py): the responder does not run on an empty store."""
        self.data = self.store.load() if self.store is not None else {}
        self.data.setdefault("chars", {})

    def save(self):
        if self.store is not None:
            self.store.save(self.data)

    def career(self, key, name=None, rid=None):
        c = self.data["chars"].get(key)
        if c is None:
            c = self.data["chars"][key] = new_career(name or "", rid or 0)
        migrate_medals(c)
        base = new_career()
        for k, v in base.items():             # files from an older shape
            c.setdefault(k, v)
        if name:
            c["name"] = name
        if rid:
            c["id"] = rid
        return c

    def _grant_medals(self, c, medals):
        for m in medals:
            c["medals"][str(m)] = c["medals"].get(str(m), 0) + 1

    def _promote(self, c, rank):
        """Raise the rank (never lower it). Returns the medals it paid: none
        -- the class chevrons it used to pay are 2005 beta medals; the launch
        client's slots 34..39 are tournament / weekly medals and a Reserved."""
        rank = clamp_rank(rank)
        if rank > c["rank"]:
            c["rank"] = rank
        return []

    def record_battle(self, mode, rows, winner, seconds, quest=None, when=None,
                      variant=None):
        """Tally one finished battle for every row (see award_medals for the row
        shape; `name` / `id` are remembered). `quest` = the quest id of a Solo
        MISSION (cleared iff its row's team == winner). `variant` = the table's
        own mode when `mode` files it under another (TDM is tallied as TBT but
        is not "the TBT mode" for a medal). Returns {key: summary}
        with the rp / gil / medals / promotion this battle paid, for the result
        screen and the log."""
        mode = mode if mode in MODES else "BT"
        seconds = max(0, int(seconds or 0))
        out = {}
        if (mode != "MISSION" and seconds < RP_MIN_SECONDS
                and not any(int(r.get("kills", 0)) for r in rows)):
            # VOID (OURS): a table started and ended at once is not a battle --
            # nothing is tallied, so a W/L cannot be farmed by Start + leave.
            # sec 4he: a battle with a KILL in it was fought, however short
            # (a kill target can end a duel in seconds) -- that one counts.
            for r in rows:
                c = self.career(r["key"], r.get("name"), r.get("id"))
                # coins picked up are still paid (they leave the bag at the
                # end whatever the verdict) -- nothing else
                cg = coin_gil(r.get("coins"))
                summ = {"mode": mode, "outcome": "void", "rp": 0, "gil": cg,
                        "coin_gil": cg,
                        "medals": [], "rank": c["rank"], "seconds": seconds,
                        "kills": 0, "kos": 0, "quest": quest,
                        "when": int(when if when is not None else self.clock())}
                c["history"] = (c["history"] + [summ])[-HISTORY_MAX:]
                out[r["key"]] = summ
            self.save()
            return out
        awards = award_medals(variant or mode, rows, winner)
        for r in rows:
            key = r["key"]
            c = self.career(key, r.get("name"), r.get("id"))
            rank_before = c["rank"]
            # 2026-10-04: a MISSION is pass/fail -- there is no draw. A player
            # who quit or ran out the clock without clearing it (winner is None)
            # must report a LOSS, not a draw: the client shows a mission DRAW as
            # "cleared", so a quit was displaying "mission success" + a bogus
            # promotion while the server correctly kept the exam open (live
            # 10-04, DG Drone 2nd exam). Only team battles have a draw.
            if mode == "MISSION":
                outcome = "w" if (winner is not None
                                  and r.get("team") == winner) else "l"
            else:
                outcome = ("d" if winner is None
                           else "w" if r.get("team") == winner else "l")
            kills, kos = max(0, int(r.get("kills", 0))), max(0, int(r.get("kos", 0)))
            c["battles"] += 1
            c["kills"] += kills
            c["kos"] += kos
            c["heals"] += max(0, int(r.get("heals", 0)))
            c["play_secs"] += seconds
            if r.get("base_capture") and (variant or mode) == "FA":
                # "FA Bases Captured" (60:[65]); a Team Base occupier
                # (2026-09-26) earns Assault, not this FA count
                c["fa_bases"] += 1
            gil, promo = 0, []
            if mode == "MISSION":
                ok = outcome == "w"
                c["missions"]["cleared" if ok else "failed"] += 1
                rp = 0
                if ok and quest is not None:
                    q = c["quests"]
                    q[str(quest)] = q.get(str(quest), 0) + 1
                    rp = QUEST_RP.get(quest, 0)
                    if quest in QUEST_PERFORMANCE_RP:
                        rp = battle_rp("w", kills, seconds)
                    gil = QUEST_GIL.get(quest, 0)
                    if quest in QUEST_PERFORMANCE_GIL:
                        gil = 100 * battle_rp("w", kills, seconds)
                    if quest in EXAM_PROMOTIONS:
                        promo = self._promote(c, EXAM_PROMOTIONS[quest])
                        # 2026-09-23: a cleared exam leaves the mission ledger
                        # (one-shot: "cannot be attempted again once cleared")
                        if quest in (c.get("quests_open") or []):
                            c["quests_open"].remove(quest)
            else:
                c[{"BT": "bt", "TBT": "tbt", "FA": "fa"}[mode]][outcome] += 1
                if "mode_idx" in r:
                    # 2026-10-01: SE's own formula, the Results screen's --
                    # its breakdown, then each medal page's rank points
                    rp = results_rp(r["mode_idx"], mode != "BT", outcome,
                                    kills, kos, r.get("team_kos", 0),
                                    r.get("streak", 0),
                                    r.get("players", len(rows)),
                                    r.get("base_hp", 0), r.get("block"))
                    rp += medals_rp(awards.get(key, []))
                else:
                    rp = battle_rp(outcome, kills, seconds)
                gil = BATTLE_GIL[outcome]
            cg = coin_gil(r.get("coins"))
            gil += cg
            # the screen's total may be negative (no floor in the client);
            # a career's rank points never go below 0
            c["rp"] = max(0, min(c["rp"] + rp, RP_MAX))
            medals = awards.get(key, []) + promo
            self._grant_medals(c, awards.get(key, []))
            summ = {"mode": mode, "outcome": outcome, "rp": rp, "gil": gil,
                    "coin_gil": cg,
                    "medals": medals, "rank": c["rank"], "seconds": seconds,
                    "kills": kills, "kos": kos, "quest": quest,
                    "when": int(when if when is not None else self.clock())}
            c["history"] = (c["history"] + [summ])[-HISTORY_MAX:]
            # the result record's own inputs (not kept in the history)
            summ = dict(summ, promoted=c["rank"] > rank_before,
                        team_kos=r.get("team_kos", 0),
                        streak=r.get("streak", 0), mode_idx=r.get("mode_idx"),
                        block=r.get("block"), players=r.get("players", len(rows)))
            self._week_tally(key, summ["when"], rp=rp, kills=kills,
                             team_w=int(outcome == "w" and mode in TEAM_WIN_MODES),
                             solo_w=int(outcome == "w" and mode in SOLO_WIN_MODES))
            out[key] = summ
        self.save()
        return out

    def record_leave(self, key, penalty, mode, seconds, name=None, rid=None,
                     when=None):
        """The player LEFT a running battle partway (lobby command 4). SE's own
        warning, client KelStr 0x5c0d / 0x8818: "Leaving a battle partway
        through will reduce your rank points. Are you sure?" -- so rank points
        go down by `penalty` (never below 0). Nothing else is tallied: no W/L,
        no battle count (no source says a leave counted as a loss). The AMOUNT
        is SOURCED (2026-09-26): SE's PlayOnline Additional Manual (the P.031
        correction): returning to the lobby or title
        mid-battle, or dropping on a line fault, takes 10 ranking points
        (LEAVE_RP_PENALTY; docudp --leave-rp-penalty defaults to it)."""
        c = self.career(key, name, rid)
        penalty = max(0, int(penalty or 0))
        lost = min(penalty, max(0, int(c["rp"])))
        c["rp"] = max(0, int(c["rp"]) - lost)
        summ = {"mode": mode if mode in MODES else "BT", "outcome": "left",
                "rp": -lost, "gil": 0, "medals": [], "rank": c["rank"],
                "seconds": max(0, int(seconds or 0)), "kills": 0, "kos": 0,
                "quest": None,
                "when": int(when if when is not None else self.clock())}
        c["history"] = (c["history"] + [summ])[-HISTORY_MAX:]
        self._week_tally(key, summ["when"], rp=-lost)
        self.save()
        return summ

    # -- the weekly medals (see WEEKLY_MEDALS) --------------------------------
    def _week_tally(self, key, when, **add):
        """Add to `key`'s running tallies for the week holding `when`."""
        wk = str(week_of(when, self.week_phase))
        t = self.data.setdefault("weekly", {}).setdefault(wk, {}).setdefault(
            key, new_week_tally())
        for f, v in add.items():
            t[f] = t.get(f, 0) + int(v)

    def week_tallies(self, week_id):
        return self.data.get("weekly", {}).get(str(int(week_id)), {})

    def close_week(self, week_id, now=None):
        """Judge one week: each WEEKLY_MEDALS category goes to its UNIQUE
        leader among the players with a tally that week, with a count above
        zero (WEEKLY_NEEDS_ONE); the medal count +1 on the career. Idempotent:
        the verdict is recorded in data["weeks_closed"] and a closed week
        returns None. Otherwise returns the verdict {"at", "players",
        "awards": {medal index: {"key", "value", "tied"}}}."""
        wk = str(int(week_id))
        closed = self.data.setdefault("weeks_closed", {})
        if wk in closed:
            return None
        tallies = self.week_tallies(wk)
        awards = {}
        for field, idx in WEEKLY_MEDALS:
            vals = [(int(t.get(field, 0)), k) for k, t in sorted(tallies.items())]
            best = max((v for v, _k in vals), default=0)
            top = [k for v, k in vals if v == best]
            win = top[0] if len(top) == 1 else None
            if WEEKLY_NEEDS_ONE and best <= 0:
                win = None
            if win is not None:
                self._grant_medals(self.career(win), [idx])
            awards[str(idx)] = {"key": win, "value": best,
                                "tied": len(top) if len(top) > 1 else 0}
        closed[wk] = {"at": int(self.clock() if now is None else now),
                      "players": len(tallies), "awards": awards}
        self.save()
        return closed[wk]

    def weeks_due(self, now=None):
        """Week ids with tallies, ENDED by `now`, not yet closed (oldest
        first) -- includes any week the server was down over."""
        now = self.clock() if now is None else now
        closed = self.data.get("weeks_closed", {})
        return sorted(int(w) for w in self.data.get("weekly", {})
                      if w not in closed and int(w) + WEEK_SECS <= now)

    def next_week_close(self):
        """When the earliest open tallied week ends (epoch), or None."""
        closed = self.data.get("weeks_closed", {})
        ends = [int(w) + WEEK_SECS for w in self.data.get("weekly", {})
                if w not in closed]
        return min(ends) if ends else None

    def close_due(self, now=None):
        """Close every week weeks_due() names. Returns [(week id, verdict)]."""
        out = []
        for wk in self.weeks_due(now):
            v = self.close_week(wk, now)
            if v is not None:
                out.append((wk, v))
        return out

    def week_lines(self, wk, verdict):
        """One log line per weekly medal of a closed week."""
        span = "%s .. %s UTC" % (
            time.strftime("%Y-%m-%d %H:%M", time.gmtime(wk)),
            time.strftime("%Y-%m-%d %H:%M", time.gmtime(wk + WEEK_SECS)))
        lines = []
        for field, idx in WEEKLY_MEDALS:
            a = verdict["awards"][str(idx)]
            if a["key"] is not None:
                c = self.data["chars"].get(a["key"], {})
                lines.append("WEEKLY %s (week %s): %s (%s) %s %d -> medal id %d, "
                             "count now %d" % (MEDALS[idx], span, a["key"],
                                               c.get("name") or "?", field,
                                               a["value"], idx - MEDAL_BASE,
                                               medal_count(c, idx)))
            else:
                lines.append("WEEKLY %s (week %s): nobody (%s)" % (
                    MEDALS[idx], span, "%d tied at %d" % (a["tied"], a["value"])
                    if a["tied"] and a["value"] > 0 else "best %d" % a["value"]))
        return lines

    def peek(self, key):
        """The career for `key` WITHOUT creating one (a fresh DGD-3 / 0 RP
        career when there is none) -- for the world door and the Status
        window, which must not litter the file with nameless entries."""
        c = self.data["chars"].get(key)
        if c is None:
            return new_career()
        migrate_medals(c)
        for k, v in new_career().items():
            c.setdefault(k, v)
        return c

    def key_for_charid(self, cid):
        """The stored key whose character id is `cid` (bits 30/31 masked, as
        the wallet key masks them), or None."""
        suffix = "/0x%08x" % (cid & 0x3FFFFFFF)
        return next((k for k in self.data["chars"] if k.endswith(suffix)), None)

    def set_private(self, key, private, name=None, rid=None):
        """Lobby command 6 (True, "Anonymous") / 7 (False, "Public")."""
        c = self.career(key, name, rid)
        if bool(c.get("private")) != bool(private):
            c["private"] = bool(private)
            self.save()
        return c["private"]

    def is_private(self, key):
        c = self.data["chars"].get(key) if key else None
        return bool(c and c.get("private"))

    def viewer_fields(self, key):
        """(rank 1..16, ranking points) for the POL Viewer profile, or None."""
        c = self.data["chars"].get(key)
        return None if c is None else (clamp_rank(c.get("rank")), int(c.get("rp", 0)))

    def ranking_values(self, key):
        """{doc_rank category: value} for one career."""
        c = self.career(key)
        return {cat: fn(c) for cat, fn in RANK_TABS.items()}

    def push_rankings(self, rankings):
        """Write every career into a doc_rank.Rankings store's "ind" values
        (the file the Ranking menu and a web board read). Characters with no
        career keep whatever the file holds."""
        chars = rankings.data.setdefault("chars", {})
        for key, c in self.data["chars"].items():
            e = chars.setdefault(key, {})
            if c.get("name"):
                e["name"] = c["name"]
            if c.get("id"):
                e["id"] = c["id"]
            e["ind"] = {str(cat): v for cat, v in self.ranking_values(key).items()}
        rankings.save()

    def summary_line(self, key):
        c = self.career(key)
        return ("%s %s rp %d, %d battle(s) (BT %d-%d-%d, TBT %d-%d-%d), %d medal(s)"
                % (c["name"] or key, RANK_CODES[clamp_rank(c["rank"]) - 1], c["rp"],
                   c["battles"], c["bt"]["w"], c["bt"]["l"], c["bt"]["d"],
                   c["tbt"]["w"], c["tbt"]["l"], c["tbt"]["d"],
                   sum(c["medals"].values())))


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import docdb
    import docpg
    docpg.need_database("doc_stats")
    # a file path is not a store any more: refused, not silently ignored
    try:
        Stats("doc-stats.json")
        raise AssertionError("a path must be refused")
    except TypeError:
        pass
    docdb.store("stats").clear()
    st = Stats(docdb.store("stats"))
    A, B, C = "member:3/0x0002aa68", "member:6/0x00041018", "member:15/0x0004107c"
    # a TBT win for team 0 (A, C) over team 1 (B); A tops kills, B tops KOs
    res = st.record_battle("TBT", [
        {"key": A, "name": "Lex", "id": 0x2aa68, "team": 0, "kills": 3, "kos": 0,
         "first_kill": True, "finisher": True},
        {"key": B, "name": "Deck", "id": 0x41018, "team": 1, "kills": 1, "kos": 3},
        {"key": C, "name": "Quarry", "team": 0, "kills": 0, "kos": 0}], winner=0,
        seconds=180)
    # launch rules (60:[43] / [45]): A tops kills - KOs and kills; nothing
    # else is a TBT medal (First Attack / Iron Seal / Finisher / Star of
    # Victory were the 2005 beta's -- TWIN: the old table paid A five medals)
    assert set(res[A]["medals"]) == {M_TEAM_MERIT, M_SLAYER}, res[A]
    assert res[B]["medals"] == [] and res[C]["medals"] == [], (res[B], res[C])
    assert res[A]["rp"] == RP_WIN + 3 * RP_PER_KILL and res[B]["rp"] == RP_LOSS + RP_PER_KILL
    assert st.career(A)["tbt"] == {"w": 1, "l": 0, "d": 0}
    assert st.career(B)["tbt"] == {"w": 0, "l": 1, "d": 0}
    # a BT draw pays the draw rate and no BT medal; too short pays nothing
    res = st.record_battle("BT", [{"key": A, "team": 0}, {"key": B, "team": 1}],
                           winner=None, seconds=120)
    assert res[A]["rp"] == RP_DRAW and res[A]["medals"] == res[B]["medals"] == []
    _void = st.record_battle("BT", [{"key": A, "team": 0}], 0, 5)[A]
    assert _void["outcome"] == "void" and _void["rp"] == 0
    assert st.career(A)["bt"] == {"w": 0, "l": 0, "d": 1}, st.career(A)["bt"]
    A, B, C, _abc = "member:90/0x3", "member:91/0x4", "member:92/0x5", (A, B, C)
    D_ = "member:93/0x6"
    # BT (60:[40..42]): 1st, 2nd (kills, then fewest KOs), most KO'd
    aw = award_medals("BT", [
        {"key": A, "team": 1, "kills": 3, "kos": 0},
        {"key": B, "team": 2, "kills": 2, "kos": 1},
        {"key": C, "team": 3, "kills": 2, "kos": 3},
        {"key": D_, "team": 4, "kills": 0, "kos": 2}], 1)
    assert aw == {A: [M_BT_CONQUEST], B: [M_BT_HONOR], C: [M_BT_DISHONOR],
                  D_: []}, aw
    aw = award_medals("BT", [{"key": A, "team": 1, "kills": 3},
                             {"key": B, "team": 2, "kills": 1},
                             {"key": C, "team": 3, "kills": 1}], 1)
    assert M_BT_HONOR not in aw[B] + aw[C]              # a tie for 2nd: nobody
    assert award_medals("BT", [{"key": A, "team": 1, "kills": 1},
                               {"key": B, "team": 2}], None) == {A: [], B: []}
    # TDM (60:[44]): the most kills among the SURVIVORS -- C out-killed A but
    # fell; Slayer still goes to C (the most kills of all)
    aw = award_medals("TDM", [
        {"key": A, "team": 0, "kills": 1, "kos": 0, "survived": True},
        {"key": B, "team": 0, "kills": 0, "kos": 0, "survived": True},
        {"key": C, "team": 1, "kills": 2, "kos": 1, "survived": False}], 0)
    assert aw == {A: [M_SURVIVOR], B: [], C: [M_SLAYER]}, aw
    assert M_SURVIVOR not in award_medals("TBT", [
        {"key": A, "team": 0, "kills": 1, "survived": True},
        {"key": B, "team": 1}], 0)[A]                   # TWIN: TDM only
    # TCP (60:[47] / [48]): carriers KO'd, the last capsule
    aw = award_medals("TCP", [
        {"key": A, "team": 0, "carrier_kos": 2, "last_capsule": True},
        {"key": B, "team": 1, "carrier_kos": 1}], 0)
    assert aw == {A: [M_LAST_CAPSULE, M_CAPSULE_SEEKER], B: []}, aw
    # TBS (60:[46]): the occupier of a WON base; TLD (60:[51]) leader kills
    aw = award_medals("TBS", [{"key": A, "team": 0, "base_capture": True},
                              {"key": B, "team": 1, "base_capture": True}], 0)
    assert aw == {A: [M_ASSAULT], B: []}, aw
    aw = award_medals("TLD", [{"key": A, "team": 0, "leader_kills": 1, "kills": 3},
                              {"key": B, "team": 1, "kills": 1}], 0)
    assert aw == {A: [M_LEADER_SLAYER], B: []}, aw
    # a medal outside its mode is never paid; a mission pays none
    assert award_medals("TBT", [{"key": A, "team": 0, "carrier_kos": 3},
                                {"key": B, "team": 1}], 0)[A] == []
    assert award_medals("MISSION", [{"key": A, "team": 0, "kills": 4},
                                    {"key": B, "team": 0}], 0)[A] == []
    # every battle medal is a holder slot of the kind-4 record (ids 0..14)
    assert all(0 <= m - MEDAL_BASE < RES_HOLDER_COUNT
               for ms in MODE_MEDALS.values() for m in ms)
    # 2005-beta counts move aside once; a fresh career holds no medal
    st.data["chars"]["member:89/0x2"] = {"medals": {"34": 1, "18": 2}}
    assert medal_mask(st.career("member:89/0x2")) == 0
    assert st.career("member:89/0x2")["medals_2005"] == {"34": 1, "18": 2}
    assert migrate_medals(st.career("member:89/0x2")) is False
    assert st.career("member:88/0x1")["medals"] == {}
    for _k in ("member:88/0x1", "member:89/0x2"):
        del st.data["chars"][_k]
    A, B, C = _abc
    # a tie for most kills awards nobody
    res = st.record_battle("BT", [{"key": A, "team": 0, "kills": 2},
                                  {"key": B, "team": 1, "kills": 2}], 0, 60)
    assert res[A]["medals"] == [M_BT_CONQUEST] and res[B]["medals"] == [M_BT_HONOR]
    aw = award_medals("TBT", [{"key": A, "team": 0, "kills": 2},
                              {"key": B, "team": 1, "kills": 2}], 0)
    assert M_SLAYER not in aw[A] + aw[B]
    # exams: quest 1 -> DGD-2; quest 28 (retail: Scout 3rd) skips to DGSC-3
    # and pays NO chevron (slot 39 is Reserved in the launch build); an exam
    # never LOWERS the rank; a failed exam pays 0
    _q1 = st.record_battle("MISSION", [{"key": C, "team": 0}], 0, 90, quest=1)[C]
    assert _q1["rank"] == 2 and _q1["medals"] == []
    res = st.record_battle("MISSION", [{"key": C, "team": 0}], 0, 90, quest=28)
    assert res[C]["rank"] == 4 and res[C]["medals"] == []
    assert st.record_battle("MISSION", [{"key": C, "team": 0}], 0, 90, quest=1)[C]["rank"] == 4
    assert st.record_battle("MISSION", [{"key": C, "team": 0}], 1, 90, quest=6)[C]["rank"] == 4
    assert st.career(C)["missions"] == {"cleared": 3, "failed": 1}
    # fixed quest rewards
    res = st.record_battle("MISSION", [{"key": B, "team": 0}], 0, 90, quest=5)
    assert res[B]["rp"] == 30                       # 51:4 "Rank Points +30"
    assert st.record_battle("MISSION", [{"key": B, "team": 0}], 0, 90, quest=23)[B]["gil"] == 2000
    # 2026-09-26: Chocobo Coins pay 1000 each, 9 at most, on top of the reward
    _cm = st.record_battle("MISSION", [{"key": B, "team": 0, "coins": 3}], 0, 90,
                           quest=31)[B]
    assert _cm["gil"] == 1000 + 3000 and _cm["coin_gil"] == 3000, _cm
    PA, PB = "member:95/0x7", "member:96/0x8"     # own keys: A/B feed checks below
    # PvP gil (FFCheats tips page, 2-player TBR): loser 9 coins = 9300, winner 10300
    _pv = st.record_battle("TBT", [{"key": PA, "team": 0, "kills": 1, "coins": 9},
                                   {"key": PB, "team": 1, "coins": 12}], 0, 120)
    assert (_pv[PA]["gil"], _pv[PB]["gil"]) == (10300, 9300), _pv
    # TWIN: without coins the same battle pays only the win / loss rate
    _pv = st.record_battle("TBT", [{"key": PA, "team": 0, "kills": 1},
                                   {"key": PB, "team": 1}], 0, 120)
    assert (_pv[PA]["gil"], _pv[PB]["gil"]) == (1300, 300), _pv
    # a VOID battle pays nothing but the coins picked up
    _vd = st.record_battle("BT", [{"key": PA, "team": 0, "coins": 2}], 0, 5)[PA]
    assert _vd["outcome"] == "void" and _vd["gil"] == 2000 and _vd["rp"] == 0
    for _k in (PA, PB):
        del st.data["chars"][_k]
    # persistence + the surfaces
    st2 = Stats(docdb.store("stats"))
    assert st2.viewer_fields(C) == (4, st.career(C)["rp"])
    assert st2.viewer_fields("member:99/0x1") is None
    v = st2.ranking_values(A)
    assert v[0] == st2.career(A)["rp"] and v[3] == 1 and v[1] == 1
    assert abs(v[2] - 0.75) < 1e-9         # BT 1-0-1 (the 5 s battle was void)
    assert v[10] == 1                       # Slayer
    # THE WIRE. The 140 career body: every record byte lands where the client's
    # scatter reads it, and the three skipped windows stay zero.
    cA = st2.career(A)
    rec = career_record(cA)
    body = career_body(cA)
    assert body[1] == CAREER_ANS and len(body) == 28 + CAREER_REC_LEN
    assert all(body[career_body_offset(k)] == rec[k] for k in range(CAREER_REC_LEN))
    assert body[56:60] == bytes(4) and body[180:188] == bytes(8) \
        and body[288:292] == bytes(4)
    assert career_body_offset(0) == 12 and career_body_offset(44) == 60 \
        and career_body_offset(164) == 188 and career_body_offset(264) == 292
    w, l_, n = struct.unpack_from("<I", rec, 0)[0], struct.unpack_from(
        "<I", rec, 4)[0], struct.unpack_from("<I", rec, 36)[0]
    assert (w, l_, n) == (2, 0, 3), (w, l_, n)      # TBT W + BT W + BT D
    slayer = MEDAL_IDS and (M_SLAYER - MEDAL_BASE)
    assert struct.unpack_from("<I", rec, 168 + 4 * slayer)[0] == 1
    assert medal_mask(cA) >> slayer & 1 and not medal_mask(cA) >> 2 & 1
    # the world door: mask / rank points / rank, nothing else touched
    lb = apply_login(bytearray(176), st2.career(C))
    assert struct.unpack_from("<I", lb, 56)[0] == medal_mask(st2.career(C))
    assert struct.unpack_from("<i", lb, 68)[0] == st2.career(C)["rp"]
    assert lb[131] == 4 and lb[:56] == bytes(56) and lb[72:131] == bytes(59)
    # the kind-4 result: outcome, totals, medals, NOBODY in the holder slots
    rr = result_record("d", 150, 20250, 0x201, 4, score=15)
    assert len(rr) == RESULT_LEN and rr[0] == 2
    assert struct.unpack_from("<III", rr, 8)[0] == 150
    assert struct.unpack_from("<I", rr, 16)[0] == 20250
    assert struct.unpack_from("<I", rr, 20)[0] == 0x201
    # 2026-10-01: the RETAIL layout (14 holder slots, rank +44, score +46)
    assert rr[30:44] == b"\xff" * 14 and rr[44] == 4 and rr[48] == 0
    assert struct.unpack_from("<H", rr, 46)[0] == 15
    assert result_record("w", 0, 0, 0, 1)[0] == 1
    # no promotion = +44 0 (the gate hides the Rank page); a promotion keeps it
    assert result_record("w", 0, 0, 0, 0, rtype=RES_TYPE_REWARD)[RES_RANK] == 0
    assert result_record("w", 0, 0, 0, 2, rtype=RES_TYPE_REWARD)[RES_RANK] == 2
    # holders: medal id h -> roster slot at +30+h; columns land per slot
    rr = result_record("w", 0, 0, 0, 1, holders={0: 1, 5: 2, 15: 3, 6: 40},
                       columns=[(3, 1, 0, 45), (0, 2, 0, -10), (7, 0, 2, 70)])
    assert rr[30] == 1 and rr[35] == 2 and rr[36] == 0xFF, rr[30:44].hex()
    assert rr[31:35] == b"\xff" * 4          # medal 15 has no slot; slot 40 > 31
    assert struct.unpack_from("<3H", rr, 60) == (3, 0, 7)
    assert struct.unpack_from("<3H", rr, 124) == (1, 2, 0)
    assert struct.unpack_from("<3H", rr, 188) == (0, 0, 2)
    assert struct.unpack_from("<3h", rr, 252) == (45, -10, 70)
    # the rank-point counts, battle type, winner, mode block, player count
    rr = result_record("w", 0, 0, 0, 1, counts=(5, 2, 1, 3),
                       rtype=RES_TYPE_TEAM | RES_TYPE_KILLS, winner=1, mode=3,
                       block={"base_flags": 5, "base_attack": 1,
                              "own_base_hp": 900, "enemy_base_left": 0},
                       players=6)
    assert struct.unpack_from("<H", rr, 2)[0] == 5
    assert struct.unpack_from("<H", rr, 6)[0] == 2
    assert struct.unpack_from("<2H", rr, 24) == (1, 3)
    assert rr[28] == 0x12 and rr[29] == 1 and rr[328] == 6
    assert rr[316:322] == bytes([5, 1]) + struct.pack("<HH", 900, 0)
    # SE's formula (re-rp/rp_ref.py, emulator-matched): BT duel 3 kills, 1 KO,
    # 2 players: 4*3 - 2 = 10, no win row, scale 1.0
    assert results_rp(0, False, "w", kills=3, kos=1, players=2) == 10
    # TBT win, 2 kills, team 9 kills, 6 players: (8 + 2 + 10) * 1.4 = 28
    assert results_rp(1, True, "w", kills=2, players=6,
                      block={"team_kills": 9}) == 28
    # a KO-heavy loss goes negative (no floor on the screen)
    assert results_rp(1, True, "l", kos=6, players=2) == -17
    assert battle_scale(30) == 2000 and battle_scale(1) == 1000
    assert medals_rp([MEDAL_BASE + 0, MEDAL_BASE + 2, MEDAL_BASE + 20]) == 30
    # the board for one recipient: others in room order, self LAST; a shared
    # medal names the recipient, a sole one its winner
    _sm = {0x11: {"kills": 3, "kos": 0, "rp": 45, "medals": [M_SLAYER, M_SURVIVOR]},
           0x22: {"kills": 0, "kos": 3, "rp": 10, "medals": [M_BT_DISHONOR]},
           0x33: {"kills": 1, "kos": 0, "rp": 35, "medals": [M_SURVIVOR]}}
    hl, cols = result_board(0x33, [0x11, 0x22, 0x33], _sm)
    assert cols == [(3, 0, 0, 45), (0, 3, 0, 10), (1, 0, 0, 35)], cols
    assert hl == {M_SLAYER - MEDAL_BASE: 0, M_BT_DISHONOR - MEDAL_BASE: 1,
                  M_SURVIVOR - MEDAL_BASE: 2}, hl
    hl, cols = result_board(0x11, [0x11, 0x22, 0x33], _sm)
    assert [c[0] for c in cols] == [0, 1, 3] and hl[M_SURVIVOR - MEDAL_BASE] == 2
    assert result_board(0x44, [0x11], {})[1] == [(0, 0, 0, 0), (0, 0, 0, 0)]
    # medal ids 15+ (tournament / weekly, Reserved) have no holder slot
    assert result_board(0x11, [0x11], {0x11: {"medals": [34]}})[0] == {}
    assert result_record("l", 0, 0, 0, 1)[0] == 0
    # peek never creates; key_for_charid finds by the masked id
    assert st2.peek("member:77/0x1")["rank"] == 1 and "member:77/0x1" not in st2.data["chars"]
    assert st2.key_for_charid(0xC002aa68) == A
    import doc_rank
    docdb.store("rankings").clear()
    rk = doc_rank.Rankings(docdb.store("rankings"))
    st2.push_rankings(rk)
    rk2 = doc_rank.Rankings(docdb.store("rankings"))
    assert rk2.data["chars"][A]["name"] == "Lex"
    assert rk2.data["chars"][A]["ind"]["0"] == st2.career(A)["rp"]
    tab = rk2.table(False, 0)
    assert tab[0][4] in ("Lex", "Deck", "Quarry") and len(tab) == 3, tab
    print(st2.summary_line(A))
    docdb.store("stats").clear()
    docdb.store("rankings").clear()
    # THE WEEKLY MEDALS. Week = Monday 00:00 JST: Mon 2026-09-28 00:00 JST is
    # Sun 2026-09-27 15:00 UTC = 1790521200.
    ph = parse_week_start(WEEK_START)
    W = 1790521200
    assert week_of(W, ph) == W and week_of(W - 1, ph) == W - WEEK_SECS
    assert week_of(W + WEEK_SECS - 1, ph) == W
    # TWIN: a UTC Monday is 9 h later -- Sun 23:00 UTC is already JST Monday
    assert week_of(W + 8 * 3600, ph) == W
    assert week_of(W + 8 * 3600, parse_week_start("mon 00:00 +00:00")) != W
    assert parse_week_start("Monday 00:00 +09:00") == ph
    for bad in ("", "xyz 00:00", "mon 25:00", "mon 00:00 09:00"):
        try:
            parse_week_start(bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    ws = Stats(docdb.store("stats"))
    ws.clock = lambda: W + 3600                # Monday 01:00 JST, week W
    P, Q, R = "member:1/0x11", "member:2/0x22", "member:3/0x33"
    # week W: P wins a BT (1 kill), Q wins a TBT with 2 kills, R clears a
    # mission (a win that is NOT a battle win) with 3 kills, Q leaves one
    ws.record_battle("BT", [{"key": P, "team": 1, "kills": 1},
                            {"key": R, "team": 2}], 1, 120)
    ws.record_battle("TBT", [{"key": Q, "team": 0, "kills": 2},
                             {"key": P, "team": 1}], 0, 120)
    ws.record_battle("MISSION", [{"key": R, "team": 0, "kills": 3}], 0, 90,
                     quest=5)
    ws.record_leave(Q, 10, "TBT", 50)
    tw = ws.week_tallies(W)
    assert tw[P] == {"rp": 35 + 10, "kills": 1, "team_w": 0, "solo_w": 1}, tw[P]
    assert tw[Q] == {"rp": 40 - 10, "kills": 2, "team_w": 1, "solo_w": 0}, tw[Q]
    assert tw[R] == {"rp": 10 + 30, "kills": 3, "team_w": 0, "solo_w": 0}, tw[R]
    # a battle stamped one second before the boundary is the PREVIOUS week
    ws.record_battle("BT", [{"key": R, "team": 1, "kills": 1},
                            {"key": P, "team": 2}], 1, 120, when=W - 1)
    assert ws.week_tallies(W - WEEK_SECS)[R]["solo_w"] == 1
    # nothing is due before the week ends; the older week is
    assert ws.weeks_due(W + WEEK_SECS - 1) == [W - WEEK_SECS]
    assert ws.next_week_close() == W
    v = ws.close_week(W, now=W + WEEK_SECS)
    aw = {int(i): x["key"] for i, x in v["awards"].items()}
    # rp: P 45 > R 40 > Q 30; kills R; team wins Q; solo wins P
    assert aw == {35: P, 36: R, 37: Q, 38: P}, aw
    assert medal_count(ws.career(P), 35) == 1 and medal_count(ws.career(P), 38) == 1
    mP = medal_mask(ws.career(P))
    assert mP >> (35 - MEDAL_BASE) & 1 and mP >> (38 - MEDAL_BASE) & 1
    assert not mP >> (36 - MEDAL_BASE) & 1 and not mP >> (37 - MEDAL_BASE) & 1
    # both surfaces carry ids 19..22: the door mask and the +168 counts
    lb = apply_login(bytearray(176), ws.career(P))
    assert struct.unpack_from("<I", lb, LOGIN_MEDAL_MASK_OFF)[0] >> 22 & 1
    assert struct.unpack_from("<I", career_record(ws.career(P)),
                              168 + 4 * (38 - MEDAL_BASE))[0] == 1
    # IDEMPOTENT: a second close (and a restart) pays nothing more
    assert ws.close_week(W, now=W + WEEK_SECS) is None
    assert Stats(docdb.store("stats")).close_week(W) is None
    assert medal_count(Stats(docdb.store("stats")).career(P), 35) == 1
    # CATCH-UP: the server was down over the older week's end -- close_due
    # closes it (R's lone solo win, R's kill) on the first look
    got = ws.close_due(now=W + 3 * WEEK_SECS)
    assert [wk for wk, _v in got] == [W - WEEK_SECS], got
    assert medal_count(ws.career(R), 38) == 1 and medal_count(ws.career(R), 36) == 2
    assert ws.close_due(now=W + 3 * WEEK_SECS) == [] and ws.next_week_close() is None
    # TIES award nobody; a zero count awards nobody; activity is needed
    ws.clock = lambda: W + WEEK_SECS + 60
    ws.record_battle("TBT", [{"key": P, "team": 0, "kills": 1},
                             {"key": Q, "team": 1, "kills": 1}], None, 120)
    v = ws.close_week(W + WEEK_SECS, now=W + 2 * WEEK_SECS)
    assert all(x["key"] is None for x in v["awards"].values()), v
    assert v["awards"]["36"]["tied"] == 2 and v["awards"]["37"]["value"] == 0
    assert any("2 tied at 1" in ln for ln in ws.week_lines(W + WEEK_SECS, v))
    assert ws.close_week(W + 5 * WEEK_SECS)["players"] == 0     # empty week
    # TWIN: the pre-weekly code kept no tally, so a career file whose week
    # lives only in `history` closes to no award
    ws.data["weekly"], ws.data["weeks_closed"] = {}, {}
    assert ws.close_due(now=W + 9 * WEEK_SECS) == []
    docdb.store("stats").clear()
    print("doc_stats self-test PASS")
    sys.exit(0)
