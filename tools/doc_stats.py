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
  QUEST REWARDS the fixed ones: 250/50/100/50/150/200 Rank Points, 3000 and
               1500 Gil; three say "(Based on Performance)".
  MEDALS       group 60 [16..39] names, [40..63] the award rules, one per medal
               (Medal of Dishonor "KO'd the most", First Attack "defeats the
               first enemy", Iron Seal "not KO'd once", Healer, Assault "captures
               his enemy's base and brings his team victory", Slayer "defeats the
               most enemies", The Finisher "ends a battle", Seeker "collects all
               the mako capsules", Star of Victory "perfect victory in TBT", BT
               "victors of the BT mode", FA "destroys its core", Survival
               "infiltrates his enemy's base for an extended period", five
               class "outstanding performance" medals, seven chevrons).

WHAT IS OURS (SE's server logic is lost; every number here is a PLACEHOLDER in
the same sense as doc_shop's prices, and each is a module constant):
  * the Rank Points a battle pays (RP_*), the "perfect victory" reading (a
    winning team with zero KOs), the Survival threshold, which rank a class
    chevron marks, the "Kill Rate" formula.
  * the per-player battle inputs (kills, KOs, heals, ...) are NOT yet read off
    the wire -- until the client's own report (game-server request 44, the reply
    to kind 4) is decoded, a battle records only who played, which side won and
    how long it lasted.
"""
import json
import os
import struct
import tempfile
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
EXAM_PROMOTIONS = {1: 2, 2: 3, 3: 4, 4: 5, 6: 6, 28: 7, 7: 8, 8: 9, 9: 10,
                   10: 11, 11: 12, 12: 13, 13: 14, 14: 15, 15: 16}
#: quest id -> fixed Rank Points / Gil (51:(N-1)); "Based on Performance" ones
#: (19 gil, 20/21 RP) pay the battle rates below instead.
QUEST_RP = {5: 250, 16: 50, 18: 100, 24: 50, 25: 150, 26: 200}
QUEST_GIL = {23: 3000, 31: 1500, 32: 1500, 33: 1500, 34: 1500, 35: 1500}
QUEST_PERFORMANCE_RP = (20, 21)
QUEST_PERFORMANCE_GIL = (19,)

# group-60 index -> medal name (the index is SE's own; 16..39)
MEDALS = {
    16: "Medal of Dishonor", 17: "First Attack", 18: "Iron Seal", 19: "Healer",
    20: "Assault", 21: "Slayer", 22: "The Finisher", 23: "Seeker",
    24: "Star of Victory", 25: "BT", 26: "FA", 27: "Survival",
    28: "Super Trooper", 29: "Super Armored", 30: "Super Sniper",
    31: "Super Mage", 32: "Super Smasher",
    33: "Turks Chevron", 34: "Drone Class Chevron", 35: "Tsviet Chevron",
    36: "General Class Chevron", 37: "Commander Class Chevron",
    38: "Trooper Class Chevron", 39: "Scout Class Chevron",
}
M_DISHONOR, M_FIRST, M_IRON, M_HEALER, M_ASSAULT, M_SLAYER, M_FINISHER, \
    M_SEEKER, M_STAR, M_BT, M_FA, M_SURVIVAL = range(16, 28)
#: class byte (our numbering, until the wire names one) -> its Super medal
CLASS_MEDALS = {"trooper": 28, "armored": 29, "sniper": 30, "mage": 31,
                "smasher": 32}
#: rank reached -> the class chevron it marks (OUR reading of "acquired X Class")
RANK_CHEVRONS = {2: 34, 4: 39, 7: 38, 10: 37, 13: 36, 16: 35}

#: doc_rank Individual category -> how to read it off a career (sec 4gl names)
RANK_TABS = {
    0: lambda c: c["rp"],
    1: lambda c: c["bt"]["w"],
    2: lambda c: win_rate(c["bt"]),
    3: lambda c: c["tbt"]["w"],
    4: lambda c: win_rate(c["tbt"]),
    5: lambda c: c["kills"],
    6: lambda c: kill_rate(c),
    7: lambda c: medal_count(c, M_DISHONOR), 8: lambda c: medal_count(c, M_HEALER),
    9: lambda c: medal_count(c, M_ASSAULT), 10: lambda c: medal_count(c, M_SLAYER),
    11: lambda c: medal_count(c, M_SEEKER), 12: lambda c: medal_count(c, M_BT),
    14: lambda c: medal_count(c, 28), 15: lambda c: medal_count(c, 29),
    16: lambda c: medal_count(c, 30), 17: lambda c: medal_count(c, M_SURVIVAL),
}

# PLACEHOLDER economy (SE's is lost)
RP_WIN, RP_DRAW, RP_LOSS = 30, 15, 10
RP_PER_KILL = 5
RP_MIN_SECONDS = 30          # a battle shorter than this pays nothing
SURVIVAL_SECONDS = 60
HISTORY_MAX = 20
RP_MAX = 0x7FFFFFFF

MODES = ("BT", "TBT", "FA", "MISSION")


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
#   Medal id n = group-60 entry 16+n (Medal of Dishonor 0 .. Scout Class
#   Chevron 23); "Medals Earned" = the number of SET BITS.
# ---------------------------------------------------------------------------
CAREER_REQ, CAREER_ANS = 139, 140
CAREER_REC_LEN = 268
LOGIN_MEDAL_MASK_OFF = 56
LOGIN_RP_OFF = 68
LOGIN_RANK_OFF = 131
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
#   +30..44  15 award-holder ROSTER SLOTS; 0xFF (>= 32) = nobody. WARNING: 0 names
#            roster slot 0 -- so zeros hand all 15 to the first player.
#   +48 u8   RANK, written to R+763 only if 1..254
#   +50 u16  "Score"
#   +52 u32 / +56 u32  item REWARD id / quantity (added to the bag)
#   +64/+128/+192/+256  four u16[32] per-roster-slot columns (Enemies
#            Defeated / Times KO'd / NPCs Defeated / Total -- which is which
#            is NOT established); roster = selector 38's order, self LAST.
# ---------------------------------------------------------------------------
RESULT_LEN = 400
RES_OUTCOME, RES_RP_TOTAL, RES_GIL_TOTAL, RES_MEDALS = 0, 8, 16, 20
RES_HOLDERS, RES_HOLDER_COUNT = 30, 15
RES_RANK, RES_SCORE, RES_ITEM, RES_ITEM_QTY = 48, 50, 52, 56
OUTCOME_CODES = {"w": 1, "l": 0, "d": 2, "void": 2}


def result_record(outcome, rp_total, gil_total, mask, rank, score=0,
                  item=(0, 0)):
    """The 400-byte kind-4 record. `outcome` is 'w' / 'l' / 'd' (or 'void')."""
    rec = bytearray(RESULT_LEN)
    rec[RES_OUTCOME] = OUTCOME_CODES.get(outcome, 2)
    struct.pack_into("<I", rec, RES_RP_TOTAL, max(0, min(int(rp_total), RP_MAX)))
    struct.pack_into("<I", rec, RES_GIL_TOTAL,
                     max(0, min(int(gil_total), 0x7FFFFFFF)))
    struct.pack_into("<I", rec, RES_MEDALS, mask & 0xFFFFFF)
    rec[RES_HOLDERS:RES_HOLDERS + RES_HOLDER_COUNT] = b"\xff" * RES_HOLDER_COUNT
    rec[RES_RANK] = clamp_rank(rank)
    struct.pack_into("<H", rec, RES_SCORE, max(0, min(int(score), 0xFFFF)))
    struct.pack_into("<II", rec, RES_ITEM, item[0] & 0xFFFFFFFF,
                     item[1] & 0xFFFFFFFF if item[0] else 0)
    return bytes(rec)


def new_career(name="", rid=0):
    return {"name": name, "id": rid, "rank": RANK_MIN, "rp": 0,
            "battles": 0, "bt": {"w": 0, "l": 0, "d": 0},
            "tbt": {"w": 0, "l": 0, "d": 0}, "fa": {"w": 0, "l": 0, "d": 0},
            "missions": {"cleared": 0, "failed": 0}, "quests": {},
            "kills": 0, "kos": 0, "heals": 0, "mvp": 0, "fa_bases": 0,
            "play_secs": 0, "medals": {}, "history": []}


def award_medals(mode, rows, winner):
    """Judge one finished battle. `rows` = per-player dicts with at least `key`
    and `team`, optionally kills / kos / heals / first_kill / finisher /
    capsules_all / base_capture / core_destroy / infiltrate_secs / cls. `winner`
    = the winning team, or None for a draw. Returns {key: [medal index, ...]}.

    Each rule is SE's own sentence from group 60 [40..63]; a "most" medal needs
    a count above zero and a unique leader (a tie awards nobody -- OURS)."""
    out = {r["key"]: [] for r in rows}

    def leader(field):
        best = max((r.get(field, 0) for r in rows), default=0)
        if best <= 0:
            return None
        top = [r["key"] for r in rows if r.get(field, 0) == best]
        return top[0] if len(top) == 1 else None

    for field, medal in (("kos", M_DISHONOR), ("heals", M_HEALER),
                         ("kills", M_SLAYER)):
        k = leader(field)
        if k is not None:
            out[k].append(medal)
    team_kos = {}
    for r in rows:
        team_kos[r.get("team")] = team_kos.get(r.get("team"), 0) + r.get("kos", 0)
    for r in rows:
        k, won = r["key"], (winner is not None and r.get("team") == winner)
        if r.get("first_kill"):
            out[k].append(M_FIRST)
        if won and r.get("kos", 0) == 0:
            out[k].append(M_IRON)                  # "not KO'd once" -- and won (OURS)
        if won and r.get("base_capture"):
            out[k].append(M_ASSAULT)
        if r.get("finisher"):
            out[k].append(M_FINISHER)
        if r.get("capsules_all"):
            out[k].append(M_SEEKER)
        if mode == "TBT" and won and team_kos.get(r.get("team"), 0) == 0:
            out[k].append(M_STAR)                  # "perfect victory" = no KOs (OURS)
        if mode == "BT" and won:
            out[k].append(M_BT)
        if mode == "FA" and r.get("core_destroy"):
            out[k].append(M_FA)
        if r.get("infiltrate_secs", 0) >= SURVIVAL_SECONDS:
            out[k].append(M_SURVIVAL)
    for cls, medal in CLASS_MEDALS.items():
        same = [r for r in rows if r.get("cls") == cls]
        best = max((r.get("kills", 0) for r in same), default=0)
        top = [r["key"] for r in same if r.get("kills", 0) == best]
        if best > 0 and len(top) == 1:
            out[top[0]].append(medal)
    return out


def battle_rp(outcome, kills, seconds):
    if seconds < RP_MIN_SECONDS:
        return 0
    base = {"w": RP_WIN, "d": RP_DRAW, "l": RP_LOSS}[outcome]
    return base + RP_PER_KILL * max(0, int(kills))


class Stats:
    """Careers keyed by docudp's wallet key (`member:N/0x<charid>`, the shop's
    and the rankings' key), in one JSON file rewritten whole on change -- the
    doc_shop / doc_rank shape."""

    def __init__(self, path):
        self.path = path
        self.data = {}
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {}
        self.data.setdefault("chars", {})

    def save(self):
        d = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".stats-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=1, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass

    def career(self, key, name=None, rid=None):
        c = self.data["chars"].get(key)
        if c is None:
            c = self.data["chars"][key] = new_career(name or "", rid or 0)
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
        """Raise the rank (never lower it) and hand out the chevron it marks.
        Returns the chevrons granted."""
        rank = clamp_rank(rank)
        got = []
        for r in range(c["rank"] + 1, rank + 1):
            if r in RANK_CHEVRONS:
                got.append(RANK_CHEVRONS[r])
        if rank > c["rank"]:
            c["rank"] = rank
        self._grant_medals(c, got)
        return got

    def record_battle(self, mode, rows, winner, seconds, quest=None, when=None):
        """Tally one finished battle for every row (see award_medals for the row
        shape; `name` / `id` are remembered). `quest` = the quest id of a Solo
        MISSION (cleared iff its row's team == winner). Returns {key: summary}
        with the rp / gil / medals / promotion this battle paid, for the result
        screen and the log."""
        mode = mode if mode in MODES else "BT"
        seconds = max(0, int(seconds or 0))
        out = {}
        if mode != "MISSION" and seconds < RP_MIN_SECONDS:
            # VOID (OURS): a table started and ended at once is not a battle --
            # nothing is tallied, so a W/L cannot be farmed by Start + leave.
            for r in rows:
                c = self.career(r["key"], r.get("name"), r.get("id"))
                summ = {"mode": mode, "outcome": "void", "rp": 0, "gil": 0,
                        "medals": [], "rank": c["rank"], "seconds": seconds,
                        "kills": 0, "kos": 0, "quest": quest,
                        "when": int(when if when is not None else time.time())}
                c["history"] = (c["history"] + [summ])[-HISTORY_MAX:]
                out[r["key"]] = summ
            self.save()
            return out
        awards = award_medals(mode, rows, winner)
        for r in rows:
            key = r["key"]
            c = self.career(key, r.get("name"), r.get("id"))
            outcome = ("d" if winner is None
                       else "w" if r.get("team") == winner else "l")
            kills, kos = max(0, int(r.get("kills", 0))), max(0, int(r.get("kos", 0)))
            c["battles"] += 1
            c["kills"] += kills
            c["kos"] += kos
            c["heals"] += max(0, int(r.get("heals", 0)))
            c["play_secs"] += seconds
            if r.get("base_capture"):
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
            else:
                c[{"BT": "bt", "TBT": "tbt", "FA": "fa"}[mode]][outcome] += 1
                rp = battle_rp(outcome, kills, seconds)
            c["rp"] = min(c["rp"] + rp, RP_MAX)
            medals = awards.get(key, []) + promo
            self._grant_medals(c, awards.get(key, []))
            summ = {"mode": mode, "outcome": outcome, "rp": rp, "gil": gil,
                    "medals": medals, "rank": c["rank"], "seconds": seconds,
                    "kills": kills, "kos": kos, "quest": quest,
                    "when": int(when if when is not None else time.time())}
            c["history"] = (c["history"] + [summ])[-HISTORY_MAX:]
            out[key] = summ
        self.save()
        return out

    def peek(self, key):
        """The career for `key` WITHOUT creating one (a fresh DGD-3 / 0 RP
        career when there is none) -- for the world door and the Status
        window, which must not litter the file with nameless entries."""
        c = self.data["chars"].get(key)
        if c is None:
            return new_career()
        for k, v in new_career().items():
            c.setdefault(k, v)
        return c

    def key_for_charid(self, cid):
        """The stored key whose character id is `cid` (bits 30/31 masked, as
        the wallet key masks them), or None."""
        suffix = "/0x%08x" % (cid & 0x3FFFFFFF)
        return next((k for k in self.data["chars"] if k.endswith(suffix)), None)

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
    p = os.path.join(tempfile.gettempdir(), "doc_stats_selftest.json")
    try:
        os.remove(p)
    except OSError:
        pass
    st = Stats(p)
    A, B, C = "member:3/0x0002aa68", "member:6/0x00041018", "member:15/0x0004107c"
    # a TBT win for team 0 (A, C) over team 1 (B); A tops kills, B tops KOs
    res = st.record_battle("TBT", [
        {"key": A, "name": "Fox", "id": 0x2aa68, "team": 0, "kills": 3,
         "first_kill": True, "finisher": True},
        {"key": B, "name": "Deck", "id": 0x41018, "team": 1, "kills": 1, "kos": 3},
        {"key": C, "name": "Quarry", "team": 0, "kills": 0}], winner=0, seconds=180)
    assert set(res[A]["medals"]) == {M_SLAYER, M_FIRST, M_IRON, M_FINISHER, M_STAR}, res[A]
    assert res[B]["medals"] == [M_DISHONOR], res[B]
    assert set(res[C]["medals"]) == {M_IRON, M_STAR}, res[C]
    assert res[A]["rp"] == RP_WIN + 3 * RP_PER_KILL and res[B]["rp"] == RP_LOSS + RP_PER_KILL
    assert st.career(A)["tbt"] == {"w": 1, "l": 0, "d": 0}
    assert st.career(B)["tbt"] == {"w": 0, "l": 1, "d": 0}
    # a BT draw pays the draw rate and no BT medal; too short pays nothing
    res = st.record_battle("BT", [{"key": A, "team": 0}, {"key": B, "team": 1}],
                           winner=None, seconds=120)
    assert res[A]["rp"] == RP_DRAW and M_BT not in res[A]["medals"]
    _void = st.record_battle("BT", [{"key": A, "team": 0}], 0, 5)[A]
    assert _void["outcome"] == "void" and _void["rp"] == 0
    assert st.career(A)["bt"] == {"w": 0, "l": 0, "d": 1}, st.career(A)["bt"]
    # a tie for most kills awards nobody
    res = st.record_battle("BT", [{"key": A, "team": 0, "kills": 2},
                                  {"key": B, "team": 1, "kills": 2}], 0, 60)
    assert M_SLAYER not in res[A]["medals"] + res[B]["medals"]
    # exams: quest 1 -> DGD-2 + the Drone chevron; quest 3 skips to DGSC-3 and
    # pays the Scout chevron; an exam never LOWERS the rank; a failed exam pays 0
    assert st.record_battle("MISSION", [{"key": C, "team": 0}], 0, 90, quest=1)[C]["rank"] == 2
    assert medal_count(st.career(C), 34) == 1
    res = st.record_battle("MISSION", [{"key": C, "team": 0}], 0, 90, quest=3)
    assert res[C]["rank"] == 4 and 39 in res[C]["medals"]
    assert st.record_battle("MISSION", [{"key": C, "team": 0}], 0, 90, quest=1)[C]["rank"] == 4
    assert st.record_battle("MISSION", [{"key": C, "team": 0}], 1, 90, quest=6)[C]["rank"] == 4
    assert st.career(C)["missions"] == {"cleared": 3, "failed": 1}
    # fixed quest rewards
    res = st.record_battle("MISSION", [{"key": B, "team": 0}], 0, 90, quest=5)
    assert res[B]["rp"] == 250
    assert st.record_battle("MISSION", [{"key": B, "team": 0}], 0, 90, quest=23)[B]["gil"] == 3000
    # persistence + the surfaces
    st2 = Stats(p)
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
    assert medal_mask(cA) >> slayer & 1 and not medal_mask(cA) >> 3 & 1
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
    assert rr[30:45] == b"\xff" * 15 and rr[48] == 4
    assert struct.unpack_from("<H", rr, 50)[0] == 15
    assert result_record("w", 0, 0, 0, 1)[0] == 1
    assert result_record("l", 0, 0, 0, 1)[0] == 0
    # peek never creates; key_for_charid finds by the masked id
    assert st2.peek("member:77/0x1")["rank"] == 1 and "member:77/0x1" not in st2.data["chars"]
    assert st2.key_for_charid(0xC002aa68) == A
    import doc_rank
    rp = os.path.join(tempfile.gettempdir(), "doc_stats_rank_selftest.json")
    try:
        os.remove(rp)
    except OSError:
        pass
    rk = doc_rank.Rankings(rp)
    st2.push_rankings(rk)
    rk2 = doc_rank.Rankings(rp)
    assert rk2.data["chars"][A]["name"] == "Fox"
    assert rk2.data["chars"][A]["ind"]["0"] == st2.career(A)["rp"]
    tab = rk2.table(False, 0)
    assert tab[0][4] in ("Fox", "Deck", "Quarry") and len(tab) == 3, tab
    print(st2.summary_line(A))
    os.remove(p)
    os.remove(rp)
    print("doc_stats self-test PASS")
    sys.exit(0)
