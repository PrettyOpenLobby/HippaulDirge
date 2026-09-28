#!/usr/bin/env python3
"""Dirge of Cerberus RANKINGS -- the server side of 137 / 149 (2026-09-13).

The lobby terminal's `Ranking` menu (Individual Ranking / Unit Ranking) asks
over kelsvc and, until now, got docudp's generic `selector + 1` answer, which
ECHOES the request body. The page size the client asked for (30, at request
body[16]) therefore landed in the answer's ROW COUNT byte, and the screen drew
30 empty rows. A savestate of the lobby (2026-09-13 07:02Z) holds exactly
that: list count 30, first position 0, row 0 +0 = 15 (the category of the tab
last opened, echoed from request body[24]).

WHAT IS MEASURED (retail lobby + online module, slot 10 / doc_p30_slot01,
byte-identical there):

  lobby phase 74 (0x00ad4a74) -> kelsvc vt+976 0x00bd5838 -> builder 0x00bce488
      sends SELECTOR 137, parks [kelsvc+12] = 43; the page is clamped to 50
      and the ROW BUFFER is the lobby's own list (manager+32 -> [kelsvc+1052])
  lobby phase 76 (0x00ad4b18) -> vt+992 0x00bd6298 -> builder 0x00bce520
      sends SELECTOR 149 (Unit Ranking), same shape
  request body:  [12] u32 START   [16] u32 PAGE (30)   [20] u32 MODE
                 [24] u32 CATEGORY
      MODE: phase 74 turns the menu's start into it --
        start  > 0 -> mode 0, a page from `start`         (Next / Previous)
        start == 0 -> mode 1, start 1: VIEW YOUR RANKING   (command 2 -> 0xab41e4)
        start  < 0 -> mode 2, start = -start: VIEW SPECIFIC RANKING (the number
                      dialog 0x00ab45a0 -> command 4 -> 0xab41d4)
  answer 138 (Individual): arm 0x00bcd4c4 (no state gate) -> 0x00bca218, then
      0x00bcd620 clears the pending bit and sets state 2 (the poll's release)
  answer 150 (Unit): arm 0x00bcd608 -> 0x00bca140, same release
      with a3 = the raw datagram, so a3+24 == body:
        body[12..15] u32 -> [kelsvc+1056] -> list +2012  FIRST POSITION (1-based)
        body[16]     u8  -> rows in this message (clamped to the page)
        body[17]     u8  -> [kelsvc+232]  -> list +2000  FLAGS
        body[20..23] u32 -> [kelsvc+228]  -> list +2004  RANK of the first row
        138 rows from body[24], stride 28 -> 32-byte slots:
            +0 u32 id   +4 u32 VALUE   +8 u32 RANK   +12 char[16] name
        150 rows from body[28], stride 36 -> 40-byte slots:
            +0 u64 id   +8 u32 VALUE   +12 u32 RANK  +16 char[20] name
  poll (phase 75 / 77): vt+984 0x00bd61b8 / vt+1000 0x00bd6378 copy
      [+1060] [+232] [+228] [+1056] to list +2008 +2000 +2004 +2012
  renderer 0x00ab39b0: column 1 = row RANK ("%d"), column 2 = name, column 3 =
      row VALUE -- "%d", or for a RATIO tab "%d.%d%d%d%d" of decimal digits
      9..5 of the value, i.e. VALUE / 10^9 to four places (1.0000 =
      1,000,000,000; the u32 caps a ratio at 4.2949)

WHAT IS INFERRED, and why:
  * FLAGS bit 0 = "this page reaches the end of the list". The renderer only
    tests bit 0, together with first+count-1 < the asked-for rank, to raise
    "Specified ranking does not exist" (43:16). 0 is always safe.
  * list +2004 seeds the renderer's TIE-AWARE rank it uses to place the cursor
    on the asked-for rank (a value equal to the previous row keeps its rank).
    We send the first row's own rank.
  * row +0 is never read by the renderer. We send the character id.

THE CATEGORIES (tab table 0x00af5990 = {74 or 76, category}, label table at
0x00af58a0, value-column-header table at 0x00af58f0, ratio flags 0x00af5940):
  Individual 0..6 are labelled KelStr 43:24..30 and 7..17 by group-60 medal
  names; Unit 0..2 are 43:31..33. WARNING: EVERY 43:24..39 IS PAST THE END OF EVERY
  lobby.bin WE HAVE (group 43 holds 24) -- that is the tab row of `!!na!!`.
  Individual 2, 4, 6 and Unit 2 are RATIO tabs. Category 13 has no tab.

NOT DONE: nothing tallies the values yet -- they come from the rankings JSON
(the same file a web board / Discord post can read), and a character with no
entry ranks with 0. Units do not exist server-side, so Unit Ranking is an
honest empty list unless the JSON names some.
"""
import os
import struct
import time

IND_REQ, IND_ANS = 137, 138
UNIT_REQ, UNIT_ANS = 149, 150
RANK_REQS = (IND_REQ, UNIT_REQ)

REQ_START, REQ_PAGE, REQ_MODE, REQ_CAT = 12, 16, 20, 24
MODE_PAGE, MODE_MINE, MODE_SPECIFIC = 0, 1, 2
PAGE_MAX = 50                    # vt+976 clamps the page (slti s1, 51)

ANS_FIRST = 12                   # u32 -> list +2012
ANS_COUNT = 16                   # u8
ANS_FLAGS = 17                   # u8  -> list +2000
ANS_FIRST_RANK = 20              # u32 -> list +2004
FLAG_END = 0x01

IND_ROWS, IND_ROW = 24, 28       # u32 id, u32 value, u32 rank, char[16]
UNIT_ROWS, UNIT_ROW = 28, 36     # u64 id, u32 value, u32 rank, char[20]
IND_NAME, UNIT_NAME = 16, 20

RATIO_SCALE = 10 ** 9
U32_MAX = 0xFFFFFFFF

# category -> (label, is_ratio). Individual 0..6 and Unit 0..2 are OUR labels:
# SE's (43:24..33) are missing from every table we have. Medal tabs are SE's
# own group-60 names, placed by the tab table.
# PARTIAL: 0..6 are an INFERENCE (read off the tab table, not measured): the tab order
# 1,3,5,0,2,4,6 reads as three (count, rate) pairs plus RP; the value-column
# headers pair cat 0 with Unit 0 (RP; "Unit Rank Points" exists) and cat 3 with
# Unit 1 (units fight team battles -> wins); cat 1 and cat 5 each have a header
# of their own; SE's site names Ranking Points, BT victories (優勝), team wins,
# kills (撃破数) and the kill rate (撃破レート) as the tracked stats; the Status
# screen shows BT Victories, TBT Results and a win rate = (W + D/2) / battles.
IND_CATEGORIES = {
    0: ("Ranking Points", False), 1: ("BT Victories", False),
    2: ("BT Victory Rate", True), 3: ("Team Battle Wins", False),
    4: ("Team Battle Win Rate", True), 5: ("Kills", False),
    6: ("Kill Rate", True),
    7: ("Medal of Dishonor", False), 8: ("Healer", False),
    9: ("Assault", False), 10: ("Slayer", False), 11: ("Seeker", False),
    12: ("BT", False), 14: ("Super Trooper", False),
    15: ("Super Armored", False), 16: ("Super Sniper", False),
    17: ("Survival", False),
}
UNIT_CATEGORIES = {       # PARTIAL: inferred as above
    0: ("Unit Rank Points", False), 1: ("Unit Wins", False),
    2: ("Unit Win Rate", True),
}


def parse_request(req_body):
    """(start, page, mode, category) from a 137/149 body, or None."""
    if req_body is None or len(req_body) < REQ_CAT + 4:
        return None
    start, page, mode, cat = struct.unpack_from("<iIII", req_body, REQ_START)
    return start, page, mode, cat


def encode_value(v, ratio):
    """The u32 the row carries: an int as-is, a ratio as value x 10^9."""
    try:
        v = float(v) * RATIO_SCALE if ratio else int(v)
    except (TypeError, ValueError):
        v = 0
    return int(min(max(v, 0), U32_MAX))


def _name(s, n):
    b = str(s or "").encode("latin-1", "replace")[:n - 1]
    return b.ljust(n, b"\x00")


def standings(entries):
    """[(key, id, name, value)] -> [(pos, rank, key, id, name, value)], sorted
    value-descending then name, with competition ranking (a tie shares the
    better rank, the next distinct value skips) -- 1, 2, 2, 4."""
    rows = sorted(entries, key=lambda e: (-e[3], str(e[2]).lower(), str(e[0])))
    out, rank, prev = [], 0, None
    for i, (key, rid, name, value) in enumerate(rows):
        if value != prev:
            rank, prev = i + 1, value
        out.append((i + 1, rank, key, rid, name, value))
    return out


def page_of(table, start, page, mode, key=None):
    """Which slice of `table` a request asks for -> (first_pos, rows)."""
    page = max(1, min(int(page or 30), PAGE_MAX))
    if not table:
        return 1, []
    if mode == MODE_MINE:
        mine = next((r[0] for r in table if r[2] == key), 1)
        first = (mine - 1) // page * page + 1
    elif mode == MODE_SPECIFIC:
        first = (max(int(start), 1) - 1) // page * page + 1
    else:
        first = max(int(start), 1)
    return first, table[first - 1:first - 1 + page]


def answer_body(selector, first, rows, total, subchannel=7):
    """A 138 (Individual) or 150 (Unit) body. `rows` are standings() tuples
    already encoded: (pos, rank, key, id, name, u32_value)."""
    unit = selector == UNIT_ANS
    off0, stride = (UNIT_ROWS, UNIT_ROW) if unit else (IND_ROWS, IND_ROW)
    body = bytearray(off0 + stride * len(rows))
    body[0] = subchannel & 0xFF
    body[1] = selector & 0xFF
    struct.pack_into("<I", body, ANS_FIRST, first if rows else 0)
    body[ANS_COUNT] = len(rows)
    last = first + len(rows) - 1
    body[ANS_FLAGS] = FLAG_END if (not rows or last >= total) else 0
    struct.pack_into("<I", body, ANS_FIRST_RANK, rows[0][1] if rows else 0)
    for i, (_pos, rank, _key, rid, name, value) in enumerate(rows):
        o = off0 + i * stride
        if unit:
            struct.pack_into("<QII", body, o, rid & 0xFFFFFFFFFFFFFFFF,
                             value, rank)
            body[o + 16:o + 16 + UNIT_NAME] = _name(name, UNIT_NAME)
        else:
            struct.pack_into("<III", body, o, rid & 0xFFFFFFFF, value, rank)
            body[o + 12:o + 12 + IND_NAME] = _name(name, IND_NAME)
    return bytes(body)


class Rankings:
    """The rankings store: {"chars": {key: {"name", "id", "ind": {cat: v}}},
    "units": {id: {"name", "unit": {cat: v}}}} in one JSON file, rewritten whole
    on change (doc_shop's shape). A key is docudp's wallet key,
    `member:N/0x<charid>`, so the shop and the rankings name one character the
    same way. `characters` is a callable returning [(key, name, id)] -- every
    character the server knows (the chara store), so a character with no stats
    still ranks, with 0."""

    def __init__(self, store, characters=None, show_zero=True, units=None):
        if isinstance(store, str):
            raise TypeError("a file path is not a store any more: pass "
                            "docdb.store('rankings') or None")
        self.store = store
        self.characters = characters or (lambda: [])
        self.show_zero = show_zero
        # 2026-09-13: registered units (doc_unit.Units.ranking_units), merged
        # under the file's own "units" -- the file wins on a shared id.
        self.units = units or (lambda: {})
        self.data = {}
        self.load()

    def load(self):
        """Read the store. A database that cannot be reached raises
        (docdb.py): the responder does not run on an empty store."""
        self.data = self.store.load() if self.store is not None else {}
        self.data.setdefault("chars", {})
        self.data.setdefault("units", {})

    def save(self):
        if self.store is not None:
            self.store.save(self.data)

    def note_character(self, key, name, rid):
        """Remember a character that entered the world (name + id), so it is
        listed even after it leaves the chara store."""
        c = self.data["chars"].setdefault(key, {})
        if c.get("name") != name or c.get("id") != rid:
            c.update(name=name, id=rid, seen=int(time.time()))
            self.save()

    def _entries(self, unit, cat):
        ratio = (UNIT_CATEGORIES if unit else IND_CATEGORIES).get(cat, ("", False))[1]
        out = {}
        if unit:
            merged = dict(self.units())
            merged.update(self.data["units"])
            for uid, u in merged.items():
                v = (u.get("unit") or {}).get(str(cat))
                if v is None and not self.show_zero:
                    continue
                out[uid] = (uid, int(uid, 0), u.get("name", uid),
                            encode_value(v or 0, ratio))
            return list(out.values())
        for key, name, rid in self.characters():
            out[key] = (key, rid, name, 0)
        for key, c in self.data["chars"].items():
            v = (c.get("ind") or {}).get(str(cat))
            if key in out:
                k, rid, name, _ = out[key]
                out[key] = (k, rid, name, encode_value(v or 0, ratio))
            elif c.get("name") and (v is not None or self.show_zero):
                # a character the chara store no longer holds, remembered by
                # note_character(); an entry with no name matches nobody (a
                # stale or mistyped key) and is not listed as its raw key
                out[key] = (key, int(c.get("id") or 0), c["name"],
                            encode_value(v or 0, ratio))
        if not self.show_zero:
            out = {k: e for k, e in out.items() if e[3]}
        return list(out.values())

    def table(self, unit, cat):
        return standings(self._entries(unit, cat))

    def body_for(self, req_sel, req_body, key, subchannel=7):
        """(answer body, note) for one ranking request, or (None, why)."""
        if req_sel not in RANK_REQS:
            return None, "not a ranking request"
        req = parse_request(req_body)
        if req is None:
            return None, "%d body unreadable" % req_sel
        start, page, mode, cat = req
        unit = req_sel == UNIT_REQ
        self.load()                    # the file is the source of truth
        tab = self.table(unit, cat)
        first, rows = page_of(tab, start, page, mode, key)
        ans = UNIT_ANS if unit else IND_ANS
        label = (UNIT_CATEGORIES if unit else IND_CATEGORIES).get(
            cat, ("category %d (no tab)" % cat, False))[0]
        note = ("%s cat %d %r: mode %d start %d page %d -> rows %d..%d of %d%s"
                % ("UNIT" if unit else "INDIVIDUAL", cat, label, mode, start,
                   page, first, first + len(rows) - 1, len(tab),
                   ("  [" + ", ".join("%d.%s=%d" % (r[1], r[4], r[5])
                                      for r in rows[:5])
                    + (" ..." if len(rows) > 5 else "") + "]") if rows else ""))
        return answer_body(ans, first, rows, len(tab), subchannel), note


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import docdb
    import docpg
    docpg.need_database("doc_rank")
    docdb.store("rankings").clear()
    chars = [("member:3/0x0004103c", "Ace", 0x4103C),
             ("member:6/0x00041058", "Deck", 0x41058),
             ("member:15/0x0004107c", "Quarry", 0x4107C)]
    rk = Rankings(docdb.store("rankings"), characters=lambda: chars)
    rk.data["chars"]["member:3/0x0004103c"] = {"ind": {"0": 250, "2": 0.5}}
    rk.data["chars"]["member:6/0x00041058"] = {"ind": {"0": 250}}
    rk.save()

    def req(start, page, mode, cat):
        b = bytearray(28)
        struct.pack_into("<iIII", b, REQ_START, start, page, mode, cat)
        return bytes(b)

    body, note = rk.body_for(IND_REQ, req(1, 30, 0, 0), "member:3/0x0004103c")
    assert body[1] == IND_ANS and body[ANS_COUNT] == 3, note
    assert struct.unpack_from("<I", body, ANS_FIRST)[0] == 1
    assert body[ANS_FLAGS] == FLAG_END
    rows = [struct.unpack_from("<III", body, IND_ROWS + IND_ROW * i)
            for i in range(3)]
    names = [body[IND_ROWS + IND_ROW * i + 12:IND_ROWS + IND_ROW * i + 28]
             .split(b"\0")[0].decode() for i in range(3)]
    # 250 / 250 / 0 -> ranks 1, 1, 3; the tie breaks by name (Ace before Deck)
    assert names == ["Ace", "Deck", "Quarry"], names
    assert [r[2] for r in rows] == [1, 1, 3], rows
    assert [r[1] for r in rows] == [250, 250, 0]
    assert rows[0][0] == 0x4103C
    assert len(body) == IND_ROWS + 3 * IND_ROW
    # a ratio tab: 0.5 -> 500,000,000 -> "0.5000"
    body, _ = rk.body_for(IND_REQ, req(1, 30, 0, 2), "member:3/0x0004103c")
    assert struct.unpack_from("<I", body, IND_ROWS + 4)[0] == 500000000
    # paging: page 2 of 1 from start 2
    body, _ = rk.body_for(IND_REQ, req(2, 1, 0, 0), "x")
    assert struct.unpack_from("<I", body, ANS_FIRST)[0] == 2
    assert body[ANS_COUNT] == 1 and body[ANS_FLAGS] == 0
    assert struct.unpack_from("<I", body, ANS_FIRST_RANK)[0] == 1   # a tie
    # VIEW YOUR RANKING: Quarry is 3rd; page 2 -> the page starting at 3
    body, _ = rk.body_for(IND_REQ, req(1, 2, MODE_MINE, 0), "member:15/0x0004107c")
    assert struct.unpack_from("<I", body, ANS_FIRST)[0] == 3, body[:24].hex()
    # VIEW SPECIFIC RANKING past the end -> the last page, END set, and
    # first + count - 1 < 9: the renderer's own "does not exist" test (43:16)
    body, _ = rk.body_for(IND_REQ, req(9, 30, MODE_SPECIFIC, 0), "x")
    assert body[ANS_FLAGS] == FLAG_END and body[ANS_COUNT] == 3
    assert struct.unpack_from("<I", body, ANS_FIRST)[0] + body[ANS_COUNT] - 1 < 9
    # Units: none -> an empty list; one named -> a 36-byte row at body[28]
    body, _ = rk.body_for(UNIT_REQ, req(1, 30, 0, 0), "x")
    assert body[1] == UNIT_ANS and body[ANS_COUNT] == 0
    rk.data["units"]["0x10"] = {"name": "Deepground Aces", "unit": {"0": 7}}
    rk.save()
    body, _ = rk.body_for(UNIT_REQ, req(1, 30, 0, 0), "x")
    assert body[ANS_COUNT] == 1 and len(body) == UNIT_ROWS + UNIT_ROW
    assert struct.unpack_from("<QII", body, UNIT_ROWS) == (0x10, 7, 1)
    assert body[UNIT_ROWS + 16:UNIT_ROWS + 31] == b"Deepground Aces"
    # the page clamp the client applies
    assert page_of(standings([("k%d" % i, i, "n", i) for i in range(80)]),
                   1, 99, 0)[1].__len__() == PAGE_MAX
    docdb.store("rankings").clear()
    print("doc_rank self-test PASS")
    sys.exit(0)
