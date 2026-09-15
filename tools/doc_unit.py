#!/usr/bin/env python3
"""Dirge of Cerberus UNITS -- the server side of Unit Management (2026-09-13).

A Unit is a POL friend-list GROUP that its master registers with DoC for a gil
fee (KelStr group 45 "Unit Management"): an area of operations (Area I..IV),
an emblem (base, symbol, four letters), a class (Squad..Army, group 38 [0..8]),
rank points and a place in the Unit Ranking. Until now every Unit screen got
the zeroed lobby-command answer of sec 4dy -- honestly "you have no units",
and nothing could be registered.

WHAT IS MEASURED (static RE, savestates doc_eastloaded_slot09 and
doc_inworld_slot03; memory note doc-units-protocol-map):

  Every Unit verb is a LOBBY COMMAND. Request selector 240 carries the command
  byte at body[12] and 12 argument bytes at body[16..27] (builder 0x00589c48,
  through the inner object's vt+112); the answer is selector 241, whose u16
  body[12] names the same command (handler 0x00bc9210, sub-type table
  0x00bf3020, subs 3..41). The lobby phase machine 0x00ad3800 (manager
  [0x00afc610]) drives them:

    phase cmd kelsvc  request                          241 sub-type arm
     82   24  vt+464  u64 selected unit at body[16]      0x00bc9330 fills the
                      (buffer = manager+32)              176-byte unit record
     84   13  vt+368  none (buffer manager+740, cap 4)   0x00bc9520: u32 count
                                                         body[16], 8-B rows
                                                         from body[20]
     86   25  vt+480  none (buffer manager+32, cap 4)    0x00bc94c4: s8 count
                                                         body[16], u64 ids at
                                                         body[20+8i] -> record
                                                         +0, stride 176
     88    8  vt+384  u64 group at body[16] + 8 bytes    SPEND [kelsvc+24] gil
                      {u32 emblem, u16 class, u16 area}  (0x00bdf5d8)
                      at body[28..35] (0x00bd4348)
     90   10  vt+432  u64 [manager+776], the new unit    R+720 = u64 body[16]
     92   12  vt+400  as 8                               SPEND [kelsvc+24] gil
     94    9  vt+416  u64 selected unit                  no arm: a bare ack
     96   10  vt+432  u64 selected unit                  R+720 = u64 body[16]
     98   11  vt+448  u64 selected unit                  R+720 = 0
  Every one of 88..98 goes back to phase 86 (refresh my units) on success.

  The answer HEADER carries fees and refusals (demux 0x00bcc88c):
  [kelsvc+24] = u16 body[6], and with body[4] bit 0 set it becomes -body[6].
  The 8/10/11/12 arms bail on a negative [kelsvc+24]; 8 and 12 SPEND it as
  gil (R+744 -= x, floored at 0). So body[6] = the fee on success, and
  body[4] = 1 + body[6] = SE's error code on a refusal.

  The unit record, sub 24 (wire -> record at manager+32; display 0x00ad8868):
    body[16] u32 rank points -> +16 ("%d pts", 37:108)
    body[20] u32 emblem      -> +8  bits 0-3 base (<16), 4-7 symbol (<16),
                                    8-31 four 6-bit letters (0x00ad8ad0)
    body[24] u16 class       -> +12 (<9, Squad..Army)
    body[26] u16 area        -> +14 (<4, Area I..IV)
    body[28..43] name        -> +20
    body[44] -> +36   body[48] u32 -> +40 ("%d", 37:109)   body[56] -> +48
    body[64+12i..] i=0..8: nine {u32 a, u32 b, u32 c} -> +56+12i; the client
                     sums every a into +44 and every c into +52
    body[172] -> +164   body[176] -> +168
    (record +0, the u64 id, is written by sub 25 -- never by 24)

  LOGIN: setUserData 0x00be6580 (src = world-door body[44]) copies src+16..23
  = body[60..67] into R+720, the enlisted unit. WARNING: body[60..67] lies INSIDE the
  echoed 52-byte session token, so until now a character's unit was 8 token
  bytes; with --units the server writes the real id there, or 0.

WHAT IS INFERRED, and why:
  * unit id == the group's u64. Phase 90 enlists [manager+776], the very u64
    that command 8 just registered.
  * WHICH POL row that u64 names is not pinned. group_name() tries friend.id =
    the low 32 bits (a group is a `friend` row, accounts.py), and the raw u64 is
    always logged, so the first live Create Unit settles it.
  * command 13's four rows read as {u8 area, u32 value}: we send each area's
    number of units. body[48] sits under 37:104 "Unit Rank", so it gets the
    unit's position by points.
  * the FEE. The prompt's "%d gil" (45:14) is client-side and its source is not
    located; --unit-fee defaults to 0, so the client deducts nothing unless
    the server admin sets one. With --shop the server wallet pays the same fee.

NOT DONE: the banned emblem word check (SE 43148) -- the 6-bit alphabet is not
decoded, so letters are stored and logged raw. The nine stat triplets are
served as zeros: nothing tallies unit battles yet.
"""
import json
import os
import sqlite3
import struct
import tempfile
import time

CMD_REQ, CMD_ANS = 240, 241
CMD_REGISTER, CMD_DELETE, CMD_ENLIST, CMD_LEAVE, CMD_MODIFY = 8, 9, 10, 11, 12
CMD_AREAS, CMD_INFO, CMD_MINE = 13, 24, 25
UNIT_CMDS = (CMD_REGISTER, CMD_DELETE, CMD_ENLIST, CMD_LEAVE, CMD_MODIFY,
             CMD_AREAS, CMD_INFO, CMD_MINE)
CMD_NAMES = {CMD_REGISTER: "REGISTER", CMD_DELETE: "DELETE",
             CMD_ENLIST: "ENLIST", CMD_LEAVE: "LEAVE", CMD_MODIFY: "MODIFY",
             CMD_AREAS: "AREAS", CMD_INFO: "INFO", CMD_MINE: "MY UNITS"}

# request (240)
REQ_CMD, REQ_ID = 12, 16
REQ_EMBLEM, REQ_CLASS, REQ_AREA = 28, 32, 34

# answer (241) header + body
HDR_FLAGS, HDR_VALUE = 4, 6        # bit 0 = failure; u16 -> [kelsvc+24]
FLAG_FAIL = 0x0001
ANS_CMD = 12                       # u16
ANS_LEN = 184                      # >= 180, the last byte sub 24 reads

INFO_PTS, INFO_EMBLEM, INFO_CLASS, INFO_AREA = 16, 20, 24, 26
INFO_NAME, INFO_NAME_LEN = 28, 16
INFO_RANK = 48
INFO_STATS, STAT_ROWS = 64, 9

MINE_COUNT, MINE_IDS, MINE_MAX = 16, 20, 4
AREA_COUNT, AREA_ROWS, AREA_ROW, AREAS = 16, 20, 8, 4
ENLIST_ID = 16

LOGIN_UNIT_OFF = 60                # world-door body[60..67] -> R+720

# SE's own refusal codes (the client's own error table)
ERR_GIL = 43016                    # not enough gil
ERR_ALREADY = 43146                # that group is already registered as a unit
ERR_BADWORD = 43148                # emblem word cannot be registered
ERR_NOUNIT = 43150                 # could not find specified unit

CLASSES = ("Squad", "Platoon", "Company", "Battalion", "Regiment", "Brigade",
           "Division", "Corps", "Army")
AREA_NAMES = ("Area I", "Area II", "Area III", "Area IV")
U64 = 0xFFFFFFFFFFFFFFFF
KIND_GROUP = 0x0001                # accounts.py: a group is a friend row


def hexid(uid):
    return "0x%x" % (uid & U64)


def parse_request(req_body):
    """{cmd, id, emblem, cls, area} from a selector-240 body, or None."""
    if req_body is None or len(req_body) < REQ_ID + 8:
        return None
    out = {"cmd": req_body[REQ_CMD],
           "id": struct.unpack_from("<Q", req_body, REQ_ID)[0],
           "emblem": None, "cls": None, "area": None}
    if len(req_body) >= REQ_AREA + 2:
        out["emblem"] = struct.unpack_from("<I", req_body, REQ_EMBLEM)[0]
        out["cls"], out["area"] = struct.unpack_from("<HH", req_body, REQ_CLASS)
    return out


def emblem_parts(emblem):
    """(base, symbol, [four 6-bit letter codes]) -- what 0x00ad8868 checks."""
    e = emblem & 0xFFFFFFFF
    letters, rest = [], e >> 8
    for _ in range(4):
        letters.append(rest & 0x3F)
        rest >>= 6
    return e & 0x0F, (e >> 4) & 0x0F, letters


def answer_head(cmd, subchannel=7, value=0, fail=None, length=ANS_LEN):
    """A 241 body with the command at body[12] and the header word the demux
    turns into [kelsvc+24]: `value` (a fee) on success, `fail` (SE's code)
    with the failure bit on a refusal."""
    b = bytearray(length)
    b[0] = subchannel & 0xFF
    b[1] = CMD_ANS
    if fail:
        struct.pack_into("<H", b, HDR_FLAGS, FLAG_FAIL)
        struct.pack_into("<H", b, HDR_VALUE, fail & 0xFFFF)
    else:
        struct.pack_into("<H", b, HDR_VALUE, max(0, min(value, 0xFFFF)))
    struct.pack_into("<H", b, ANS_CMD, cmd & 0xFFFF)
    return b


def _name(s, n):
    raw = str(s or "").encode("latin-1", "replace")[:n - 1]
    return raw.ljust(n, b"\x00")


def standings(units):
    """{hexid: unit} -> {hexid: rank}, points-descending, ties share a rank."""
    rows = sorted(units.items(), key=lambda kv: (-int(kv[1].get("pts", 0)),
                                                 str(kv[1].get("name", "")).lower(),
                                                 kv[0]))
    out, rank, prev = {}, 0, None
    for i, (k, u) in enumerate(rows):
        p = int(u.get("pts", 0))
        if p != prev:
            rank, prev = i + 1, p
        out[k] = rank
    return out


class Units:
    """The unit store: {"units": {hexid: {name, emblem, cls, area, pts, stats,
    registrant, members, created}}, "enlist": {key: hexid}} in one JSON file,
    rewritten whole on change (doc_shop's shape). A key is docudp's wallet key
    `member:N/0x<charid>`, the same one the shop and the rankings use, so a
    character's gil, rank and unit are one identity."""

    def __init__(self, path, fee=0, shop=None, accounts_db=None):
        self.path = path
        self.fee = max(0, min(int(fee or 0), 0xFFFF))
        self.shop = shop
        self.accounts_db = accounts_db
        self.data = {}
        self.load()

    # -- persistence -------------------------------------------------------
    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {}
        self.data.setdefault("units", {})
        self.data.setdefault("enlist", {})

    def save(self):
        d = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".unit-", suffix=".tmp")
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

    # -- lookups -----------------------------------------------------------
    def group_name(self, uid):
        """The POL group's name for a unit id, or None. Best effort: the id's
        low 32 bits as a `friend` row of kind GROUP (read-only)."""
        if not self.accounts_db:
            return None
        try:
            uri = "file:%s?mode=ro" % os.path.abspath(self.accounts_db)
            db = sqlite3.connect(uri, uri=True, timeout=2)
            try:
                row = db.execute("SELECT peer_name, kind FROM friend WHERE id = ?",
                                 (uid & 0xFFFFFFFF,)).fetchone()
            finally:
                db.close()
        except sqlite3.Error:
            return None
        if row and (int(row[1] or 0) & KIND_GROUP):
            return row[0]
        return None

    def unit(self, uid):
        return self.data["units"].get(hexid(uid))

    def enlisted(self, key):
        """The unit id `key` is enlisted in, or 0 -- what login writes to R+720."""
        h = self.data["enlist"].get(key)
        return int(h, 16) if h and h in self.data["units"] else 0

    def my_units(self, key):
        """Up to 4 unit ids for `key`: the enlisted one first, then every unit
        it registered or belongs to (the lobby buffer holds 4)."""
        out = []
        e = self.enlisted(key)
        if e:
            out.append(e)
        for h, u in sorted(self.data["units"].items()):
            if key == u.get("registrant") or key in (u.get("members") or ()):
                uid = int(h, 16)
                if uid not in out:
                    out.append(uid)
        return out[:MINE_MAX]

    def ranking_units(self):
        """doc_rank's `units` shape: {hexid: {"name", "unit": {"0": points}}}."""
        return {h: {"name": u.get("name", h), "unit": {"0": int(u.get("pts", 0))}}
                for h, u in self.data["units"].items()}

    # -- the fee -----------------------------------------------------------
    def _charge(self, key):
        """(ok, note). Charge the fee to the shop wallet when there is one."""
        if not self.fee:
            return True, "fee 0"
        if self.shop is None:
            return True, "fee %d (client-side only, no --shop)" % self.fee
        w = self.shop.wallet(key)
        if w["gil"] < self.fee:
            return False, "wallet %d gil < fee %d" % (w["gil"], self.fee)
        w["gil"] -= self.fee
        self.shop.save()
        return True, "fee %d -> wallet %d gil" % (self.fee, w["gil"])

    # -- answers -----------------------------------------------------------
    def info_body(self, uid, subchannel=7):
        b = answer_head(CMD_INFO, subchannel)
        u = self.unit(uid)
        if u is None:
            return b                          # "not enlisted": an empty record
        struct.pack_into("<I", b, INFO_PTS, int(u.get("pts", 0)) & 0xFFFFFFFF)
        struct.pack_into("<I", b, INFO_EMBLEM, int(u.get("emblem", 0)) & 0xFFFFFFFF)
        struct.pack_into("<HH", b, INFO_CLASS,
                         min(int(u.get("cls", 0)), len(CLASSES) - 1),
                         min(int(u.get("area", 0)), AREAS - 1))
        b[INFO_NAME:INFO_NAME + INFO_NAME_LEN] = _name(u.get("name"), INFO_NAME_LEN)
        struct.pack_into("<I", b, INFO_RANK,
                         standings(self.data["units"]).get(hexid(uid), 0))
        stats = u.get("stats") or []
        for i in range(STAT_ROWS):
            row = (list(stats[i]) if i < len(stats) else []) + [0, 0, 0]
            struct.pack_into("<III", b, INFO_STATS + 12 * i,
                             *(int(x) & 0xFFFFFFFF for x in row[:3]))
        return b

    def mine_body(self, key, subchannel=7):
        b = answer_head(CMD_MINE, subchannel)
        ids = self.my_units(key)
        b[MINE_COUNT] = len(ids)
        for i, uid in enumerate(ids):
            struct.pack_into("<Q", b, MINE_IDS + 8 * i, uid & U64)
        return b, ids

    def areas_body(self, subchannel=7):
        b = answer_head(CMD_AREAS, subchannel)
        counts = [0] * AREAS
        for u in self.data["units"].values():
            a = int(u.get("area", 0))
            if 0 <= a < AREAS:
                counts[a] += 1
        struct.pack_into("<I", b, AREA_COUNT, AREAS)
        for i, n in enumerate(counts):
            struct.pack_into("<BxxxI", b, AREA_ROWS + AREA_ROW * i, i, n)
        return b, counts

    def body_for(self, cmd, req_body, key, subchannel=7):
        """(241 body, note) for one Unit lobby command, or (None, why)."""
        if cmd not in UNIT_CMDS:
            return None, "not a unit command"
        req = parse_request(req_body)
        if req is None:
            return None, "240 body unreadable"
        self.load()                            # the file is the source of truth
        uid, h = req["id"], hexid(req["id"])
        units = self.data["units"]
        raw = bytes(req_body[16:36]).hex(" ")
        tag = "%s (cmd %d)" % (CMD_NAMES[cmd], cmd)

        def refuse(code, why):
            return (answer_head(cmd, subchannel, fail=code),
                    "%s REFUSED %d: %s  [req body[16..35] = %s]" % (tag, code, why, raw))

        if cmd == CMD_INFO:
            u = units.get(h)
            return self.info_body(uid, subchannel), "%s %s: %s" % (
                tag, h, ("%r %s, %s, %d pts" % (
                    u.get("name"), CLASSES[min(int(u.get("cls", 0)), 8)],
                    AREA_NAMES[min(int(u.get("area", 0)), 3)], int(u.get("pts", 0))))
                if u else "no such unit -> empty record")
        if cmd == CMD_MINE:
            b, ids = self.mine_body(key, subchannel)
            return b, "%s [%s]: %d unit(s) %s" % (tag, key, len(ids),
                                                 ", ".join(hexid(i) for i in ids))
        if cmd == CMD_AREAS:
            b, counts = self.areas_body(subchannel)
            return b, "%s: units per area %s (row meaning inferred)" % (tag, counts)

        if cmd in (CMD_REGISTER, CMD_MODIFY):
            if not uid:
                return refuse(ERR_NOUNIT, "group id 0")
            if req["emblem"] is None:
                return refuse(ERR_NOUNIT, "no emblem/class/area in the request")
            base, sym, letters = emblem_parts(req["emblem"])
            cls = min(int(req["cls"] or 0), len(CLASSES) - 1)
            area = min(int(req["area"] or 0), AREAS - 1)
            if cmd == CMD_REGISTER and h in units:
                return refuse(ERR_ALREADY, "%s is already a unit" % h)
            if cmd == CMD_MODIFY and h not in units:
                return refuse(ERR_NOUNIT, "%s is not a unit" % h)
            ok, fee_note = self._charge(key)
            if not ok:
                return refuse(ERR_GIL, fee_note)
            if cmd == CMD_REGISTER:
                name = self.group_name(uid) or "Unit %X" % (uid & 0xFFFFFFFF)
                units[h] = {"name": name, "pts": 0, "stats": [],
                            "registrant": key, "members": [key],
                            "created": int(time.time())}
            u = units[h]
            u.update(emblem=req["emblem"] & 0xFFFFFFFF, cls=cls, area=area)
            self.save()
            return (answer_head(cmd, subchannel, value=self.fee),
                    "%s %s %r: emblem base %d symbol %d letters %s, %s, %s; %s  "
                    "[req body[16..35] = %s]" % (tag, h, u["name"], base, sym,
                                                 letters, CLASSES[cls],
                                                 AREA_NAMES[area], fee_note, raw))
        if cmd == CMD_DELETE:
            u = units.get(h)
            if u is None:
                return refuse(ERR_NOUNIT, "%s is not a unit" % h)
            del units[h]
            for k in [k for k, v in self.data["enlist"].items() if v == h]:
                del self.data["enlist"][k]
            self.save()
            return answer_head(cmd, subchannel), "%s %s %r deleted (registrant %s)" % (
                tag, h, u.get("name"), u.get("registrant"))
        if cmd == CMD_ENLIST:
            u = units.get(h)
            if u is None:
                return refuse(ERR_NOUNIT, "%s is not a unit" % h)
            self.data["enlist"][key] = h
            if key not in u.setdefault("members", []):
                u["members"].append(key)
            self.save()
            b = answer_head(cmd, subchannel)
            struct.pack_into("<Q", b, ENLIST_ID, uid & U64)
            return b, "%s [%s] -> %s %r (R+720)" % (tag, key, h, u.get("name"))
        if cmd == CMD_LEAVE:
            was = self.data["enlist"].pop(key, None)
            self.save()
            return answer_head(cmd, subchannel), "%s [%s]: left %s" % (tag, key, was)
        return None, "unhandled"


def apply_login(body, unit_id):
    """Write the enlisted unit (or 0) into a selector-2 answer body."""
    need = LOGIN_UNIT_OFF + 8
    if len(body) < need:
        body += bytes(need - len(body))
    struct.pack_into("<Q", body, LOGIN_UNIT_OFF, (unit_id or 0) & U64)
    return body


if __name__ == "__main__":
    import sys
    p = os.path.join(tempfile.gettempdir(), "doc_unit_selftest.json")
    try:
        os.remove(p)
    except OSError:
        pass
    k1, k2 = "member:3/0x0004103c", "member:6/0x00041058"
    us = Units(p)
    G = 0x0000000700000029               # an arbitrary group u64

    def req(cmd, uid=0, emblem=None, cls=0, area=0):
        b = bytearray(36)
        b[REQ_CMD] = cmd
        struct.pack_into("<Q", b, REQ_ID, uid)
        if emblem is not None:
            struct.pack_into("<IHH", b, REQ_EMBLEM, emblem, cls, area)
        return bytes(b)

    def hdr(b):
        return struct.unpack_from("<HH", b, HDR_FLAGS)

    # nothing yet: my units is empty, info of 0 is an empty record
    b, _ = us.body_for(CMD_MINE, req(CMD_MINE), k1)
    assert b[1] == CMD_ANS and b[ANS_CMD] == CMD_MINE and b[MINE_COUNT] == 0
    b, _ = us.body_for(CMD_INFO, req(CMD_INFO, 0), k1)
    assert b[INFO_PTS:INFO_PTS + 16] == bytes(16) and len(b) >= 180
    # register: emblem base 3, symbol 5, letters 1..4; Platoon, Area III
    em = 3 | (5 << 4) | (1 << 8) | (2 << 14) | (3 << 20) | (4 << 26)
    b, note = us.body_for(CMD_REGISTER, req(CMD_REGISTER, G, em, 1, 2), k1)
    assert hdr(b) == (0, 0), note
    assert emblem_parts(em) == (3, 5, [1, 2, 3, 4])
    # again -> SE 43146 with the failure bit
    b, note = us.body_for(CMD_REGISTER, req(CMD_REGISTER, G, em, 1, 2), k1)
    assert hdr(b) == (FLAG_FAIL, ERR_ALREADY) and "REFUSED" in note
    # enlist -> body[16] = the id; login field follows
    b, _ = us.body_for(CMD_ENLIST, req(CMD_ENLIST, G), k1)
    assert struct.unpack_from("<Q", b, ENLIST_ID)[0] == G
    assert Units(p).enlisted(k1) == G, "persisted"
    lb = apply_login(bytearray(56), Units(p).enlisted(k1))
    assert struct.unpack_from("<Q", lb, LOGIN_UNIT_OFF)[0] == G
    # my units + info
    b, _ = us.body_for(CMD_MINE, req(CMD_MINE), k1)
    assert b[MINE_COUNT] == 1 and struct.unpack_from("<Q", b, MINE_IDS)[0] == G
    b, _ = us.body_for(CMD_INFO, req(CMD_INFO, G), k1)
    assert struct.unpack_from("<I", b, INFO_EMBLEM)[0] == em
    assert struct.unpack_from("<HH", b, INFO_CLASS) == (1, 2)
    assert b[INFO_NAME:INFO_NAME + 8] == b"Unit 29\x00"
    assert struct.unpack_from("<I", b, INFO_RANK)[0] == 1
    # areas: one unit in Area III
    b, _ = us.body_for(CMD_AREAS, req(CMD_AREAS), k1)
    assert struct.unpack_from("<I", b, AREA_COUNT)[0] == 4
    assert [struct.unpack_from("<BxxxI", b, AREA_ROWS + 8 * i) for i in range(4)] \
        == [(0, 0), (1, 0), (2, 1), (3, 0)]
    # modify an unknown unit -> 43150; modify ours -> Area IV
    b, _ = us.body_for(CMD_MODIFY, req(CMD_MODIFY, 0x99, em, 0, 0), k1)
    assert hdr(b) == (FLAG_FAIL, ERR_NOUNIT)
    b, _ = us.body_for(CMD_MODIFY, req(CMD_MODIFY, G, em, 1, 3), k1)
    assert hdr(b) == (0, 0) and us.unit(G)["area"] == 3
    # a second character enlists, then leaves
    us.body_for(CMD_ENLIST, req(CMD_ENLIST, G), k2)
    assert us.enlisted(k2) == G and us.my_units(k2) == [G]
    b, _ = us.body_for(CMD_LEAVE, req(CMD_LEAVE, G), k2)
    assert hdr(b) == (0, 0) and us.enlisted(k2) == 0
    # the ranking feed
    assert us.ranking_units()[hexid(G)]["name"] == "Unit 29"
    # the fee rides body[6] and is charged to a --shop wallet
    import doc_shop
    sp = p + ".shop"
    shop = doc_shop.Shop(sp, start_gil=500)
    uf = Units(p, fee=300, shop=shop)
    b, note = uf.body_for(CMD_REGISTER, req(CMD_REGISTER, 0x42, em, 0, 0), k1)
    assert hdr(b) == (0, 300) and shop.wallet(k1)["gil"] == 200, note
    b, note = uf.body_for(CMD_REGISTER, req(CMD_REGISTER, 0x43, em, 0, 0), k1)
    assert hdr(b) == (FLAG_FAIL, ERR_GIL) and 0x43 not in [int(x, 16) for x in uf.data["units"]]
    # delete clears enlistments
    b, _ = us.body_for(CMD_DELETE, req(CMD_DELETE, G), k1)
    us.load()
    assert hdr(b) == (0, 0) and us.enlisted(k1) == 0 and hexid(G) not in us.data["units"]
    for f in (p, sp):
        os.remove(f)
    print("doc_unit self-test PASS")
    sys.exit(0)
