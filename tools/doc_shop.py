#!/usr/bin/env python3
"""Dirge of Cerberus SHOP + ITEMS -- the server side of the lobby shop (sec 4gk).

Until 2026-09-13 every shop request got docudp's generic `selector + 1` answer:
empty lists, and buys that added item 0 and spent nothing. This module serves
them from a server-owned stock and a per-character wallet + bag that persists.

LIVE (confirmed in a live session, 09-13): the lists render ("The shop is up and works!!"), and
the capture of that session names the BUY: request 66, not 145.

  Buy   req 66 (Java op 5, builder via kelsvc vt+804): body[12] u32 = args[5]
        (3 on every capture -- the shop id [lobby+12112]), body[16] u32 = ITEM,
        body[20] u32 = QTY. Captured 09:11:51-09:12:21: Auto Scope, Power Booster
        x2, Fire Materia, Silencer, Speed/Weight/Power Kit, all qty 1.
        answer 67 (gate 18, 0x00bcbda8): ADD body[12] x u16 body[20], SPEND
        body[28] (R+744 -= x, floored at 0).
  Sell  req 68 (op 6, vt+820): body[16] = the id of the args[2]-th BAG entry,
        body[20] = args[3] (or the entry's own +4 word when args[3] == -1).
        answer 69 (gate 19, 0x00bcbe98): REMOVE body[16] x u16 body[22], then
        0x00bdf570 ADDS body[24] to R+744 -- a sell credits gil immediately.
  Modify req 145 (op 9, sent by the C++ shop executor 0x00551180, tab 2):
        body[12] = shop, body[16] = SOURCE item, body[20] = RESULT item. The
        kit and fee are NOT sent -- the server looks them up in its recipes.
        answer 146 (gate 47, 0x00bcbf78): ADD body[12] x u16 body[20], REMOVE
        body[16] x u16 body[22], SPEND body[28], REMOVE kit body[32] x1 (the
        client removes that kit without checking it).

  lists  each TAB has its own round (tab table 0x00afc5f8):
         Buy    64 -> 65  (gate 17) 16-B rows {id, _, price, _}; client cap 128.
         Sell  143 -> 144 (gate 46) 12-B rows {id, sell value, _}; cap 50. Served
                per character: the bag at the price a sell pays.
         Modify 141 -> 142 (gate 45) 20-B rows {source, result, kit (0 = none),
                fee}; getter 0x00ad3388, list builder 0x00552248, which HIDES a
                row whose kit is not in the bag and greys one whose fee > gil.
         Proven by running the client's own code (sec 4gk addendum 3).
  login  selector-2 world door: body[52] -> R+744 GIL, body[140] bag count,
         body[240+8i] {u32 id, u16 0, u16 qty} (MEASURED, doc_shop_proof.py).

STOCK = the ONLINE catalogue. Categories 0x6932 / 0x6F3x carry SE's "O"
placeholders (OI.., OF.., OB.., OS.., OO.., OA..) and hold Flash Materia, which
Lifestream says an update ADDED to the online shop; Lifestream also says the
shop machines sold WEAPONS and MATERIA. Online weapons are PARTS: 0x6F30 frames
(handgun 00-08, rifle 0B-13, machine gun 14-1C), 0x6F31 barrels. The 0x6430
upgrade KITS ("items necessary for upgrading weapon parts") are stocked too, so
Modify is usable -- whether retail SOLD them is unknown (that category's
placeholders are "QI", quest items). Left out: Broken Handgun / Scarlet Custom
(special), the Gatling Gun ("a stationary firearm"), the SC Frame Kit (no
recipe), tickets and plates. The retail stock LIST, recipes and PRICES do not
survive; prices, fees and recipe ladders here are PLACEHOLDERS / inferred.
"""
import json
import os
import struct
import tempfile

STOCK_REQ, STOCK_ANS = 64, 65
BUY_REQ, BUY_ANS = 66, 67
SELL_REQ, SELL_ANS = 68, 69
RECIPE_REQ, RECIPE_ANS = 141, 142
PRICE_REQ, PRICE_ANS = 143, 144
TXN_REQ, TXN_ANS = 145, 146          # Modify
SHOP_REQS = (STOCK_REQ, BUY_REQ, SELL_REQ, RECIPE_REQ, PRICE_REQ, TXN_REQ)

LIST_COUNT_OFF = 16          # u32, all three lists
LIST_ROWS_OFF = 20
STOCK_ROW, STOCK_MAX = 16, 89   # client cap 128; 24+20+16*89 = 1468 B = one
                                # unfragmented datagram (1472 max UDP payload)
RECIPE_ROW, RECIPE_MAX = 20, 128
PRICE_ROW, PRICE_MAX = 12, 50

ANS_ADD_ID = 12              # 67 / 146: u32 -> ADD
ANS_ADD_QTY = 20             # 67 / 146: u16
ANS_SPEND = 28               # 67 / 146: u32, subtract only
ANS_REM_ID = 16              # 69 / 146: u32 -> REMOVE
ANS_REM_QTY = 22             # 69 / 146: u16
ANS_GAIN = 24                # 69: u32 -> ADDED to gil (0x00bdf570)
ANS_KIT = 32                 # 146: u32, REMOVE x1 if nonzero
ANS_LEN = 48

LOGIN_GIL_OFF = 52           # selector-2 answer -> R+744
LOGIN_BAG_COUNT_OFF = 140    # the sec 4bo count; the client does NOT clamp it
LOGIN_BAG_OFF = 240          # src+196 with src = body[44]
BAG_MAX = 50                 # the `Inventory n/50` cap; R's tally holds 256

GIL_ID = 0x67300000
START_GIL = 20000
GIL_MAX = 0x7FFFFFFF
QTY_MAX = 99
SELL_RATE = 0.5              # placeholder, like the prices


def _parts(cat, rows):
    return [((cat << 16) | idx, price, name) for idx, price, name in rows]


#: (item id, price, name). PLACEHOLDER prices -- override with --shop-stock.
#: Order matters for the probe: the first 50 are sure to fit the 144 list.
DEFAULT_STOCK = tuple(
    _parts(0x6932, [(0x00, 50, "Potion"), (0x01, 300, "Hi-Potion"),
                    (0x02, 1000, "X-Potion"), (0x04, 800, "Phoenix Down"),
                    (0x05, 2500, "Phoenix Pinion")])
    + _parts(0x6F34, [(0x17, 3000, "Fire Materia"), (0x18, 3000, "Blizzard Materia"),
                      (0x19, 3000, "Thunder Materia"), (0x1A, 4000, "Cure Materia"),
                      (0x1B, 5000, "Flash Materia"), (0x1C, 5000, "Bind Materia"),
                      (0x1D, 5000, "Grenade Materia")])
    + _parts(0x6F30, [  # handgun frames
        (0x00, 2000, "One Eighty"), (0x01, 4000, "Three Sixty"),
        (0x02, 7000, "Five Fourty"), (0x03, 10000, "Seven Twenty"),
        (0x04, 15000, "Caballerial"), (0x05, 15000, "Steelfish"),
        (0x06, 15000, "Alley-Oop"), (0x07, 15000, "Elgarial"),
        (0x08, 25000, "Miller Flip"),
        # rifle frames
        (0x0B, 3000, "Tomin"), (0x0C, 5000, "Balmen"), (0x0D, 8000, "Bror"),
        (0x0E, 12000, "Clynel"), (0x0F, 18000, "Caol"), (0x10, 18000, "Tlemill"),
        (0x11, 18000, "Ringbank"), (0x12, 18000, "Ockdhu"), (0x13, 30000, "Farran"),
        # machine gun frames
        (0x14, 3000, "Nelson"), (0x15, 5000, "Stenberg"), (0x16, 8000, "Ullman"),
        (0x17, 12000, "Foresythe"), (0x18, 18000, "Grogono"),
        (0x19, 18000, "Terashima"), (0x1A, 18000, "Smith"), (0x1B, 18000, "Revis"),
        (0x1C, 30000, "Hopcroft")])
    + _parts(0x6F31, [(0x00, 1500, "Vernis"), (0x01, 5000, "Vernis Prime"),
                      (0x02, 12000, "Vernis X"), (0x03, 2000, "Rouge"),
                      (0x04, 6000, "Rouge Prime"), (0x05, 14000, "Rouge X"),
                      (0x06, 2000, "Parfum"), (0x07, 6000, "Parfum Prime"),
                      (0x08, 14000, "Parfum X")])
    # --- past row 48: whether these show a price settles 144's cap of 50
    + _parts(0x6F32, [(0x00, 2000, "Auto Scope"), (0x01, 6000, "Auto Scope Revo"),
                      (0x02, 2500, "Sniper Scope"), (0x03, 4000, "Materia Floater"),
                      (0x04, 8000, "S Auto Scope")])
    + _parts(0x6F33, [(0x00, 2000, "Power Booster"), (0x01, 6000, "Power Booster Revo"),
                      (0x02, 2500, "Auto Reloader"), (0x03, 3000, "Rapidfire Unit"),
                      (0x04, 8000, "Rapidfire Unit Revo"), (0x05, 3000, "Gravity Floater"),
                      (0x06, 4000, "Materia Booster"), (0x07, 9000, "Materia Booster Beta")])
    + _parts(0x6F34, [(0x00, 1500, "Guard Relief"), (0x01, 5000, "Revo Guard Relief"),
                      (0x02, 2000, "Power Cross"), (0x03, 6000, "Power Cross Revo"),
                      (0x04, 1500, "S Adjuster"), (0x05, 5000, "S Adjuster Revo"),
                      (0x06, 1500, "M Adjuster"), (0x07, 5000, "M Adjuster Revo"),
                      (0x08, 1500, "L Adjuster"), (0x09, 5000, "L Adjuster Revo"),
                      (0x0A, 1500, "Recoil Limiter"), (0x0B, 1500, "Silencer"),
                      (0x0C, 5000, "Limit Breaker"), (0x0D, 12000, "Limit Breaker Revo")])
    # Modify kits (SC Frame Kit 0x64300005 left out: no recipe known)
    + _parts(0x6430, [(0x00, 1000, "Power Kit"), (0x01, 1000, "Speed Kit"),
                      (0x02, 1000, "Weight Kit"), (0x03, 2000, "Handgun Kit EX"),
                      (0x04, 5000, "Handgun Kit ULT"), (0x06, 2000, "Rifle Kit EX"),
                      (0x07, 5000, "Rifle Kit ULT"), (0x08, 2000, "Machine Gun Kit EX"),
                      (0x09, 5000, "Machine Gun Kit ULT"), (0x0A, 1500, "N Barrel Kit"),
                      (0x0B, 1500, "L Barrel Kit"), (0x0C, 1500, "S Barrel Kit"),
                      (0x0D, 2500, "Materia Booster Kit"), (0x0E, 2000, "Auto Scope Kit")])
)


def _ladder(cat, idxs, kit):
    return [((cat << 16) | a, (cat << 16) | b, kit) for a, b in zip(idxs, idxs[1:])]


#: Modify recipes (source, result, kit). INFERRED from the item names' tier
#: ladders and the kit names -- SE's table does not survive. Fees are derived
#: in Shop (half the price gap, at least 1000). (source, result) must be
#: unique: request 145 carries nothing else to tell recipes apart.
DEFAULT_RECIPES = tuple(
    _ladder(0x6F31, [0x00, 0x01, 0x02], 0x6430000A)       # Vernis -> Prime -> X
    + _ladder(0x6F31, [0x03, 0x04, 0x05], 0x6430000B)     # Rouge
    + _ladder(0x6F31, [0x06, 0x07, 0x08], 0x6430000C)     # Parfum
    + _ladder(0x6F30, [0x00, 0x01, 0x02, 0x03], 0x64300003)   # handgun frames, Kit EX
    + [(0x6F300003, 0x6F300008, 0x64300004)]              # Seven Twenty -> Miller Flip, ULT
    + _ladder(0x6F30, [0x0B, 0x0C, 0x0D, 0x0E], 0x64300006)   # rifle frames
    + [(0x6F30000E, 0x6F300013, 0x64300007)]              # Clynel -> Farran
    + _ladder(0x6F30, [0x14, 0x15, 0x16, 0x17], 0x64300008)   # machine gun frames
    + [(0x6F300017, 0x6F30001C, 0x64300009)]              # Foresythe -> Hopcroft
    + [(0x6F320000, 0x6F320001, 0x6430000E),              # Auto Scope -> Revo
       (0x6F330000, 0x6F330001, 0x64300000),              # Power Booster -> Revo
       (0x6F330003, 0x6F330004, 0x64300001),              # Rapidfire Unit -> Revo
       (0x6F330006, 0x6F330007, 0x6430000D),              # Materia Booster -> Beta
       (0x6F340000, 0x6F340001, 0x64300002),              # Guard Relief -> Revo
       (0x6F340002, 0x6F340003, 0x64300000),              # Power Cross -> Revo
       (0x6F340004, 0x6F340005, 0x64300002),              # S Adjuster -> Revo
       (0x6F340006, 0x6F340007, 0x64300002),              # M Adjuster -> Revo
       (0x6F340008, 0x6F340009, 0x64300002),              # L Adjuster -> Revo
       (0x6F34000C, 0x6F34000D, 0x64300000)]              # Limit Breaker -> Revo
)


def _int(v):
    return int(v, 0) if isinstance(v, str) else int(v)


def load_stock(path):
    """(stock [(id, price, name)], start_gil or None) from a JSON file, or the
    defaults. File shape: {"start_gil": N, "stock": [{"id": "0x69320000",
    "price": 50, "name": "Potion"}, ...]}."""
    if not path:
        return list(DEFAULT_STOCK), None
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    stock = [(_int(r["id"]) & 0xFFFFFFFF, max(0, _int(r["price"])),
              str(r.get("name", ""))) for r in cfg.get("stock", [])]
    sg = cfg.get("start_gil")
    return stock, (None if sg is None else max(0, _int(sg)))


def list_body(selector, rows, row_len, subchannel=7):
    """A lobby list answer: u32 count at body[16], rows from body[20]."""
    body = bytearray(LIST_ROWS_OFF + row_len * len(rows))
    body[0] = subchannel & 0xFF
    body[1] = selector & 0xFF
    struct.pack_into("<I", body, LIST_COUNT_OFF, len(rows))
    for i, r in enumerate(rows):
        off = LIST_ROWS_OFF + i * row_len
        body[off:off + row_len] = bytes(r[:row_len]).ljust(row_len, b"\x00")
    return bytes(body)


def stock_body(stock, subchannel=7):
    rows = [struct.pack("<IIII", iid, price, price, 0)
            for iid, price, _ in stock[:STOCK_MAX]]
    return list_body(STOCK_ANS, rows, STOCK_ROW, subchannel)


def price_body(stock, subchannel=7):
    # Stock order, NOT id order: the lobby's lookup 0x00ad3328 walks linearly,
    # and the handler keeps the first 50 -- so the order says which items drop.
    rows = [struct.pack("<III", iid, price, 0) for iid, price, _ in stock[:STOCK_MAX]]
    return list_body(PRICE_ANS, rows, PRICE_ROW, subchannel)


def recipe_body(recipes=(), subchannel=7):
    """142: 20-B rows {source, result, kit (0 = none), fee, _}."""
    rows = [struct.pack("<IIIII", src, res, kit, fee, 0)
            for src, res, kit, fee in list(recipes)[:RECIPE_MAX]]
    return list_body(RECIPE_ANS, rows, RECIPE_ROW, subchannel)


def parse_modify(req_body):
    """Request 145: body[12] shop, body[16] source id, body[20] result id."""
    if req_body is None or len(req_body) < 24:
        return None
    shop, src, res = struct.unpack_from("<III", req_body, 12)
    return {"shop": shop, "src": src, "res": res}


def _answer(selector, subchannel, fields):
    body = bytearray(ANS_LEN)
    body[0] = subchannel & 0xFF
    body[1] = selector & 0xFF
    for fmt, off, val in fields:
        struct.pack_into(fmt, body, off, val)
    return bytes(body)


def buy_body(add=(0, 0), spend=0, subchannel=7):
    """The 67 answer. All zero = a well-formed refusal (nothing added)."""
    return _answer(BUY_ANS, subchannel, (
        ("<I", ANS_ADD_ID, add[0] & 0xFFFFFFFF), ("<H", ANS_ADD_QTY, add[1] & 0xFFFF),
        ("<I", ANS_SPEND, max(0, spend) & 0xFFFFFFFF)))


def sell_body(remove=(0, 0), gain=0, subchannel=7):
    """The 69 answer: REMOVE, then ADD `gain` gil."""
    return _answer(SELL_ANS, subchannel, (
        ("<I", ANS_REM_ID, remove[0] & 0xFFFFFFFF), ("<H", ANS_REM_QTY, remove[1] & 0xFFFF),
        ("<I", ANS_GAIN, max(0, gain) & 0xFFFFFFFF)))


def txn_body(add=(0, 0), remove=(0, 0), spend=0, kit=0, subchannel=7):
    """The 146 (Modify) answer. All zero = a well-formed no-op."""
    return _answer(TXN_ANS, subchannel, (
        ("<I", ANS_ADD_ID, add[0] & 0xFFFFFFFF), ("<H", ANS_ADD_QTY, add[1] & 0xFFFF),
        ("<I", ANS_REM_ID, remove[0] & 0xFFFFFFFF), ("<H", ANS_REM_QTY, remove[1] & 0xFFFF),
        ("<I", ANS_SPEND, max(0, spend) & 0xFFFFFFFF), ("<I", ANS_KIT, kit & 0xFFFFFFFF)))


def parse_entry(req_body):
    """Requests 66 / 68: body[12] u32 shop, body[16] u32 item, body[20] qty.
    body[20] is a u32 on every live 66; for 68 it may be the bag entry's own
    {u16, u16 qty} word, so fall back to its high half."""
    if req_body is None or len(req_body) < 24:
        return None
    shop, iid, q = struct.unpack_from("<III", req_body, 12)
    qty = q if 0 < q <= 0xFFFF else (q >> 16) & 0xFFFF
    return {"shop": shop, "iid": iid, "qty": min(max(qty, 1), QTY_MAX)}


def apply_login(body, gil=None, bag=None):
    """Write gil and the bag into a selector-2 answer body (a bytearray)."""
    if gil is not None:
        if len(body) < LOGIN_GIL_OFF + 4:
            body += bytes(LOGIN_GIL_OFF + 4 - len(body))
        struct.pack_into("<I", body, LOGIN_GIL_OFF, min(max(0, gil), GIL_MAX))
    if bag is not None:
        bag = list(bag)[:BAG_MAX]
        need = max(LOGIN_BAG_COUNT_OFF + 4, LOGIN_BAG_OFF + 8 * len(bag))
        if len(body) < need:
            body += bytes(need - len(body))
        struct.pack_into("<I", body, LOGIN_BAG_COUNT_OFF, len(bag))
        for i, (iid, qty) in enumerate(bag):
            struct.pack_into("<IHH", body, LOGIN_BAG_OFF + 8 * i,
                             iid & 0xFFFFFFFF, 0, min(qty, 0xFFFF))
    return body


# sec 4go (2026-09-13): AMMUNITION IS AN INVENTORY ITEM, and an empty bag is
# why the online gun never fired. The arena actor's item inventory is filled
# from the world-door bag (getMyItemData 0x00beba60 -> add 0x004a95d0), and
# the magazine routine 0x004a5780 loads each weapon's rounds (+148) from the
# inventory's 0x6230000N stack: min(magazine, bullets held). Zero bullets =
# every magazine stays 0. The handgun itself is there (frame/barrel kinds
# default 1/1 at [[0x005dd968]+128/129]). Only Death Penalty self-issues
# (0x004a6768 adds 300 of 0x62300003). Stackable, def+14 = 500 per stack.
AMMO_HANDGUN, AMMO_RIFLE, AMMO_MG = 0x62300000, 0x62300001, 0x62300002
#: Lifestream's "standard mission supplies" (read off the shipped string tables).
STANDARD_AMMO = ((AMMO_HANDGUN, 36), (AMMO_RIFLE, 18), (AMMO_MG, 60))
AMMO_STACK_MAX = 500


def parse_issue(spec):
    """'off'/'' -> (), 'standard' -> STANDARD_AMMO, else 'ID:QTY,ID:QTY'."""
    spec = (spec or "").strip().lower()
    if spec in ("", "off", "none", "0"):
        return ()
    if spec == "standard":
        return STANDARD_AMMO
    out = []
    for part in spec.split(","):
        iid, _, q = part.strip().partition(":")
        out.append((int(iid, 0) & 0xFFFFFFFF,
                    min(max(int(q or "1", 0), 1), AMMO_STACK_MAX)))
    return tuple(out)


def issue_items(bag, issued):
    """`bag` with every issued (id, qty) topped UP to at least qty -- never
    lowered, never persisted (issued per login, like mission supplies).
    Id-sorted, so 0x6230 bullets (the lowest category) survive BAG_MAX."""
    have = dict(bag or ())
    for iid, q in issued:
        have[iid] = max(have.get(iid, 0), q)
    return sorted((i, q) for i, q in have.items() if q > 0)[:BAG_MAX]


class Shop:
    """Stock + per-character wallets. Same deliberately-dumb JSON store shape as
    doc_charastore: synchronous, fsync'd, rewritten whole on every change."""

    def __init__(self, path, stock_path="", start_gil=None):
        self.path = path
        self.stock, file_gil = load_stock(stock_path)
        self.prices = {iid: price for iid, price, _ in self.stock}
        self.names = {iid: name for iid, _, name in self.stock}
        # (source, result) -> (kit, fee); only recipes whose ends are priced
        self.recipes = {}
        for src, res, kit in DEFAULT_RECIPES:
            if src in self.prices and res in self.prices:
                fee = max(1000, (self.prices[res] - self.prices[src]) // 2)
                self.recipes[(src, res)] = (kit, fee)
        self.start_gil = (start_gil if start_gil is not None
                          else file_gil if file_gil is not None else START_GIL)
        self.data = {}
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {}

    def save(self):
        d = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".shop-", suffix=".tmp")
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

    #: DESIGN DECISION 2026-09-13: "players should absolutely have a starter set of
    #: both guns at creation for now". A gun with no frame/barrel holds 0
    #: rounds and cannot fire (measured offline against the client's gun code), and the
    #: bag bullets cannot fill it. Handgun One Eighty + rifle Tomin, a Vernis
    #: barrel each (the PC's Tomin + Vernis measured 4/4 rounds). Granted ONCE
    #: per character (the "kit" mark), so selling it is not free gil; a wallet
    #: made before the kit existed gets it at its next login.
    STARTER_KIT = ((0x6F300000, 1), (0x6F30000B, 1), (0x6F310000, 2))
    KIT_MARK = "kit"

    def wallet(self, key):
        w = self.data.get(key)
        if w is None:
            w = self.data[key] = {"gil": self.start_gil, "bag": {}}
            self.save()
        if not w.get(self.KIT_MARK):
            bag = w["bag"]
            for iid, q in self.STARTER_KIT:
                k = "0x%08x" % iid
                bag[k] = min(QTY_MAX, bag.get(k, 0) + q)
            w[self.KIT_MARK] = 1
            self.save()
        return w

    def bag(self, key):
        """[(id, qty)] for qty > 0, capped at BAG_MAX, id-sorted."""
        out = [(int(k, 16), q) for k, q in self.wallet(key)["bag"].items() if q > 0]
        return sorted(out)[:BAG_MAX]

    def login_fields(self, key):
        return self.wallet(key)["gil"], self.bag(key)

    def name(self, iid):
        return self.names.get(iid) or "0x%08x" % iid

    def buy(self, key, iid, qty):
        """(add, spend, note). A refusal is ((0, 0), 0, why)."""
        w = self.wallet(key)
        bag = w["bag"]
        k = "0x%08x" % iid
        if iid not in self.prices:
            return (0, 0), 0, "REFUSED buy 0x%08x: not stocked" % iid
        cost = self.prices[iid] * qty
        if w["gil"] < cost:
            return (0, 0), 0, ("REFUSED buy %s x%d: %d gil < %d (SE 43016 not wired)"
                               % (self.name(iid), qty, w["gil"], cost))
        if k not in bag and len([v for v in bag.values() if v > 0]) >= BAG_MAX:
            return (0, 0), 0, "REFUSED buy %s: bag full (%d)" % (self.name(iid), BAG_MAX)
        w["gil"] -= cost
        bag[k] = bag.get(k, 0) + qty
        self.save()
        return (iid, qty), cost, ("BUY %s x%d for %d -> %d gil"
                                  % (self.name(iid), qty, cost, w["gil"]))

    def sell(self, key, iid, qty):
        """(remove, gain, note). Only what the SERVER bag holds can be sold."""
        w = self.wallet(key)
        bag = w["bag"]
        k = "0x%08x" % iid
        have = bag.get(k, 0)
        if have <= 0:
            return (0, 0), 0, ("REFUSED sell 0x%08x: not in the server's bag "
                               "(client-only item?)" % iid)
        n = min(qty, have)
        gain = int(self.prices.get(iid, 0) * SELL_RATE) * n
        bag[k] = have - n
        if bag[k] <= 0:
            del bag[k]
        w["gil"] = min(w["gil"] + gain, GIL_MAX)
        self.save()
        return (iid, n), gain, ("SELL %s x%d for %d -> %d gil"
                                % (self.name(iid), n, gain, w["gil"]))

    def trade(self, key_a, offer_a, key_b, offer_b):
        """Swap two (gil, [(id, qty)]) offers between wallets, all or nothing.
        Only what each SERVER bag holds can change hands. (ok, note)."""
        if key_a == key_b:
            return False, "REFUSED trade: both sides are wallet %s" % key_a
        wa, wb = self.wallet(key_a), self.wallet(key_b)
        for w, (gil, items), who in ((wa, offer_a, key_a), (wb, offer_b, key_b)):
            if w["gil"] < gil:
                return False, "REFUSED trade: %s offers %d gil, has %d" % (who, gil, w["gil"])
            need = {}
            for iid, q in items:
                need[iid] = need.get(iid, 0) + q
            for iid, q in need.items():
                have = w["bag"].get("0x%08x" % iid, 0)
                if have < q:
                    return False, ("REFUSED trade: %s offers %s x%d, server bag has %d"
                                   % (who, self.name(iid), q, have))

        def move(src, dst, gil, items):
            src["gil"] -= gil
            dst["gil"] = min(dst["gil"] + gil, GIL_MAX)
            for iid, q in items:
                k = "0x%08x" % iid
                src["bag"][k] -= q
                if src["bag"][k] <= 0:
                    del src["bag"][k]
                dst["bag"][k] = dst["bag"].get(k, 0) + q
        move(wa, wb, *offer_a)
        move(wb, wa, *offer_b)
        self.save()
        return True, "TRADE %s gave %s; %s gave %s" % (key_a, offer_a, key_b, offer_b)

    def sell_value(self, iid):
        return int(self.prices.get(iid, 0) * SELL_RATE)

    def sell_rows(self, key):
        """The Sell tab's 144 list: this character's bag at sell value."""
        return [(iid, self.sell_value(iid), self.name(iid))
                for iid, _ in self.bag(key) if self.sell_value(iid) > 0][:PRICE_MAX]

    def recipe_rows(self):
        return [(s, r, k, f) for (s, r), (k, f) in self.recipes.items()]

    def modify(self, key, src, res):
        """(add, remove, fee, kit, note). A refusal is all zeros + why."""
        w = self.wallet(key)
        bag = w["bag"]
        nope = ((0, 0), (0, 0), 0, 0)
        rc = self.recipes.get((src, res))
        if rc is None:
            return nope + ("REFUSED modify 0x%08x -> 0x%08x: no such recipe" % (src, res),)
        kit, fee = rc
        ks, kk = "0x%08x" % src, "0x%08x" % kit
        if bag.get(ks, 0) <= 0:
            return nope + ("REFUSED modify %s: not in the server's bag" % self.name(src),)
        if kit and bag.get(kk, 0) <= 0:
            return nope + ("REFUSED modify %s: needs %s" % (self.name(src), self.name(kit)),)
        if w["gil"] < fee:
            return nope + ("REFUSED modify %s: %d gil < fee %d" % (self.name(src), w["gil"], fee),)
        for k in (ks, kk) if kit else (ks,):
            bag[k] -= 1
            if bag[k] <= 0:
                del bag[k]
        kr = "0x%08x" % res
        bag[kr] = bag.get(kr, 0) + 1
        w["gil"] -= fee
        self.save()
        return ((res, 1), (src, 1), fee, kit,
                "MODIFY %s -> %s (kit %s, fee %d) -> %d gil"
                % (self.name(src), self.name(res), self.name(kit) if kit else "none",
                   fee, w["gil"]))

    def body_for(self, req_sel, req_body, key, subchannel=7):
        """(answer body, note) for one shop request, or (None, why)."""
        raw = req_body[12:28].hex(" ") if req_body else ""
        if req_sel == STOCK_REQ:
            return stock_body(self.stock, subchannel), "%d stocked" % len(
                self.stock[:STOCK_MAX])
        if req_sel == PRICE_REQ:
            rows = self.sell_rows(key)
            return price_body(rows, subchannel), "Sell tab: %d bag item(s) at sell value" % len(rows)
        if req_sel == RECIPE_REQ:
            rows = self.recipe_rows()
            return recipe_body(rows, subchannel), "Modify tab: %d recipe(s)" % len(rows)
        if req_sel in (BUY_REQ, SELL_REQ):
            e = parse_entry(req_body)
            if e is None:
                return None, "request %d body unreadable" % req_sel
            if req_sel == BUY_REQ:
                add, spend, note = self.buy(key, e["iid"], e["qty"])
                return buy_body(add, spend, subchannel), "%s  [req %s]" % (note, raw)
            rem, gain, note = self.sell(key, e["iid"], e["qty"])
            return sell_body(rem, gain, subchannel), "%s  [req %s]" % (note, raw)
        if req_sel == TXN_REQ:
            m = parse_modify(req_body)
            if m is None:
                return None, "request 145 body unreadable"
            add, rem, fee, kit, note = self.modify(key, m["src"], m["res"])
            return (txn_body(add, rem, fee, kit, subchannel=subchannel),
                    "%s  [req %s]" % (note, raw))
        return None, "not a shop request"


if __name__ == "__main__":
    import sys
    p = os.path.join(tempfile.gettempdir(), "doc_shop_selftest.json")
    try:
        os.remove(p)
    except OSError:
        pass
    ids = [i for i, _, _ in DEFAULT_STOCK]
    assert len(ids) == len(set(ids)) == STOCK_MAX == 89, len(ids)
    pairs = [(s, r) for s, r, _ in DEFAULT_RECIPES]
    assert len(pairs) == len(set(pairs)), "recipe (source, result) must be unique"
    shop = Shop(p, start_gil=10000)
    # the STARTER KIT (design decision 09-13): both guns' parts, granted ONCE per character
    kk = "member:9/0x00000001"
    assert shop.login_fields(kk) == (10000, [(0x6F300000, 1), (0x6F30000B, 1),
                                             (0x6F310000, 2)]), shop.login_fields(kk)
    shop.wallet(kk)["bag"].clear()                   # sold / fitted away
    shop.save()
    assert Shop(p).login_fields(kk) == (10000, []), "kit granted once, never again"
    # the rest runs on a character that already received its kit
    k = "member:3/0x0002a664"
    shop.data[k] = {"gil": 10000, "bag": {}, Shop.KIT_MARK: 1}
    shop.save()
    assert shop.login_fields(k) == (10000, [])
    # the LIVE 09:11:51 request 66: Auto Scope x1 at shop 3
    live66 = bytes.fromhex("074200000100ffffffffffff030000000000326f0100000000000000")
    assert parse_entry(live66) == {"shop": 3, "iid": 0x6F320000, "qty": 1}
    body, note = shop.body_for(BUY_REQ, live66, k)
    assert body[1] == BUY_ANS, note
    assert struct.unpack_from("<I", body, ANS_ADD_ID)[0] == 0x6F320000
    assert struct.unpack_from("<H", body, ANS_ADD_QTY)[0] == 1
    assert struct.unpack_from("<I", body, ANS_SPEND)[0] == 2000
    assert Shop(p).login_fields(k) == (8000, [(0x6F320000, 1)]), "persisted"
    # refused: too expensive -> all-zero 67
    rq = bytearray(live66)
    struct.pack_into("<I", rq, 16, 0x6F300013)      # Farran, 30000
    body, note = shop.body_for(BUY_REQ, bytes(rq), k)
    assert body[12:36] == bytes(24) and "REFUSED" in note, note
    # sell the Auto Scope back: 69 removes it and ADDS half the price
    body, note = shop.body_for(SELL_REQ, live66, k)
    assert body[1] == SELL_ANS, note
    assert struct.unpack_from("<I", body, ANS_REM_ID)[0] == 0x6F320000
    assert struct.unpack_from("<H", body, ANS_REM_QTY)[0] == 1
    assert struct.unpack_from("<I", body, ANS_GAIN)[0] == 1000
    assert shop.login_fields(k) == (9000, [])
    # selling what the server never gave is refused
    body, note = shop.body_for(SELL_REQ, live66, k)
    assert body[12:36] == bytes(24) and "REFUSED" in note, note
    # MODIFY: Vernis + N Barrel Kit -> Vernis Prime, fee = (5000-1500)//2
    VER, VERP, NKIT = 0x6F310000, 0x6F310001, 0x6430000A
    rq145 = bytearray(24)
    struct.pack_into("<III", rq145, 12, 3, VER, VERP)
    assert parse_modify(bytes(rq145)) == {"shop": 3, "src": VER, "res": VERP}
    body, note = shop.body_for(TXN_REQ, bytes(rq145), k)       # nothing owned yet
    assert body[1] == TXN_ANS and body[12:36] == bytes(24) and "REFUSED" in note, note
    shop.wallet(k)["bag"].update({"0x%08x" % VER: 1, "0x%08x" % NKIT: 1})
    body, note = shop.body_for(TXN_REQ, bytes(rq145), k)
    assert struct.unpack_from("<IIHH", body, 12) == (VERP, VER, 1, 1), note
    assert struct.unpack_from("<I", body, ANS_SPEND)[0] == 1750
    assert struct.unpack_from("<I", body, ANS_KIT)[0] == NKIT
    assert Shop(p).login_fields(k) == (9000 - 1750, [(VERP, 1)]), "persisted, kit used"
    # the Modify tab: 142 rows {source, result, kit, fee}
    b = shop.body_for(RECIPE_REQ, None, k)[0]
    n = struct.unpack_from("<I", b, LIST_COUNT_OFF)[0]
    assert n == len(shop.recipes) >= 25 and len(b) == LIST_ROWS_OFF + RECIPE_ROW * n
    assert struct.unpack_from("<IIII", b, LIST_ROWS_OFF) == (VER, VERP, NKIT, 1750)
    # the Sell tab: 144 = this bag at SELL value (Vernis Prime 5000 -> 2500)
    b = shop.body_for(PRICE_REQ, None, k)[0]
    assert struct.unpack_from("<I", b, LIST_COUNT_OFF)[0] == 1
    assert struct.unpack_from("<II", b, LIST_ROWS_OFF) == (VERP, 2500)
    shop.wallet(k)["gil"] = 9000
    shop.wallet(k)["bag"].clear()
    shop.save()
    # the Buy tab
    b = stock_body(shop.stock)
    assert struct.unpack_from("<I", b, LIST_COUNT_OFF)[0] == 89 and 24 + len(b) < 1472
    # login fields
    lb = apply_login(bytearray(176), 550, [(0x69320000, 3)])
    assert struct.unpack_from("<I", lb, LOGIN_GIL_OFF)[0] == 550
    assert struct.unpack_from("<I", lb, LOGIN_BAG_COUNT_OFF)[0] == 1
    assert struct.unpack_from("<IHH", lb, LOGIN_BAG_OFF) == (0x69320000, 0, 3)
    # sec 4go: issued ammo tops the bag up, bullets first, never persisted
    assert issue_items([(0x69320000, 3)], parse_issue("standard")) == [
        (AMMO_HANDGUN, 36), (AMMO_RIFLE, 18), (AMMO_MG, 60), (0x69320000, 3)]
    assert issue_items([(AMMO_HANDGUN, 400)], STANDARD_AMMO)[0] == (AMMO_HANDGUN, 400)
    assert parse_issue("off") == () and parse_issue("0x62300002:9999") == ((AMMO_MG, 500),)
    assert shop.login_fields(k) == (9000, []), "issuing never touches the wallet"
    os.remove(p)
    print("doc_shop self-test PASS")
    sys.exit(0)
