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

STOCK, PRICES, TUNING, SELL RULE (2026-09-26, replaces the 09-13 placeholders)
------------------------------------------------------------------------------
SOURCED from the 2006 retail player guides:
  * source: 2006 player guide (EX-POTION), online shop price list and the
    tune trees with their fees.
  * source: player guide (FFCheats), final 2007 revision, the same prices
    plus every item's sell price.
  Both agree: frames 200, barrels / options 150, scope / accessories /
  materia 100, suits 300; a tune costs 100 (frames) or 50 (barrels, scope,
  options) at the shop machine and needs NO kit; sell = 80 % of what the item
  cost in total (One-Eighty 200 -> 160, a tuned frame 200 + 100 -> 240,
  Middle Barrel III 150 + 50 + 50 -> 200). Ammunition and consumables were
  NOT sold (mission supplies / field pickups only) -- none are stocked.
  2026-09-26: those sell prices are the 2007 revision. LAUNCH (January) sold
  lower and per kind: LAUNCH_SELL, from a January 2006 player blog's shop
  list; the same blog gives the launch starting gil and kit.

MEASURED on our build: every id below is NAMED in the 20060124_3 client's own
item table (kelstr.bin via an offline run of the client's own code (doc_kelitem); the names are
byte-identical to the 20051209_6 disc's), and every item the guides list has
an id there. An older FFCheats revision (mid-2006: frames 5000, upgrade kits, and
beta-era part ladders) names items our build only
has as SE placeholders (OF1, OF12, OS0; the 0x6430 kits are "chi 1..15") --
that is the beta economy the 09-13 stock was built from; it is gone.

THE DISC's price table is NOT the online one: the 29,184-B "shop data" buffer
(0x00551390) is filled from data/zone/zNNN/shp.bin (header "KelShop1.0
2005/11/21", each shop decrypted with key 7 + zlib by 0x003bbad0) -- the STORY
shops. Its 474-row sorted {id -> u32} table is the story SELL value (Potion
100 buy -> 70, Cerberus 1000 -> 700, Cerberus II 1000 + 2000 tune -> 2100:
70 % of buy + tune fees) and every online id (0x6F3x, 0x6331) carries the
default 10. So the disc confirms the MODEL (sell = a fixed share of buy +
tune fees) but has no online prices; the guides give those. Flash Materia
(0x6F34001B) stays out: per the Lifestream fan archive, a later update added it.
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
#: source: January 2006 player blog, launch-day notes: a new character has
#: 3000 gil, already holds every shop item except armor, and armor costs 300
#: each. It was 1000 (OURS, 09-26) and 20000 before that. Only a NEW
#: wallet starts with it: existing wallets keep their gil.
START_GIL = 3000
GIL_MAX = 0x7FFFFFFF
QTY_MAX = 99
#: The FALLBACK sell rule, for items outside LAUNCH_SELL (a --shop-stock file
#: can stock other categories): source: player guide (FFCheats), 2007
#: revision: sell at 80 % of the total paid. That is the 2007 revision, not launch.
SELL_RATE = 0.8
#: SOURCED sell prices outside the 80 % rule (FFCheats, 2007): the Broken
#: Handgun / Broken Barrel (Soar's quest items, never on sale) sell for 1.
SELL_OVERRIDES = {0x6F300009: 1, 0x6F310009: 1}

# The ids are our build's own (doc_kelitem.py on the 20060124_3 kelstr.bin);
# the English names are the guides' / Lifestream's renderings.
ONE_EIGHTY, TOMINTOUL, NELSON = 0x6F300000, 0x6F30000B, 0x6F300014
MIDDLE_BARREL, LONG_BARREL, SHORT_BARREL = 0x6F310000, 0x6F310003, 0x6F310006
SNIPE_SCOPE = 0x6F320002
POWER_BOOSTER, RAPID_FIRE = 0x6F330000, 0x6F330003
FLASH_MATERIA = 0x6F34001B


def _parts(cat, rows):
    return [((cat << 16) | idx, price, name) for idx, price, name in rows]


#: (item id, price, name) -- the Buy tab. source: 2006 player guides
#: (EX-POTION, FFCheats), shop price lists; they agree on every price.
#: Override with --shop-stock.
DEFAULT_STOCK = tuple(
    _parts(0x6F30, [(0x00, 200, "One-Eighty"),            # handgun frame
                    (0x0B, 200, "Tomintoul"),             # rifle frame
                    (0x14, 200, "Nelson")])               # machine gun frame
    + _parts(0x6F31, [(0x00, 150, "Middle Barrel"), (0x03, 150, "Long Barrel"),
                      (0x06, 150, "Short Barrel")])
    + _parts(0x6F32, [(0x02, 100, "Snipe Scope")])
    + _parts(0x6F33, [(0x00, 150, "Power Booster"), (0x02, 150, "Auto Reloader"),
                      (0x03, 150, "Rapid Fire"), (0x05, 150, "Anti-Gravity Floater")])
    + _parts(0x6F34, [(0x04, 100, "Near Adjuster"), (0x06, 100, "Middle Adjuster"),
                      (0x08, 100, "Far Adjuster"), (0x0A, 100, "Recoil Limiter"),
                      (0x0B, 100, "Silencer"), (0x0E, 100, "Quick Turn"),
                      (0x0F, 100, "Auto Shot"),
                      (0x17, 100, "Fire Materia"), (0x18, 100, "Blizzard Materia"),
                      (0x19, 100, "Thunder Materia"), (0x1A, 100, "Cure Materia")])
    # 2026-09-24: no Flash Materia (0x6F34001B) -- a later update added it to
    # the shop (Lifestream fan archive); our client is the Jan 24 lobby
    + _parts(0x6331, [(0x00, 300, "Soldier Suit"), (0x14, 300, "Snipe Suit"),
                      (0x28, 300, "Speed Suit"), (0x3C, 300, "Magic Suit"),
                      (0x50, 300, "Toughness Suit")])
)


#: source: January 2006 player blog, shop list: the launch SELL prices,
#: buy/sell per item: every
#: frame 200/100, every barrel and option 150/120, the Snipe Scope and every
#: accessory / materia 100/80, every suit 300/250. Not one flat share (50 %,
#: 80 %, 80 %, 83 %), so it is a per-item table. The 80 % rule above is the
#: 2007 revision (frames 160, suits 240).
LAUNCH_SELL_BY_CAT = {0x6F30: 100, 0x6F31: 120, 0x6F32: 80, 0x6F33: 120,
                      0x6F34: 80, 0x6331: 250}
LAUNCH_SELL = {iid: LAUNCH_SELL_BY_CAT[iid >> 16] for iid, _p, _n in DEFAULT_STOCK}
#: A TUNED item (a Modify result) sells for its BASE part's launch price: no
#: January source prices a tuned item or says the tune fee comes back (the
#: January tune list gives fees only; adding tune fees is the 2007 FFCheats rule).
#: OURS, flagged.

#: source: January 2006 player blog (above): every character starts holding every item the launch
#: shop sells except armor (suits): the three frames, three barrels, the
#: Snipe Scope, the four options and the eleven accessories / materia, one
#: each (the count is not given; one each is OURS).
STARTER_KIT = tuple((iid, 1) for iid, _p, _n in DEFAULT_STOCK
                    if iid >> 16 != 0x6331)
#: the kit every wallet got until 2026-09-26 (handgun + rifle frame + two
#: Middle Barrels, the "kit" mark)
OLD_STARTER_KIT = ((0x6F300000, 1), (0x6F30000B, 1), (0x6F310000, 2))
#: = doc_gear.MASK_RULE_MARK: set on every wallet made from 2026-09-26 on, so
#: the character EARNS its Soldier Mask (Drone 2nd exam); an older wallet
#: keeps the mask it was issued (doc_gear.settle_soldier_mask)
SOLDIER_MASK_RULE_MARK = "smask"


def _tunes(src, fee, results):
    return [(src, res, 0, fee, name) for res, name in results]


def _chain(ids, fee, names):
    return [(a, b, 0, fee, n) for a, b, n in zip(ids, ids[1:], names)]


#: Modify = the guides' TUNE trees: (source, result, kit, fee, result name).
#: source: 2006 player guides (EX-POTION tune tables, FFCheats item list,
#: which names each result's source part). Retail tuning needs no
#: kit (kit 0 = the 142 row's "none"); the 0x6430 kit ids are unnamed SE
#: placeholders in our build. (source, result) must be unique: request 145
#: carries nothing else to tell recipes apart.
DEFAULT_RECIPES = tuple(
    _tunes(ONE_EIGHTY, 100, [(0x6F300003, "Three-Sixty"), (0x6F300004, "Cavalerial"),
                             (0x6F300005, "Steelfish"), (0x6F300006, "Alley-Oop"),
                             (0x6F30000A, "Scarlet Custom"),
                             (0x6F30001D, "Auto-lock Handgun")])
    + _tunes(TOMINTOUL, 100, [(0x6F30000E, "Clynelish"), (0x6F30000F, "Caol Ila"),
                              (0x6F300010, "Littlemill"), (0x6F300011, "Springbank")])
    + _tunes(NELSON, 100, [(0x6F300017, "Forsyth"), (0x6F300018, "Grogono"),
                           (0x6F300019, "Terashima"), (0x6F30001A, "Smith"),
                           (0x6F30001E, "Auto-lock Machinegun")])
    + _chain([MIDDLE_BARREL, 0x6F310001, 0x6F310002], 50,
             ["Middle Barrel II", "Middle Barrel III"])
    + _chain([LONG_BARREL, 0x6F310004, 0x6F310005], 50,
             ["Long Barrel II", "Long Barrel III"])
    + _chain([SHORT_BARREL, 0x6F310007, 0x6F310008], 50,
             ["Short Barrel II", "Short Barrel III"])
    + _tunes(SNIPE_SCOPE, 50, [(0x6F320005, "Snipe Scope +"),
                               (0x6F320006, "Snipe Scope -")])
    + _tunes(POWER_BOOSTER, 50, [(0x6F330001, "Revo Power Booster")])
    + _tunes(RAPID_FIRE, 50, [(0x6F330004, "Revo Rapid Fire")])
)

#: names for items that are neither stocked nor a tune result (log lines;
#: the Broken Handgun / Barrel keep their hex ids -- doc_npcquest_e2e reads them)
EXTRA_NAMES = {0x67300001: "Chocobo Coin"}


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
#: the standard mission supplies (read off the shipped string tables).
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


def fired_counts(body):
    """{bullet item id: rounds} from a request-44 body (2026-09-26).

    The client's per-battle shot tally [chan+1000..1063] -- 8 x {u32 key, u32
    count} from body[12], incremented only by the shot sender 0x00be9500 and
    zeroed by the kind-2 spawn arm (0x00bc2800 -> 0x00bc29e0), so one 44 =
    one battle. Keys seen live (09-24): 0x3000 x4, 0x3001 x6 -- read as
    the bullet category's low byte + index, i.e. 0x3000 = 0x62300000 (handgun)
    and 0x3001 = rifle (INFERRED from that capture, not from the client)."""
    out = {}
    if body is None:
        return out
    for i in range(8):
        off = 12 + 8 * i
        if off + 8 > len(body):
            break
        key, n = struct.unpack_from("<II", body, off)
        if key >> 8 == 0x30 and n:
            iid = 0x62300000 | (key & 0xFF)
            out[iid] = out.get(iid, 0) + n
    return out


def supply_grant(held, want):
    """The (item, qty) pairs that bring `held` ({item: qty}) up to `want` --
    never lowers, never above a stack (AMMO_STACK_MAX; Potion carries 4)."""
    out = []
    for iid, q in want:
        q = min(q, AMMO_STACK_MAX)
        if held.get(iid, 0) < q:
            out.append((iid, q - held.get(iid, 0)))
    return out


# 2026-09-26: BETA-ERA PLACEHOLDERS. The old placeholder shop (and its kit
# recipes) sold ids that our build's own item table names only by SE's
# placeholder codes (kelstr item index: OF7, OS0, OA12, OI1, "chi"1 ...) -- the
# Dec-2005 beta's parts, not retail items. Each is converted once per wallet:
# to the retail item of the same kind where one exists (a frame to its gun
# type's base frame, a scope to the Snipe Scope, an adjuster Revo to its
# adjuster, Hi-/X-Potion to Potion, Phoenix Pinion to Phoenix Down), else to
# gil at the retail sell rate of its kind. The pairings are OURS. Real items
# the shop does not sell (Potion, Phoenix Down, the tuned frames) are kept.
_POTION, _PHOENIX_DOWN = 0x69320000, 0x69320004
_BASE_FRAME = {"hg": 0x6F300000, "rf": 0x6F30000B, "mg": 0x6F300014}


def _frame_kind(idx):
    return "hg" if idx <= 0x0A or idx == 0x1D else "rf" if idx <= 0x13 else "mg"


#: placeholder id -> retail id (from the client's item table: every id below
#: is named by a placeholder code in 20060124_3's kelstr)
BETA_CONVERT = dict(
    [((0x6F30 << 16) | i, _BASE_FRAME[_frame_kind(i)])
     # (0x09 is NOT one: the Broken Handgun, a real quest reward)
     for i in (0x01, 0x02, 0x07, 0x08, 0x0C, 0x0D, 0x12, 0x13, 0x15,
               0x16, 0x1B, 0x1C)]
    + [(0x6F320000, 0x6F320002), (0x6F320001, 0x6F320002),
       (0x6F320003, 0x6F320002), (0x6F320004, 0x6F320002),
       (0x6F330006, 0x6F330000), (0x6F330007, 0x6F330000),
       (0x6F340005, 0x6F340004), (0x6F340007, 0x6F340006),
       (0x6F340009, 0x6F340008),
       (0x69320001, _POTION), (0x69320002, _POTION),
       (0x69320005, _PHOENIX_DOWN)])
#: placeholder id -> gil per unit (no retail counterpart): 80 = the sell value
#: of a 100-gil accessory / materia (SELL_RATE)
BETA_REFUND = dict(
    [((0x6430 << 16) | i, 80) for i in range(0x00, 0x10)]           # kits
    + [(0x6F340000, 80), (0x6F340001, 80), (0x6F340002, 80),
       (0x6F340003, 80), (0x6F34000C, 80), (0x6F34000D, 80),
       (0x6F34001C, 80), (0x6F34001D, 80)])                        # OA*


def beta_convert(bag):
    """(new bag, gil refund, notes) for a wallet bag {"0x%08x": qty}."""
    out, refund, notes = {}, 0, []
    for k, q in bag.items():
        iid = int(k, 16)
        if q <= 0:
            continue
        if iid in BETA_CONVERT:
            t = "0x%08x" % BETA_CONVERT[iid]
            out[t] = min(QTY_MAX, out.get(t, 0) + q)
            notes.append("%s x%d -> %s" % (k, q, t))
        elif iid in BETA_REFUND:
            refund += BETA_REFUND[iid] * q
            notes.append("%s x%d -> %d gil" % (k, q, BETA_REFUND[iid] * q))
        else:
            out[k] = min(QTY_MAX, out.get(k, 0) + q)
    return out, refund, notes


class Shop:
    """Stock + per-character wallets. Same deliberately-dumb JSON store shape as
    doc_charastore: synchronous, fsync'd, rewritten whole on every change."""

    def __init__(self, path, stock_path="", start_gil=None):
        self.path = path
        self.stock, file_gil = load_stock(stock_path)
        self.prices = {iid: price for iid, price, _ in self.stock}
        self.names = dict(EXTRA_NAMES)
        self.names.update({iid: name for iid, _, name in self.stock})
        # 2026-09-26: an item's VALUE = everything paid for it: its buy price
        # plus each tune fee on the way (the guides' sell rule is 80 % of
        # that). (source, result) -> (kit, fee); a tune whose source has no
        # value (not stocked, not itself a tune result) is not offered.
        self.values = dict(self.prices)
        self.base = {}                  # tune result -> the stocked part it came from
        self.recipes = {}
        pending = list(DEFAULT_RECIPES)
        while pending:
            left = [r for r in pending if r[0] not in self.values]
            for src, res, kit, fee, name in pending:
                if src in self.values:
                    self.recipes[(src, res)] = (kit, fee)
                    self.values.setdefault(res, self.values[src] + fee)
                    self.base.setdefault(res, self.base.get(src, src))
                    self.names.setdefault(res, name)
            if len(left) == len(pending):
                break
            pending = left
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
    #: bag bullets cannot fill it. Handgun One-Eighty + rifle Tomintoul, a
    #: Middle Barrel each (0x6F310000 -- the 09-13 comment called it "Vernis",
    #: a beta name; the PC's rifle + that barrel measured 4/4 rounds). Granted ONCE
    #: per character (the "kit" mark), so selling it is not free gil; a wallet
    #: made before the kit existed gets it at its next login.
    #: 2026-09-26: the kit is now the LAUNCH kit (STARTER_KIT above, every
    #: part but the suits). A wallet that got the old kit (KIT_MARK only) gets
    #: the parts the old kit lacked ONCE (KIT2_MARK); its gil is not touched.
    STARTER_KIT = STARTER_KIT
    KIT_MARK = "kit"
    KIT2_MARK = "kit2"
    RETAIL_MARK = "retail"

    @staticmethod
    def _grant(bag, items):
        """Add `items` to a wallet bag, a new stack only while the bag has
        room (BAG_MAX). Returns the (id, qty) pairs that did not fit."""
        left = []
        for iid, q in items:
            k = "0x%08x" % iid
            if k not in bag and len([v for v in bag.values() if v > 0]) >= BAG_MAX:
                left.append((iid, q))
                continue
            bag[k] = min(QTY_MAX, bag.get(k, 0) + q)
        return left

    def wallet(self, key):
        w = self.data.get(key)
        if w is None:
            # SOLDIER_MASK_RULE_MARK: a character made from now on EARNS its
            # Soldier Mask (doc_gear.settle_soldier_mask)
            w = self.data[key] = {"gil": self.start_gil, "bag": {},
                                  SOLDIER_MASK_RULE_MARK: 1}
            self.save()
        if not w.get(self.KIT_MARK):
            self._grant(w["bag"], self.STARTER_KIT)
            w[self.KIT_MARK] = 1
            w[self.KIT2_MARK] = 1
            self.save()
        if not w.get(self.KIT2_MARK):
            old = {i for i, _q in OLD_STARTER_KIT}
            left = self._grant(w["bag"], [(i, q) for i, q in self.STARTER_KIT
                                          if i not in old])
            w[self.KIT2_MARK] = 1
            print("  [shop] [%s] launch starter kit: the parts the old kit lacked "
                  "granted once%s" % (key, (" (bag full, not given: %s)"
                                             % ", ".join(self.name(i) for i, _q in left))
                                      if left else ""), flush=True)
            self.save()
        if not w.get(self.RETAIL_MARK):
            # 2026-09-26 (design decision): once per
            # wallet, every placeholder id becomes its retail counterpart or
            # its sell value in gil (beta_convert)
            bag, refund, notes = beta_convert(w["bag"])
            w["bag"] = bag
            w["gil"] = min(GIL_MAX, w["gil"] + refund)
            w[self.RETAIL_MARK] = 1
            if notes:
                print("  [shop] [%s] beta parts converted: %s"
                      % (key, "; ".join(notes)), flush=True)
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
        gain = self.sell_value(iid) * n
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
        """What one `iid` sells for: the launch price (LAUNCH_SELL; a tuned
        item its base part's), a sourced override, else 80 % of its value;
        0 = not sellable (not listed on 144)."""
        if iid in SELL_OVERRIDES:
            return SELL_OVERRIDES[iid]
        base = self.base.get(iid, iid)
        if base in LAUNCH_SELL and iid in self.values:
            return LAUNCH_SELL[base]
        return int(self.values.get(iid, 0) * SELL_RATE)

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
    assert len(ids) == len(set(ids)) <= STOCK_MAX == 89, len(ids)
    # 2026-09-24: Flash Materia came with a later update, after our client
    assert FLASH_MATERIA not in ids, "Flash Materia is not a launch item"
    # 2026-09-26: the guides' shop sells no ammunition and no consumables
    assert not [i for i in ids if i >> 16 in (0x6230, 0x6932, 0x6430)], ids
    pairs = [(s, r) for s, r, _, _, _ in DEFAULT_RECIPES]
    assert len(pairs) == len(set(pairs)), "recipe (source, result) must be unique"
    shop = Shop(p, start_gil=10000)
    # every sourced tune is offered, none needs a kit
    assert len(shop.recipes) == len(DEFAULT_RECIPES) == 25, len(shop.recipes)
    assert all(k == 0 for k, _ in shop.recipes.values())
    # the LAUNCH sell prices (January 2006 player blog, shop list: buy/sell
    # 200/100, 150/120, 100/80, 300/250); a tuned item sells as its base part
    for iid, want in ((ONE_EIGHTY, 100), (TOMINTOUL, 100), (NELSON, 100),
                      (0x6F300003, 100), (0x6F30001E, 100),
                      (MIDDLE_BARREL, 120), (0x6F310001, 120), (0x6F310002, 120),
                      (SNIPE_SCOPE, 80), (0x6F320005, 80), (POWER_BOOSTER, 120),
                      (0x6F330001, 120), (RAPID_FIRE, 120), (0x6F340017, 80),
                      (0x6F34000B, 80), (0x6331003C, 250),
                      (0x6F300009, 1), (0x6F310009, 1)):
        assert shop.sell_value(iid) == want, (hex(iid), shop.sell_value(iid), want)
    # TWIN: the 2007 80 % rule gives a frame 160 and a suit 240, not launch's
    assert int(shop.prices[ONE_EIGHTY] * SELL_RATE) == 160 != shop.sell_value(ONE_EIGHTY)
    assert int(shop.prices[0x6331003C] * SELL_RATE) == 240 != shop.sell_value(0x6331003C)
    assert shop.sell_value(0x69320000) == 0, "an unstocked item still does not sell"
    # the LAUNCH STARTER KIT: every stocked part but the suits, ONCE per character
    assert len(STARTER_KIT) == 22 and not [i for i, _q in STARTER_KIT if i >> 16 == 0x6331]
    assert {NELSON, SHORT_BARREL, 0x6F340019} <= {i for i, _q in STARTER_KIT}
    kk = "member:9/0x00000001"
    assert shop.login_fields(kk) == (10000, sorted(STARTER_KIT)), shop.login_fields(kk)
    shop.wallet(kk)["bag"].clear()                   # sold / fitted away
    shop.save()
    assert Shop(p).login_fields(kk) == (10000, []), "kit granted once, never again"
    # a wallet from before 09-26 (old kit, mark "kit" only) gets the parts the
    # old kit lacked, ONCE, and keeps its gil and what it had
    shop.data["pre"] = {"gil": 1234, "bag": {"0x6f300000": 1, "0x6f310000": 2,
                                             "0x6f300014": 1}, Shop.KIT_MARK: 1}
    g, b = shop.login_fields("pre")
    bd = dict(b)
    assert g == 1234 and bd[0x6F300000] == 1 and bd[0x6F310000] == 2, (g, b)
    assert bd[NELSON] == 2 and bd[SHORT_BARREL] == 1 and TOMINTOUL not in bd, b
    assert len(b) == 21, b                 # 22 kit ids minus the rifle frame (sold)
    assert shop.login_fields("pre") == (g, b), "TWIN: the top-up runs once"
    # a FULL bag: new stacks that do not fit are skipped, never over BAG_MAX
    full = {"0x%08x" % (0x69000000 + i): 1 for i in range(BAG_MAX)}
    shop.data["full"] = {"gil": 5, "bag": dict(full), Shop.KIT_MARK: 1}
    assert len(shop.wallet("full")["bag"]) == BAG_MAX and shop.wallet("full")[Shop.KIT2_MARK]
    # the rest runs on a character that already received its kit
    k = "member:3/0x0002a664"
    shop.data[k] = {"gil": 10000, "bag": {}, Shop.KIT_MARK: 1, Shop.KIT2_MARK: 1}
    shop.save()
    assert shop.login_fields(k) == (10000, [])
    # the LIVE request 66 (Auto Scope, a beta id our build has only
    # as the placeholder "OS0"): no longer stocked -> an all-zero 67
    live66 = bytes.fromhex("074200000100ffffffffffff030000000000326f0100000000000000")
    assert parse_entry(live66) == {"shop": 3, "iid": 0x6F320000, "qty": 1}
    body, note = shop.body_for(BUY_REQ, live66, k)
    assert body[1] == BUY_ANS and body[12:36] == bytes(24) and "not stocked" in note, note
    # the same request for the Snipe Scope buys it at the guides' 100
    rq = bytearray(live66)
    struct.pack_into("<I", rq, 16, SNIPE_SCOPE)
    body, note = shop.body_for(BUY_REQ, bytes(rq), k)
    assert struct.unpack_from("<I", body, ANS_ADD_ID)[0] == SNIPE_SCOPE, note
    assert struct.unpack_from("<H", body, ANS_ADD_QTY)[0] == 1
    assert struct.unpack_from("<I", body, ANS_SPEND)[0] == 100
    assert Shop(p).login_fields(k) == (9900, [(SNIPE_SCOPE, 1)]), "persisted"
    # refused: too expensive -> all-zero 67
    shop.wallet(k)["gil"] = 50
    body, note = shop.body_for(BUY_REQ, bytes(rq), k)
    assert body[12:36] == bytes(24) and "REFUSED" in note, note
    shop.wallet(k)["gil"] = 9900
    # sell it back: 69 removes it and ADDS 80 % of the price
    body, note = shop.body_for(SELL_REQ, bytes(rq), k)
    assert body[1] == SELL_ANS, note
    assert struct.unpack_from("<I", body, ANS_REM_ID)[0] == SNIPE_SCOPE
    assert struct.unpack_from("<H", body, ANS_REM_QTY)[0] == 1
    assert struct.unpack_from("<I", body, ANS_GAIN)[0] == 80
    assert shop.login_fields(k) == (9980, [])
    # selling what the server never gave is refused
    body, note = shop.body_for(SELL_REQ, bytes(rq), k)
    assert body[12:36] == bytes(24) and "REFUSED" in note, note
    # MODIFY (tune): Middle Barrel -> Middle Barrel II, 50 gil, no kit
    MB, MB2, MB3 = MIDDLE_BARREL, 0x6F310001, 0x6F310002
    rq145 = bytearray(24)
    struct.pack_into("<III", rq145, 12, 3, MB, MB2)
    assert parse_modify(bytes(rq145)) == {"shop": 3, "src": MB, "res": MB2}
    body, note = shop.body_for(TXN_REQ, bytes(rq145), k)       # nothing owned yet
    assert body[1] == TXN_ANS and body[12:36] == bytes(24) and "REFUSED" in note, note
    shop.wallet(k)["bag"].update({"0x%08x" % MB: 1})
    body, note = shop.body_for(TXN_REQ, bytes(rq145), k)
    assert struct.unpack_from("<IIHH", body, 12) == (MB2, MB, 1, 1), note
    assert struct.unpack_from("<I", body, ANS_SPEND)[0] == 50
    assert struct.unpack_from("<I", body, ANS_KIT)[0] == 0, "retail tuning takes no kit"
    assert Shop(p).login_fields(k) == (9930, [(MB2, 1)]), "persisted"
    # ...and on to III (the ladder)
    struct.pack_into("<III", rq145, 12, 3, MB2, MB3)
    body, note = shop.body_for(TXN_REQ, bytes(rq145), k)
    assert struct.unpack_from("<IIHH", body, 12) == (MB3, MB2, 1, 1), note
    # TWIN: a tune the guides do not list (III -> II) is refused
    struct.pack_into("<III", rq145, 12, 3, MB3, MB2)
    body, note = shop.body_for(TXN_REQ, bytes(rq145), k)
    assert body[12:36] == bytes(24) and "no such recipe" in note, note
    # the Modify tab: 142 rows {source, result, kit 0, fee}
    b = shop.body_for(RECIPE_REQ, None, k)[0]
    n = struct.unpack_from("<I", b, LIST_COUNT_OFF)[0]
    assert n == len(shop.recipes) == 25 and len(b) == LIST_ROWS_OFF + RECIPE_ROW * n
    assert struct.unpack_from("<IIII", b, LIST_ROWS_OFF) == (ONE_EIGHTY, 0x6F300003, 0, 100)
    # the Sell tab: 144 = this bag at SELL value (Middle Barrel III -> 120,
    # its base part's launch price)
    b = shop.body_for(PRICE_REQ, None, k)[0]
    assert struct.unpack_from("<I", b, LIST_COUNT_OFF)[0] == 1
    assert struct.unpack_from("<II", b, LIST_ROWS_OFF) == (MB3, 120)
    shop.wallet(k)["gil"] = 9000
    shop.wallet(k)["bag"].clear()
    shop.save()
    # the Buy tab
    b = stock_body(shop.stock)
    assert struct.unpack_from("<I", b, LIST_COUNT_OFF)[0] == len(DEFAULT_STOCK) and 24 + len(b) < 1472
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
    # 2026-09-26: beta placeholders convert ONCE per wallet (the live shapes:
    # OI1/OI2/OI5, OS0 x2) -- real items stay, kits refund their sell value
    nb, nr, _n = beta_convert({"0x69320001": 1, "0x69320002": 1, "0x69320005": 1,
                               "0x6f320000": 2, "0x6f320002": 2, "0x69320000": 3,
                               "0x6f300009": 1, "0x64300000": 2, "0x6f300015": 1})
    assert nb == {"0x69320000": 5, "0x69320004": 1, "0x6f320002": 4,
                  "0x6f300009": 1, "0x6f300014": 1}, nb
    assert nr == 160, nr
    shop.data["old"] = {"gil": 700, "bag": {"0x6f320000": 2}, Shop.KIT_MARK: 1,
                        Shop.KIT2_MARK: 1}
    assert shop.login_fields("old") == (700, [(0x6F320002, 2)])
    assert shop.wallet("old")[Shop.RETAIL_MARK] == 1
    shop.data["old"]["bag"]["0x6f320000"] = 1          # (cannot come back, but)
    assert shop.login_fields("old")[1] == [(0x6F320000, 1), (0x6F320002, 2)],         "TWIN: the conversion runs once -- a marked wallet is left alone"
    assert START_GIL == 3000 and Shop(p).wallet("fresh")["gil"] == 3000
    os.remove(p)
    print("doc_shop self-test PASS")
    sys.exit(0)
