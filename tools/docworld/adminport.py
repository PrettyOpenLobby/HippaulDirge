"""adminport.py -- Dirge of Cerberus in an OpenLobby admin panel (the panel's admin protocol, olport.py).

Runs inside the world responder (worldserver.main starts it once the socket is bound). Off
unless POL_DOC_ADMIN_PORT is set; a bad setting is logged and the world runs on without it.

  POL_DOC_ADMIN_PORT    the HTTP port, e.g. 8823
  POL_DOC_ADMIN_BIND    default 127.0.0.1; the panel's container reaches this host-networked
                        process through the Docker gateway (for example 172.17.0.1, Docker's default bridge, with a token)
  POL_DOC_ADMIN_TOKEN   the token the panel sends (POL_ADMIN_GAME_DOC_TOKEN on its side)

The world is one thread: the select loop owns the sessions, the tables and every store's
in-memory `data`, and saves a store by diffing that `data` against what it last wrote
(docdb.Table). So nothing here touches them from the HTTP thread. Each page and action is a
function of the world (`w`, the namespace main() hands over) that LoopBridge runs on the loop
thread between datagrams; the loop selects on the bridge's wake socket beside its own. The
HTTP thread only renders what came back.

The pages, each its own permission in the panel:

  Players       who is online: character, rank, unit, where (lobby area or table), since
  Battle tables every table: mode, map, members by team, restrictions, state
  Rankings      the Ranking menu's character and unit tables, this week's tallies and when
                the week closes (doc_stats' weekly medals)
  Units         every unit: leader, members, rank points
  Characters    one character by name: rank, career, medals, gil and bag, gear, play time;
                Give gil and Give an item, refused while that character's account is online

A gift is written the way the game writes the same change: gil as the battle result credits
it (doc_shop wallet, capped at GIL_MAX), an item as a shop BUY adds it to the server bag (only
stocked items and the rotating masks, the bag's 50-stack cap), then the store's own save().

Not yet: announce (the GM chat kind, doc_chat.KIND_GM, has never been sent by this server
and needs a console test) and kick (a UDP session has no clean disconnect).
"""
import collections
import os
import socket
import struct
import threading
import time

import docdb                       # noqa: F401  puts OpenLobby's services/ on sys.path in a checkout
import doc_shop
import doc_stats
import doc_rank
import doc_unit
from . import arenamaps, charrecords, tablerecords

try:
    import olpage
    import olport
except ImportError:                # a checkout whose core is not beside it
    olpage = olport = None

PORT = int(os.environ.get("POL_DOC_ADMIN_PORT", "0") or 0)
BIND = os.environ.get("POL_DOC_ADMIN_BIND", "127.0.0.1")
TOKEN = os.environ.get("POL_DOC_ADMIN_TOKEN", "")
GIFT_GIL_MAX = 1_000_000
CALL_TIMEOUT = 10.0


def _say(msg):
    print("[docadmin] " + msg, flush=True)


# --------------------------------------------------------------------------- #
# the hand-off to the world's loop
# --------------------------------------------------------------------------- #
class LoopBridge:
    """Runs functions on the world's loop thread. call() queues one and wakes the loop through
    a socket pair; the loop selects on `wake` and calls drain() when it is readable."""

    def __init__(self):
        self._q = collections.deque()
        self.wake, self._poke = socket.socketpair()
        self.wake.setblocking(False)
        self._poke.setblocking(False)

    def fileno(self):
        return self.wake.fileno()

    def call(self, fn, *args, timeout=CALL_TIMEOUT):
        done = threading.Event()
        box = {}
        self._q.append((fn, args, done, box))
        try:
            self._poke.send(b"x")
        except (BlockingIOError, OSError):
            pass                   # the loop has wake-ups pending already
        if not done.wait(timeout):
            raise TimeoutError("the world loop did not answer")
        if "exc" in box:
            raise box["exc"]
        return box["val"]

    def drain(self):
        """On the loop thread: run everything queued."""
        try:
            while self.wake.recv(4096):
                pass
        except (BlockingIOError, OSError):
            pass
        while self._q:
            fn, args, done, box = self._q.popleft()
            try:
                box["val"] = fn(*args)
            except Exception as exc:                    # noqa: BLE001 -- handed to the caller
                box["exc"] = exc
            done.set()


# --------------------------------------------------------------------------- #
# reading the world (each of these runs on the loop thread)
# --------------------------------------------------------------------------- #
def _acct(key):
    return str(key).rsplit("/", 1)[0]


def _rank_text(c):
    if not c:
        return ""
    r = doc_stats.clamp_rank(c.get("rank"))
    return "%s, %d RP" % (doc_stats.RANK_CODES[r - 1], int(c.get("rp") or 0))


def _career(w, key):
    if w.stats is None:
        return None
    return w.stats.data.get("chars", {}).get(key)


def _unit_name(w, key):
    if w.units is None:
        return ""
    uid = w.units.enlisted(key)
    u = w.units.unit(uid) if uid else None
    return (u or {}).get("name", "") if uid else ""


def _characters(w):
    """[(key, name, id, account, record)] of every stored character, keyed as _wallet_key keys
    them (the chara store's account plus the served id)."""
    out = []
    if w.store is None:
        return out
    for acct, chars in w.store.data.items():
        for c in chars or ():
            cid = charrecords.chara_id_of(w.a.chara_id_base, 0, acct, c.get("slot", 0), c)
            if cid:
                out.append(("%s/0x%08x" % (acct, cid & 0x3FFFFFFF), c.get("name", ""), cid, acct, c))
    return out


def _name_of(w, key, cid=0):
    for k, name, _cid, _a, _c in _characters(w):
        if k == key:
            return name
    c = _career(w, key)
    if c and c.get("name"):
        return c["name"]
    return (w.players.get(cid) or {}).get("name", "") if cid else ""


def _name_by_cid(w, cid):
    name = (w.players.get(cid) or {}).get("name")
    if name and not name.startswith("Player_"):
        return name
    want = cid & 0x3FFFFFFF
    return next((n for _k, n, i, _a, _c in _characters(w) if i & 0x3FFFFFFF == want),
                name or "0x%08x" % cid)


def _where(w, cid):
    wh = w.chat_where(cid)
    if wh.battle is not None:
        return "In battle, table %d" % wh.battle
    lobby = ("Lobby, area %d" % (wh.area[1] + 1)) if wh.area and wh.area[0] == "lobby" else "Lobby"
    if wh.table is not None:
        return "%s, seated at table %d" % (lobby, wh.table)
    return lobby


def snap_players(w):
    out = []
    for sess in list(w.sessions.values()):
        cid = sess.seen_charid[0] & 0x3FFFFFFF
        if not cid:
            out.append({"name": "", "rank": "", "unit": "", "where": "Choosing a character",
                        "since": sess.since,
                        "heard": sess.last_peer_rx[0]})
            continue
        key = w.wallet_key(sess.seen_uid[0], cid, sess)
        out.append({"name": _name_of(w, key, sess.seen_charid[0]) or "0x%08x" % cid,
                    "rank": _rank_text(_career(w, key)), "unit": _unit_name(w, key),
                    "where": _where(w, sess.seen_charid[0]),
                    "since": sess.since, "heard": sess.last_peer_rx[0]})
    out.sort(key=lambda p: (p["name"] == "", p["name"].lower()))
    return out


RESTRICT_BITS = ((0x01, "no melee"), (0x02, "no magic"), (0x04, "no Limit Break"),
                 (0x08, "no shooting"), (0x10, "no bombs"), (0x20, "no S-mines"))


def _mode_of(rec):
    flags = struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0]
    if flags & tablerecords.BT_FLAG_MISSION:
        return "Mission %d" % struct.unpack_from("<H", rec, tablerecords.BT_OFF_MISSION)[0]
    if flags & tablerecords.BT_FLAG_INDIVIDUAL:
        return "BT"
    return tablerecords.BT_MODE_NAMES.get(rec[tablerecords.BT_OFF_MODE],
                                          "mode %d" % rec[tablerecords.BT_OFF_MODE])


def _rules_of(rec):
    """The table's restrictions as words. The password is never read, only its flag."""
    flags = struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0]
    out = []
    if flags & tablerecords.BT_FLAG_PASSWORD:
        out.append("password")
    if flags & tablerecords.BT_FLAG_HAS_RESTRICT:
        out.extend(t for b, t in RESTRICT_BITS if rec[tablerecords.BT_OFF_RESTRICT] & b)
    if flags & tablerecords.BT_FLAG_ITEM_RESTRICT:
        out.append("item restrictions")
    if flags & tablerecords.BT_FLAG_MIN_RP:
        out.append("min %d RP" % struct.unpack_from("<I", rec, tablerecords.BT_OFF_MIN_RP)[0])
    if flags & tablerecords.BT_FLAG_MAX_RP:
        out.append("max %d RP" % struct.unpack_from("<I", rec, tablerecords.BT_OFF_MAX_RP)[0])
    if flags & tablerecords.BT_FLAG_KO_LIMIT:
        out.append("KO limit %d" % rec[tablerecords.BT_OFF_KO_LIMIT])
    if flags & tablerecords.BT_FLAG_FRIENDLY_FIRE:
        out.append("friendly fire")
    if flags & tablerecords.BT_FLAG_RANDOM_TEAMS:
        out.append("random teams")
    if flags & tablerecords.BT_FLAG_NOVICE:
        out.append("beginners")
    if flags & tablerecords.BT_FLAG_UNIT:
        out.append("unit table")
    return out


def snap_tables(w):
    out = []
    for key in sorted(w.bt_store.tables):
        t = w.bt_store.get(key)
        rec = w.bt_store.record(key)
        if t is None or rec is None:
            continue
        room = w.battles.get(key)
        picked = (w.gs_tables.get(key) or {}).get("teams") or {}
        individual = bool(struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0]
                          & tablerecords.BT_FLAG_INDIVIDUAL)
        teams = {}
        for m in t["members"]:
            if not m:
                continue
            team = (room.team_of(m) if room is not None and m in room.members
                    else picked.get(m))
            name = _name_by_cid(w, m)
            if m == t.get("leader_cid"):
                name += " (leader)"
            teams.setdefault("Seat" if individual else
                             ("Team %d" % (team + 1) if team is not None else "No team yet"),
                             []).append(name)
        state = ("in battle" if w.bt_store.in_progress(key) or room is not None and not room.over
                 else "briefing" if w.briefing_running(key) else "open")
        comment = rec[tablerecords.BT_OFF_COMMENT:tablerecords.BT_OFF_COMMENT + 40].split(b"\0", 1)[0]
        mi = rec[tablerecords.BT_OFF_MAP]
        out.append({"id": key, "name": comment.decode("cp932", "replace"), "mode": _mode_of(rec),
                    "map": (arenamaps.LOBBY_MAP_NAMES[mi] if mi < len(arenamaps.LOBBY_MAP_NAMES)
                            else "map %d" % mi),
                    "count": len([m for m in t["members"] if m]),
                    "max": rec[tablerecords.BT_OFF_MAX], "teams": sorted(teams.items()),
                    "rules": _rules_of(rec), "state": state})
    return out


#: the Ranking menu tabs shown (counts, not the ratio tabs)
RANK_TABS = (0, 5, 3, 1)


def snap_rankings(w, top=20):
    out = {"chars": [], "units": [], "week": None}
    if w.rank is not None:
        w.rank.load()              # what the Ranking menu does before every page
        for cat in RANK_TABS:
            rows = [(r[1], r[4], r[5]) for r in w.rank.table(False, cat)[:top]]
            out["chars"].append((doc_rank.IND_CATEGORIES[cat][0], rows))
        out["units"] = [(r[1], r[4], r[5]) for r in w.rank.table(True, 0)[:top]]
    if w.stats is not None:
        now = w.stats.clock()
        wk = doc_stats.week_of(now, w.stats.week_phase)
        tallies = w.stats.week_tallies(wk)
        best = []
        for field, idx in doc_stats.WEEKLY_MEDALS:
            rows = sorted(((int(t.get(field, 0)), k) for k, t in tallies.items()), reverse=True)
            best.append((doc_stats.MEDALS.get(idx, field), [(_name_of(w, k) or k, v)
                                                            for v, k in rows[:5] if v > 0]))
        closed = w.stats.data.get("weeks_closed") or {}
        last = max(closed, key=int) if closed else None
        out["week"] = {"start": wk, "end": wk + doc_stats.WEEK_SECS,
                       "offset": float(getattr(w.a, "test_clock_offset", 0) or 0),
                       "on": getattr(w.a, "weekly_medals", "on") == "on",
                       "players": len(tallies), "best": best,
                       "last": None if last is None else {
                           "start": int(last),
                           "awards": [(doc_stats.MEDALS.get(int(i), i),
                                       (_name_of(w, a["key"]) or a["key"]) if a.get("key") else "",
                                       a.get("value", 0))
                                      for i, a in sorted(closed[last]["awards"].items(),
                                                         key=lambda kv: int(kv[0]))]}}
    return out


def snap_units(w):
    if w.units is None:
        return None
    units = w.units.data["units"]
    ranks = doc_unit.standings(units)
    enlist = collections.Counter(w.units.data["enlist"].values())
    out = []
    for h, u in units.items():
        out.append({"id": h, "name": u.get("name", h), "rank": ranks.get(h, 0),
                    "pts": int(u.get("pts", 0)),
                    "leader": _name_of(w, u.get("registrant", "")) or u.get("registrant", ""),
                    "members": [_name_of(w, k) or k for k in (u.get("members") or ())],
                    "enlisted": enlist.get(h, 0)})
    out.sort(key=lambda u: (u["rank"], u["name"].lower()))
    return out


def _find(w, name):
    """(key, name, id, account, record or None) for a character name (any case), or None."""
    want = str(name or "").strip().lower()
    if not want:
        return None
    for hit in _characters(w):
        if hit[1].lower() == want:
            return hit
    for key, c in (w.stats.data.get("chars", {}).items() if w.stats is not None else ()):
        if str(c.get("name", "")).lower() == want:
            return key, c["name"], int(c.get("id") or 0), _acct(key), None
    return None


def _online(w, key):
    """Whether a live session plays `key`'s account (any of its characters)."""
    acct = _acct(key)
    for sess in list(w.sessions.values()):
        k = w.wallet_key(sess.seen_uid[0], sess.seen_charid[0], sess)
        if k == key or _acct(k) == acct:
            return True
    return False


def snap_character(w, name):
    hit = _find(w, name)
    if hit is None:
        return None
    key, cname, cid, acct, rec = hit
    c = _career(w, key) or {}
    wallet = (w.shop.data.get(key) if w.shop is not None else None) or {}
    gear = w.gear.get(key) if w.gear is not None else None
    item = (lambda i: w.shop.name(i)) if w.shop is not None else (lambda i: "0x%08x" % i)
    return {
        "key": key, "name": cname, "id": cid, "account": acct,
        "slot": (rec or {}).get("slot"), "created": (rec or {}).get("created", ""),
        "online": _online(w, key), "rank": _rank_text(c), "unit": _unit_name(w, key),
        "career": c, "wallet": bool(wallet), "gil": wallet.get("gil"),
        "bag": sorted((item(int(k, 16)), q) for k, q in (wallet.get("bag") or {}).items() if q > 0),
        "gear": None if not gear else [(slot, item(gear[slot]) if isinstance(gear.get(slot), int)
                                        else gear.get(slot)) for slot in ("mask", "suit")
                                       if slot in gear],
        "playtime": w.playtime.seconds(key) if w.playtime is not None else None,
        "medals": sorted(((doc_stats.MEDALS.get(int(i), "medal %s" % i), n)
                          for i, n in (c.get("medals") or {}).items() if n), key=lambda m: m[0]),
    }


# --------------------------------------------------------------------------- #
# the gifts (also on the loop thread)
# --------------------------------------------------------------------------- #
def gift_items(w):
    """[(id, name)] an item gift may give: what the shop sells and the rotating masks, the
    ids a BUY puts in a bag."""
    if w.shop is None:
        return []
    ids = {iid for iid, _p, _n in w.shop.stock} | {iid for iid, _n in doc_shop.ROTATING_MASKS}
    return sorted(((i, w.shop.name(i)) for i in ids), key=lambda x: x[1].lower())


def give_gil(w, name, amount, actor):
    if w.shop is None:
        return False, "The shop store is off (--shop), so there are no wallets."
    try:
        amount = int(str(amount).replace(",", "").strip())
    except ValueError:
        return False, "The amount is a whole number of gil."
    if not 0 < amount <= GIFT_GIL_MAX:
        return False, "Give between 1 and %d gil." % GIFT_GIL_MAX
    hit = _find(w, name)
    if hit is None:
        return False, "No character called %r." % str(name or "")
    key, cname = hit[0], hit[1]
    if _online(w, key):
        return False, ("%s's account is online. The running game holds this wallet; give it "
                       "once they have left Dirge of Cerberus." % cname)
    # the battle result's credit (worldserver's tally): the wallet, capped, then save
    wl = w.shop.wallet(key)
    before = wl["gil"]
    wl["gil"] = min(wl["gil"] + amount, doc_shop.GIL_MAX)
    w.shop.save()
    _say("%s gave %d gil to %s [%s]: %d -> %d" % (actor or "?", amount, cname, key, before, wl["gil"]))
    return True, "%s has %s gil now (was %s)." % (cname, "{:,}".format(wl["gil"]), "{:,}".format(before))


def _item_id(w, text):
    text = str(text or "").strip()
    ok = dict(gift_items(w))
    try:
        i = int(text, 0)
        return i if i in ok else None
    except ValueError:
        pass
    want = text.lower().replace(" ", "")
    return next((i for i, n in ok.items() if n.lower().replace(" ", "") == want), None)


def give_item(w, name, item, qty, actor):
    if w.shop is None:
        return False, "The shop store is off (--shop), so there are no bags."
    try:
        qty = int(str(qty or "1").strip())
    except ValueError:
        return False, "The quantity is a whole number."
    if not 0 < qty <= doc_shop.QTY_MAX:
        return False, "Give between 1 and %d." % doc_shop.QTY_MAX
    hit = _find(w, name)
    if hit is None:
        return False, "No character called %r." % str(name or "")
    key, cname = hit[0], hit[1]
    iid = _item_id(w, item)
    if iid is None:
        return False, "%r is not an item the shop sells." % str(item or "")
    if _online(w, key):
        return False, ("%s's account is online. The running game holds this bag; give it "
                       "once they have left Dirge of Cerberus." % cname)
    # a shop BUY's write without the price (doc_shop.Shop.buy): a new stack only while
    # the bag has room, the stack capped at QTY_MAX
    wl = w.shop.wallet(key)
    bag = wl["bag"]
    k = "0x%08x" % iid
    if k not in bag and len([v for v in bag.values() if v > 0]) >= doc_shop.BAG_MAX:
        return False, "%s's bag is full (%d stacks)." % (cname, doc_shop.BAG_MAX)
    have = int(bag.get(k, 0))
    bag[k] = min(doc_shop.QTY_MAX, have + qty)
    w.shop.save()
    _say("%s gave %s x%d to %s [%s]: %d -> %d" % (actor or "?", w.shop.name(iid), qty, cname,
                                                    key, have, bag[k]))
    return True, "%s has %d %s now; it is in their bag at their next login." % (
        cname, bag[k], w.shop.name(iid))


# --------------------------------------------------------------------------- #
# the pages (rendered on the HTTP thread from what the loop handed back)
# --------------------------------------------------------------------------- #
def _when(t):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else "-"


def _ago(t, now):
    if not t:
        return "-"
    s = max(0, int(now - t))
    h, m = divmod(s // 60, 60)
    return ("%dh %02dm" % (h, m)) if h else ("%dm" % m) if m else "%ds" % s


def _hms(s):
    h, m = divmod(int(s or 0) // 60, 60)
    return "%dh %02dm" % (h, m)


def players_page(rows):
    now = time.time()
    # No address column: the panel shows players' addresses to its owner alone, and a tool
    # page cannot tell the owner from a moderator.
    body = olpage.table(["Character", "Rank", "Unit", "Where", "Since", "Last heard"],
                        [[p["name"] or olpage.Raw('<span class="muted">-</span>'), p["rank"],
                          p["unit"], p["where"],
                          _ago(p["since"], now) + " ago", _ago(p["heard"], now) + " ago"]
                         for p in rows], empty="Nobody is online.")
    return olpage.page("Players", olpage.panel("", body),
                       sub="Every client the world server holds a session for. A session that "
                           "goes quiet is dropped after the server's idle limit.")


def tables_page(rows):
    out = []
    for t in rows:
        teams = olpage.Raw("<br>".join("%s: %s" % (olpage.esc(n), olpage.esc(", ".join(ms)))
                                       for n, ms in t["teams"])) if t["teams"] else \
            olpage.Raw('<span class="muted">empty</span>')
        out.append([olpage.Raw('<span class="mono">%d</span>' % t["id"]), t["name"], t["mode"],
                    t["map"], "%d/%d" % (t["count"], t["max"]), teams,
                    ", ".join(t["rules"]) or olpage.Raw('<span class="muted">none</span>'),
                    olpage.Raw('<span class="pill">%s</span>' % olpage.esc(t["state"]))])
    return olpage.page("Battle tables", olpage.panel("", olpage.table(
        ["Id", "Name", "Mode", "Map", "Players", "Members", "Restrictions", "State"], out,
        empty="No battle tables are open.")),
        sub="Every table the lobby lists. A table's password is never shown, only that it has one.")


def rankings_page(r):
    parts = []
    wk = r["week"]
    if wk is not None:
        off = wk["offset"]
        parts.append(olpage.panel("This week", olpage.kv([
            ("Week", "%s to %s" % (_when(wk["start"] - off), _when(wk["end"] - off))),
            ("Closes and awards the weekly medals", _when(wk["end"] - off)
             if wk["on"] else "never (--weekly-medals off)"),
            ("Players with a tally", wk["players"])])))
        parts.append(olpage.grid(*[olpage.panel(title, olpage.table(
            ["Character", "This week"], rows, empty="Nobody yet."))
            for title, rows in wk["best"]]))
        if wk["last"]:
            parts.append(olpage.panel("Last closed week (from %s)" % _when(wk["last"]["start"] - off),
                                      olpage.table(["Medal", "Awarded to", "Count"],
                                                   [[m, who or olpage.Raw('<span class="muted">'
                                                                          'nobody</span>'), v]
                                                    for m, who, v in wk["last"]["awards"]])))
    if r["chars"]:
        parts.append(olpage.grid(*[olpage.panel(title, olpage.table(
            ["#", "Character", "Value"], [[rk, n, "{:,}".format(v)] for rk, n, v in rows],
            empty="No characters.")) for title, rows in r["chars"]]))
        parts.append(olpage.panel("Unit Rank Points", olpage.table(
            ["#", "Unit", "Points"], [[rk, n, "{:,}".format(v)] for rk, n, v in r["units"]],
            empty="No units.")))
    if not parts:
        parts.append(olpage.panel("", olpage.Raw('<p class="muted">The rankings and career '
                                                 'stores are off on this server.</p>')))
    return olpage.page("Rankings", *parts,
                       sub="The tables the lobby's Ranking menu serves (top 20 of each), and "
                           "the week the weekly medals are judged on.")


def units_page(rows):
    if rows is None:
        body = olpage.Raw('<p class="muted">The units store is off on this server (--units).</p>')
    else:
        body = olpage.table(["#", "Unit", "Leader", "Members", "Enlisted", "Rank points"],
                            [[u["rank"], u["name"], u["leader"], ", ".join(u["members"]) or "-",
                              u["enlisted"], "{:,}".format(u["pts"])] for u in rows],
                            empty="No units yet.")
    return olpage.page("Units", olpage.panel("", body),
                       sub="Every registered unit. Enlisted counts the characters flying its "
                           "colours now.")


def characters_page(name="", c=None, items=(), note=None):
    parts = [olpage.panel("Look a character up", olpage.form([("name", "Character name", name)],
                                                             "Look up", hidden={"op": "find"}))]
    if name and c is None:
        parts.append(olpage.panel("", olpage.Raw('<p class="muted">No character called %s.</p>'
                                                 % olpage.esc(name))))
    if c is not None:
        car = c["career"] or {}
        wld = lambda b: "%d-%d-%d" % ((car.get(b) or {}).get("w", 0), (car.get(b) or {}).get("l", 0),
                                      (car.get(b) or {}).get("d", 0))
        parts.append(olpage.grid(
            olpage.panel(c["name"], olpage.kv([
                ("Status", olpage.Raw('<span class="pill">online</span>') if c["online"]
                 else "offline"),
                ("Account", olpage.Raw('<span class="mono">%s</span>' % olpage.esc(c["key"]))),
                ("Character id", "0x%08x" % c["id"]), ("Slot", "-" if c["slot"] is None else c["slot"] + 1),
                ("Created", c["created"] or "-"), ("Rank", c["rank"] or "-"),
                ("Unit", c["unit"] or "-"),
                ("Play time", "-" if c["playtime"] is None else _hms(c["playtime"]))])),
            olpage.panel("Career", olpage.kv([
                ("Battles", car.get("battles", 0)), ("BT won-lost-drawn", wld("bt")),
                ("Team battles", wld("tbt")), ("Kills", car.get("kills", 0)),
                ("Times KO'd", car.get("kos", 0)),
                ("Missions cleared", (car.get("missions") or {}).get("cleared", 0)),
                ("Medals", ", ".join("%s x%d" % m for m in c["medals"]) or "-")])),
            olpage.panel("Wallet", olpage.kv([
                ("Gil", "{:,}".format(c["gil"]) if c["gil"] is not None else
                 "no wallet yet (made at their first login)"),
                ("Gear", ", ".join("%s: %s" % g for g in c["gear"]) if c["gear"] else "-")]),
                olpage.table(["Item", "Qty"], [list(b) for b in c["bag"]], empty="The bag is empty."))))
        parts.append(olpage.grid(
            olpage.panel("Give gil", olpage.form([("gil", "Gil", "")], "Give gil",
                                                 hidden={"op": "gil", "name": c["name"]})),
            olpage.panel("Give an item", olpage.form(
                [("item", "Item name or id", ""), ("qty", "Quantity", "1")], "Give the item",
                hidden={"op": "item", "name": c["name"]}),
                olpage.Raw('<p class="muted">%s</p>' % olpage.esc(
                    "Items: " + ", ".join(n for _i, n in items))))))
    return olpage.page("Characters", *parts, note=note,
                       sub="A gift is refused while the character's account is online: the "
                           "running game holds the wallet and bag.")


# --------------------------------------------------------------------------- #
# the port
# --------------------------------------------------------------------------- #
def build(w, bridge):
    port = olport.AdminPort(
        "doc", "Dirge of Cerberus", short="Dirge", platform="PlayOnline: PS2",
        about="One UDP world server: lobby, battle tables and battles. These tools run inside it. "
              "Announce and kick are not yet available.",
        token=TOKEN, bind=BIND, port=PORT, content_ids=[10],
        services=[{"name": "Dirge of Cerberus", "containers": ["{core}-doc-1"],
                   "warning": "Everyone in Dirge of Cerberus is disconnected."}])
    run = bridge.call

    def _status(w):
        units = len(w.units.data["units"]) if w.units is not None else None
        chars = len(_characters(w)) if w.store is not None else None
        week = None
        if w.stats is not None:
            week = len(w.stats.week_tallies(doc_stats.week_of(w.stats.clock(), w.stats.week_phase)))
        return snap_players(w), snap_tables(w), units, chars, week

    @port.status
    def status():
        players, tables, units, chars, week = run(_status, w)
        online = len(players)
        try:
            import live_sessions
            m = live_sessions.read_marker("doc") or {}
            if time.time() - float(m.get("stamp") or 0) < 60:
                online = int(m.get("count") or 0)
        except Exception:                               # noqa: BLE001 -- the loop's count stands
            pass
        playing = [t for t in tables if t["state"] == "in battle"]
        facts = []
        if units is not None:
            facts.append({"label": "units", "value": units})
        if chars is not None:
            facts.append({"label": "characters", "value": chars})
        if week is not None:
            facts.append({"label": "playing this week", "value": week})
        return {"up": True, "online": online,
                "players": [{"name": p["name"] or "(choosing)", "where": p["where"]} for p in players],
                "rooms": [{"name": t["name"] or "Table %d" % t["id"], "players": t["count"],
                           "max": t["max"], "mode": t["mode"], "state": t["state"]} for t in tables],
                "rooms_label": "battle tables",
                "summary": ("%d battle%s on" % (len(playing), "" if len(playing) == 1 else "s"))
                if playing else "",
                "facts": facts}

    @port.tool("players", "Players", "players")
    def players(method, sub, query, body, actor):
        return 200, olpage.CTYPE, players_page(run(snap_players, w)).encode()

    @port.tool("tables", "Battle tables", "tables")
    def tables(method, sub, query, body, actor):
        return 200, olpage.CTYPE, tables_page(run(snap_tables, w)).encode()

    @port.tool("rankings", "Rankings", "rankings")
    def rankings(method, sub, query, body, actor):
        return 200, olpage.CTYPE, rankings_page(run(snap_rankings, w)).encode()

    @port.tool("units", "Units", "units")
    def units(method, sub, query, body, actor):
        return 200, olpage.CTYPE, units_page(run(snap_units, w)).encode()

    @port.tool("characters", "Characters", "characters")
    def characters(method, sub, query, body, actor):
        import urllib.parse
        f = olpage.posted(body) if method == "POST" else {
            k: v[-1].strip() for k, v in urllib.parse.parse_qs(query or "").items()}
        name, note = f.get("name", ""), None
        if method == "POST" and f.get("op") == "gil":
            note = run(give_gil, w, name, f.get("gil"), actor)
        elif method == "POST" and f.get("op") == "item":
            note = run(give_item, w, name, f.get("item"), f.get("qty"), actor)
        c = run(snap_character, w, name) if name else None
        return 200, olpage.CTYPE, characters_page(name, c, run(gift_items, w), note).encode()

    @port.action("gil", "Give gil", fields=[{"id": "name", "label": "Character"},
                                            {"id": "amount", "label": "Gil"}],
                 about="Into the character's wallet; refused while their account is online.")
    def gil(params, actor):
        return run(give_gil, w, params.get("name"), params.get("amount"), actor)

    @port.action("item", "Give an item", fields=[{"id": "name", "label": "Character"},
                                                  {"id": "item", "label": "Item name or id"},
                                                  {"id": "qty", "label": "Quantity"}],
                 about="Into the character's bag, as a shop purchase adds it; refused while "
                       "their account is online.")
    def item(params, actor):
        return run(give_item, w, params.get("name"), params.get("item"), params.get("qty"), actor)

    return port


def start(world):
    """Called from worldserver.main once the socket is bound. -> the LoopBridge the loop must
    select on and drain, or None (no port configured, or it could not start; never raises)."""
    if not PORT:
        return None
    if olport is None:
        _say("admin port not started (olport/olpage not found beside polcore)")
        return None
    try:
        bridge = LoopBridge()
        port = build(world, bridge)
        host, n = port.start()
    except (OSError, ValueError) as e:
        _say("admin port not started (%s)" % e)
        return None
    bridge.port = port
    _say("OpenLobby admin protocol on %s:%d%s" % (host, n, "" if TOKEN else " (no token)"))
    return bridge
