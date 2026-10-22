#!/usr/bin/env python3
"""LOOPBACK end-to-end for the OpenLobby admin port (docworld/adminport.py), through the real
docudp main() and over HTTP, the way the panel's proxy calls it.

The stores are seeded first: account member:7 holds Lex and Mira (the account the test
clients play), member:8 holds Tobin (never online). Careers, a unit (Marigold), this week's
tallies, Tobin's wallet, gear and play time. Then, with nobody online:

  the token is refused when wrong; the description names five pages and two actions; the
  status says nobody is online and lists the seeded battle table; every page renders with no
  <script>; Tobin's career, wallet and gear show; a gil gift lands in doc_wallet exactly as
  the game's credit writes it (gil + n, every other field untouched); an item gift adds the
  stack a shop BUY adds; a silly amount, an unknown item and an unknown name are refused

and with Lex and Mira online (a world door each), Lex at a password table and Mira at an
open one:

  the Players page shows both with rank and unit; the Battle tables page shows the members,
  the password FLAG and never the password; the status counts them; a gift to Lex (and to
  Mira, same account) is refused and the wallet row is unchanged; Tobin still gets one.

    python doc_adminport_e2e.py        # ~20 s; DOC_E2E_PORT picks the UDP port
"""
import io
import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import docudp as D                                          # noqa: E402
from docworld import tablerecords as T, tableverbs as V     # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening          # noqa: E402
from doc_battle_e2e import world_req                        # noqa: E402
import docpg                                                # noqa: E402
import docdb                                                # noqa: E402
import doc_shop                                             # noqa: E402
import doc_stats                                            # noqa: E402

PORT = int(os.environ.get("DOC_E2E_PORT", "41733"))
TOKEN = "doc-admin-test-token-1"
LEX, MIRA, TOBIN = 0x00041101, 0x00041102, 0x00041201
K_LEX, K_MIRA, K_TOBIN = ("member:7/0x%08x" % LEX, "member:7/0x%08x" % MIRA,
                          "member:8/0x%08x" % TOBIN)
UNIT = "0x51"
FAILS = []


def check(name, cond, detail=""):
    print("  %s %s%s" % ("ok  " if cond else "FAIL", name,
                         ("  " + str(detail)[:1500]) if detail and not cond else ""), flush=True)
    if not cond:
        FAILS.append(name)
PASSWORD = b"ZQXW"


def free_port():
    p = socket.socket()
    p.bind(("127.0.0.1", 0))
    n = p.getsockname()[1]
    p.close()
    return n


def career(name, cid, rank, rp, kills):
    c = doc_stats.new_career(name, cid)
    c.update(rank=rank, rp=rp, kills=kills, battles=7)
    c["bt"]["w"] = 3
    c["medals"] = {"16": 2}
    return c


def seed():
    docpg.seed("characters", {
        "member:7": [{"name": "Lex", "slot": 0, "cid": LEX, "gender": 0},
                     {"name": "Mira", "slot": 1, "cid": MIRA, "gender": 1}],
        "member:8": [{"name": "Tobin", "slot": 0, "cid": TOBIN, "gender": 0,
                      "created": "2026-10-01T10:00:00Z"}]})
    week = doc_stats.week_of(time.time(), doc_stats.parse_week_start(doc_stats.WEEK_START))
    docpg.seed("stats", {
        "chars": {K_LEX: career("Lex", LEX, 4, 1200, 30), K_MIRA: career("Mira", MIRA, 2, 400, 9),
                  K_TOBIN: career("Tobin", TOBIN, 7, 2600, 51)},
        "weekly": {str(week): {K_TOBIN: {"rp": 240, "kills": 12, "team_w": 2, "solo_w": 0},
                               K_LEX: {"rp": 90, "kills": 4, "team_w": 0, "solo_w": 1}}},
        "weeks_closed": {}})
    docpg.seed("units", {
        "units": {UNIT: {"name": "Marigold", "pts": 345, "registrant": K_LEX,
                         "members": [K_LEX, K_MIRA], "cls": 0, "area": 0}},
        "enlist": {K_LEX: UNIT}})
    docpg.seed("shop", {K_TOBIN: {"gil": 5000, "bag": {"0x%08x" % doc_shop.STARTER_KIT[0][0]: 1},
                                  "kit": 1, "kit2": 1, "retail": 1}})
    docpg.seed("gear", {K_TOBIN: {"mask": doc_shop.ROTATING_MASKS[0][0]}})
    docpg.seed("playtime", {K_TOBIN: 3725})


def wallet_row(key):
    return docdb.store("shop").get(key)


def main():
    docpg.e2e_database("doc_adminport_e2e")
    seed()
    aport = free_port()
    log_path = os.path.join(os.environ.get("TEMP", HERE), "doc_adminport_e2e.log")
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT), "--session-idle-drop=0", "--intro=off",
            "--chara-store", "on", "--account", "member:7", "--shop", "on", "--units", "on",
            "--rankings", "on", "--stats", "on", "--battletable-list", "kalm:0/8:Arden corner"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1",
               POL_DOC_ADMIN_PORT=str(aport), POL_DOC_ADMIN_TOKEN=TOKEN)
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=HERE)
    url = "http://127.0.0.1:%d" % aport

    def get(path, form=None, token=TOKEN):
        data = None if form is None else urllib.parse.urlencode(form).encode()
        req = urllib.request.Request(url + path, data=data, method="GET" if form is None else "POST",
                                     headers={"X-Devtool-Token": token, "X-Devtool-Actor": "arden-gm",
                                              "Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except OSError as e:                 # the port is not there (the server died)
            return 0, str(e)

    def action(aid, params):
        r = urllib.request.Request(url + "/openlobby/actions/" + aid, data=json.dumps(params).encode(),
                                   headers={"X-Devtool-Token": TOKEN, "X-Devtool-Actor": "arden-gm"},
                                   method="POST")
        with urllib.request.urlopen(r, timeout=15) as resp:
            return json.loads(resp.read())

    try:
        check("docudp is up", wait_listening(log, srv))
        deadline = time.time() + 10
        while time.time() < deadline and "OpenLobby admin protocol" not in io.open(
                log_path, encoding="utf-8", errors="replace").read():
            time.sleep(0.1)

        # -- nobody online -------------------------------------------------------
        check("without the token nothing answers", get("/openlobby/module.json", token="x")[0] == 403)
        desc = json.loads(get("/openlobby/module.json")[1])
        check("it describes itself as doc with five pages and two actions",
              (desc["key"], desc["title"], desc["content_ids"], [t["id"] for t in desc["tools"]],
               [a["id"] for a in desc["actions"]]) ==
              ("doc", "Dirge of Cerberus", [10], ["players", "tables", "rankings", "units", "characters"],
               ["gil", "item"]), desc)
        check("...and says announce and kick are not yet there", "not yet" in desc["about"])
        st = json.loads(get("/openlobby/status.json")[1])
        check("the status: nobody online, the seeded table as a room, the facts",
              st.get("online") == 0 and st.get("rooms_label") == "battle tables"
              and [r["name"] for r in st["rooms"]] == ["Arden corner"]
              and {f["label"]: f["value"] for f in st["facts"]} ==
              {"units": 1, "characters": 3, "playing this week": 2}, st)
        pages = ("/players", "/tables", "/rankings", "/units", "/characters",
                 "/characters?name=tobin")
        got = {p: get(p) for p in pages}
        check("every page answers 200 with no script",
              all(s == 200 and "<script" not in b.lower() for s, b in got.values()),
              {p: s for p, (s, _b) in got.items()})
        check("Players says nobody is online", "Nobody is online." in got["/players"][1])
        b = got["/rankings"][1]
        check("Rankings: the characters by rank points, the unit, this week's leader",
              b.index("Tobin") < b.index("Lex") and "Marigold" in b and "This week" in b
              and "Closes and awards the weekly medals" in b, b[-600:])
        b = got["/units"][1]
        check("Units: Marigold, its leader, members and points",
              "Marigold" in b and "Lex, Mira" in b and "345" in b, b[-500:])
        b = got["/characters?name=tobin"][1]
        want = ["Tobin", "DGT-3, 2600 RP", "5,000", "1h 02m", "BT Conquest Medal x2",
                doc_shop.Shop(None).name(doc_shop.ROTATING_MASKS[0][0])]
        check("Characters: Tobin's rank, wallet, gear, play time and medals",
              all(x in b for x in want), [x for x in want if x not in b])
        check("an unknown name says so", "No character called" in get("/characters?name=nobody")[1])

        before = wallet_row(K_TOBIN)
        st_, b = get("/characters", {"op": "gil", "name": "Tobin", "gil": "2,500"})
        after = wallet_row(K_TOBIN)
        check("a gil gift to an offline character says so", "has 7,500 gil now" in b, b[-400:])
        check("...and lands in doc_wallet as the game's credit writes it (gil + n, nothing else)",
              after["gil"] == 7500 and dict(after, gil=0) == dict(before, gil=0), (before, after))
        check("a silly amount is refused",
              "between 1 and" in get("/characters", {"op": "gil", "name": "Tobin", "gil": "0"})[1])
        check("an unknown character is refused",
              "No character called" in get("/characters", {"op": "gil", "name": "Nobody", "gil": "5"})[1])
        iid, _p, iname = doc_shop.DEFAULT_STOCK[-1]
        k = "0x%08x" % iid
        had = int(before["bag"].get(k, 0))
        b = get("/characters", {"op": "item", "name": "Tobin", "item": iname, "qty": "2"})[1]
        row = wallet_row(K_TOBIN)
        check("an item gift adds the stack a shop BUY adds",
              row["bag"].get(k) == had + 2 and row["gil"] == 7500
              and {x: v for x, v in row["bag"].items() if x != k}
              == {x: v for x, v in before["bag"].items() if x != k}, (iname, row))
        check("an item the shop does not sell is refused",
              "not an item the shop sells" in get("/characters", {"op": "item", "name": "Tobin",
                                                                  "item": "0xdeadbeef", "qty": "1"})[1])

        # -- Lex and Mira online -------------------------------------------------
        dst = ("127.0.0.1", PORT)
        so = {}
        for cid in (LEX, MIRA):
            so[cid] = udp_socket()
            so[cid].bind(("127.0.0.1", 0))
            so[cid].settimeout(0.2)
            tail = bytearray(80)
            struct.pack_into("<I", tail, 80 - 12, cid)        # body[80]: the selected character
            so[cid].sendto(world_req(cid, 1, bytes(tail)), dst)
            time.sleep(0.5)
        rec = bytearray(T.build_battletable_record(table_id=0, leader=0, cur=1, maximum=4, map_idx=2,
                                                   mode=2, comment="Lex's room"))
        struct.pack_into("<I", rec, T.BT_OFF_FLAGS, T.BT_FLAG_PASSWORD)
        rec[T.BT_OFF_PW_REC:T.BT_OFF_PW_REC + len(PASSWORD)] = PASSWORD
        so[LEX].sendto(world_req(LEX, V.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.4)
        rec = bytearray(T.build_battletable_record(table_id=0, leader=0, cur=1, maximum=8, map_idx=0,
                                                   mode=1, comment="Mira's open"))
        so[MIRA].sendto(world_req(MIRA, V.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.6)

        b = get("/players")[1]
        check("Players shows Lex and Mira, with rank and unit",
              "Lex" in b and "Mira" in b and "DGSC-3, 1200 RP" in b and "Marigold" in b
              and "seated at table" in b, b[-1200:])
        b = get("/tables")[1]
        check("Battle tables shows both new tables with their members",
              "Lex&#x27;s room" in b and "Mira&#x27;s open" in b and "Lex (leader)" in b
              and "Mira (leader)" in b and "TDM" in b, b[-1500:])
        check("...the password flag, never the password",
              "password" in b and PASSWORD.decode() not in b)
        st = json.loads(get("/openlobby/status.json")[1])
        check("the status lists three tables and both players",
              len(st["rooms"]) == 3 and sorted(p["name"] for p in st["players"]) == ["Lex", "Mira"], st)

        lex_before = wallet_row(K_LEX)
        b = get("/characters", {"op": "gil", "name": "lex", "gil": "100"})[1]
        check("a gift to Lex is refused while Lex is online", "account is online" in b, b[-400:])
        check("...and Lex's wallet row is unchanged", wallet_row(K_LEX) == lex_before,
              (lex_before, wallet_row(K_LEX)))
        out = action("gil", {"name": "Mira", "amount": "100"})
        check("the panel's gil action refuses Mira too (same account online)",
              not out["ok"] and "online" in out["msg"], out)
        out = action("item", {"name": "Mira", "item": iname, "qty": "1"})
        check("...and the item action", not out["ok"] and "online" in out["msg"], out)
        out = action("gil", {"name": "Tobin", "amount": "10"})
        check("the gil action still gives to Tobin, who is offline",
              out["ok"] and wallet_row(K_TOBIN)["gil"] == 7510, out)
        check("the Characters page shows Lex online",
              "online</span>" in get("/characters?name=Lex")[1])
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
            srv.wait()
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check("no traceback in the server log", "Traceback" not in text, log_path)
    check("the server logged each gift with the moderator", text.count("arden-gm gave") == 3, log_path)
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
