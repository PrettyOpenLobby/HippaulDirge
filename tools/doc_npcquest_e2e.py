#!/usr/bin/env python3
"""LOOPBACK end-to-end for the lobby ITEM QUESTS (doc_npcquests: Soar, Este-D,
Hiren), through the real docudp main() with --stats / --shop / the ledger.

Seeded: the character has 35 wins and a bag holding 1 Dandelion + 1 Fuzzy
Seed; --npc-este-accept 1 (Este-D always keeps the flower) and
--npc-quest-day 3 (Hiren's "day" = 3 s). Drives command 26 walk-ups and the
command 27 "scene done" reports the retail scenes send:

    Soar   26 -> 1533, 27 1533 -> Broken Handgun +1, 26 -> 1532
    Este-D 26 -> 201 (met), 26 -> 204, 27 204 -> Dandelion -1 / Gasmask +1,
           26 -> 205
    Hiren  26 -> 1541, 27 1541, 26 -> 1540, 27 1540 -> Fuzzy Seed -1,
           26 -> 1539 (growing), wait 2 "days" -> 1538 ... 5 -> 1536,
           27 1536 -> Dandelion +1   (--npc-hiren-wither 0: these visits are
           days apart)
    2026-09-26, a second server with the default wither rule: a growing seed
    last seen 2 "days" ago -> 1535 (withered), then 1554 with a seed in the
    bag, 27 1554 -> the seed is taken and grows again (1539).

    python doc_npcquest_e2e.py        # ~50 s
"""
import io
import json
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import docudp as D            # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening  # noqa: E402
import doc_npc as N           # noqa: E402
import doc_npcquests as Q     # noqa: E402
from doc_battle_e2e import world_req, check, FAILS   # noqa: E402

PORT = int(os.environ.get("DOC_E2E_PORT", "41559"))
CID = 0x0002A664
KEY = "anon/0x%08x" % CID
TMP = os.environ.get("TEMP", HERE)


def sel_of(p):
    return p[D.BODY_OFF + 1] if len(p) > D.BODY_OFF + 1 else None


def drain(sock):
    try:
        while True:
            sock.recv(65535)
    except socket.timeout:
        pass


def walk_up(sock, npc):
    """Command 26 (trigger npc, b 0); the answered event id."""
    drain(sock)
    sock.sendto(world_req(CID, D.LOBBY_CMD_SELECTOR_REQ,
                          struct.pack("<IIHH", N.CMD_CHECK, 0, 0, npc)),
                ("127.0.0.1", PORT))
    time.sleep(0.4)
    try:
        while True:
            p = sock.recv(65535)
            if sel_of(p) == D.LOBBY_CMD_SELECTOR_ANS:
                return struct.unpack_from("<H", p, D.BODY_OFF + 6)[0]
    except socket.timeout:
        return None


def done(sock, event):
    """Command 27 (the scene reports itself done)."""
    drain(sock)
    sock.sendto(world_req(CID, D.LOBBY_CMD_SELECTOR_REQ,
                          struct.pack("<II", N.CMD_DONE, event)),
                ("127.0.0.1", PORT))
    time.sleep(0.4)
    drain(sock)


def bag(shop_path):
    w = json.load(open(shop_path, encoding="utf-8")).get(KEY, {})
    return {int(k, 16): v for k, v in (w.get("bag") or {}).items()}


def main():
    stats = os.path.join(TMP, "doc_npcquest_e2e_stats.json")
    shop = os.path.join(TMP, "doc_npcquest_e2e_shop.json")
    with open(stats, "w", encoding="utf-8") as f:
        json.dump({"chars": {KEY: {"tbt": {"w": 35, "l": 0, "d": 0}}}}, f)
    with open(shop, "w", encoding="utf-8") as f:
        json.dump({KEY: {"gil": 1000, "kit": 1, "kit2": 1, "bag": {
            "0x%08x" % Q.DANDELION: 1, "0x%08x" % Q.FUZZY_SEED: 1}}}, f)
    log_path = os.path.join(TMP, "doc_npcquest_e2e.log")
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--bt-no-onfly-reserve", "--session-idle-drop=0", "--intro=off",
            "--stats", stats, "--shop", shop, "--mission-ledger", "on",
            "--npc-este-accept", "1", "--npc-quest-day", "3",
            "--npc-hiren-wither", "0"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    try:
        wait_listening(log, srv)
        check("docudp is up", srv.poll() is None)
        sock = udp_socket()
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(0.4)

        # --- Soar
        check("Soar: 35 wins -> 1533 (the Broken Handgun scene)",
              walk_up(sock, Q.SOAR) == 1533)
        done(sock, 1533)
        check("Soar: done -> Broken Handgun in the bag",
              bag(shop).get(Q.BROKEN_HANDGUN) == 1)
        check("Soar: then 1532 'come back with victories'",
              walk_up(sock, Q.SOAR) == 1532)
        done(sock, 1533)
        check("Soar: a repeated done does not give a second handgun",
              bag(shop).get(Q.BROKEN_HANDGUN) == 1)

        # --- Sturm (the seeded career holds no rank -> rank 1)
        check("Sturm: rank 1 -> the tutorial 1131", walk_up(sock, Q.STURM) == 1131)

        # --- Este-D
        check("Este-D: first meeting 201", walk_up(sock, Q.ESTE) == 201)
        check("Este-D: holding a Dandelion -> 204 (accept forced to 1)",
              walk_up(sock, Q.ESTE) == 204)
        check("Este-D: nothing moves before the scene is done",
              bag(shop).get(Q.DANDELION) == 1 and not bag(shop).get(Q.GASMASK))
        done(sock, 204)
        b = bag(shop)
        check("Este-D: done -> Dandelion gone, Gasmask +1",
              not b.get(Q.DANDELION) and b.get(Q.GASMASK) == 1, "%r" % b)
        check("Este-D: 205 from then on", walk_up(sock, Q.ESTE) == 205)

        # --- Hiren (3 s = 1 day)
        check("Hiren: first meeting 1541", walk_up(sock, Q.HIREN) == 1541)
        done(sock, 1541)
        check("Hiren: holding a Fuzzy Seed -> 1540", walk_up(sock, Q.HIREN) == 1540)
        t0 = time.time()                 # the seed goes in now: day 0
        done(sock, 1540)

        def at_day(d):
            time.sleep(max(0.0, t0 + 3.0 * d - time.time()))

        check("Hiren: done takes the seed", not bag(shop).get(Q.FUZZY_SEED))
        check("Hiren: growing 1539", walk_up(sock, Q.HIREN) == 1539)
        at_day(2.4)
        ev = walk_up(sock, Q.HIREN)
        check("Hiren: day 2 -> sprouted 1538", ev == 1538, "%r" % ev)
        done(sock, 1538)
        check("Hiren: sprout seen -> 1552", walk_up(sock, Q.HIREN) == 1552)
        at_day(4.4)
        ev = walk_up(sock, Q.HIREN)
        check("Hiren: day 4 -> the bud 1537", ev == 1537, "%r" % ev)
        done(sock, 1537)
        at_day(5.4)
        ev = walk_up(sock, Q.HIREN)
        check("Hiren: day 5 (120 h) -> bloomed 1536", ev == 1536, "%r" % ev)
        done(sock, 1536)
        check("Hiren: done -> a Dandelion in the bag",
              bag(shop).get(Q.DANDELION) == 1)
        check("Hiren: afterwards, no seed -> 1542", walk_up(sock, Q.HIREN) == 1542)
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
            srv.wait()          # until it has exited it still holds the port
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check("no traceback in the server log", "Traceback" not in text)
    check("log: the item moves are logged",
          "0x%08x +1" % Q.BROKEN_HANDGUN in text
          and "0x%08x +1" % Q.GASMASK in text)
    wither_run()


def wither_run():
    """Hiren's seed WITHERS (January blog: look in on it about once a real
    day), through docudp's default --npc-hiren-wither (1 day; 3 s here)."""
    stats = os.path.join(TMP, "doc_npcquest_e2e_w_stats.json")
    shop = os.path.join(TMP, "doc_npcquest_e2e_w_shop.json")
    now = time.time()
    with open(stats, "w", encoding="utf-8") as f:
        json.dump({"chars": {KEY: {Q.KEY: {str(Q.HIREN): {
            "met": 1, "seed_at": now - 7.0, "seen_at": now - 6.5,
            "stage": 0}}}}}, f)
    with open(shop, "w", encoding="utf-8") as f:
        json.dump({KEY: {"gil": 1000, "kit": 1, "kit2": 1, "bag": {}}}, f)
    log_path = os.path.join(TMP, "doc_npcquest_e2e_w.log")
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--bt-no-onfly-reserve", "--session-idle-drop=0", "--intro=off",
            "--stats", stats, "--shop", shop, "--mission-ledger", "on",
            "--npc-quest-day", "3"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    try:
        wait_listening(log, srv)
        check("[wither] docudp is up", srv.poll() is None)
        sock = udp_socket()
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(0.4)
        ev = walk_up(sock, Q.HIREN)
        check("[wither] last seen > 1 day ago -> 1535 'I let it wither'",
              ev == 1535, "%r" % ev)
        ev = walk_up(sock, Q.HIREN)
        check("[wither] then, no seed -> 1555 TNK_NASHI", ev == 1555, "%r" % ev)
        c = json.load(open(stats, encoding="utf-8"))["chars"][KEY]
        check("[wither] the career holds no growing seed any more",
              c[Q.KEY][str(Q.HIREN)].get("seed_at") is None
              and c[Q.KEY][str(Q.HIREN)].get("kare") == 1, "%r" % c[Q.KEY])
        w = json.load(open(shop, encoding="utf-8"))
        w[KEY]["bag"]["0x%08x" % Q.FUZZY_SEED] = 1
        with open(shop, "w", encoding="utf-8") as f:
            json.dump(w, f)
        srv.terminate()
        srv.wait(5)
        srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                               env=env, cwd=HERE)
        wait_listening(log, srv, count=2)
        ev = walk_up(sock, Q.HIREN)
        check("[wither] a new seed in the bag -> 1554 TNK_AZUKE", ev == 1554,
              "%r" % ev)
        done(sock, 1554)
        check("[wither] 27 1554 takes the seed", not bag(shop).get(Q.FUZZY_SEED))
        ev = walk_up(sock, Q.HIREN)
        check("[wither] it grows again -> 1539", ev == 1539, "%r" % ev)
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
            srv.wait()          # until it has exited it still holds the port
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check("[wither] no traceback", "Traceback" not in text)
    check("[wither] the log names the withering", "WITHERED" in text)
    if FAILS:
        print("%d check(s) failed" % len(FAILS))
        sys.exit(1)
    print("ALL PASS")


if __name__ == "__main__":
    main()
