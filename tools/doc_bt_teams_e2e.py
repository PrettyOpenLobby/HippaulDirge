#!/usr/bin/env python3
"""LOOPBACK end-to-end for the INDIVIDUAL (BT) table's teams (2026-10-06),
through the real docudp main().

Live (3- and 4-player Battle Royale): every BT briefing sends request 31 with
team 0, the "everyone on one side" rebalance split the table 2/1, and the two
on one team saw each other as allies (no red sight, no name). An individual
table has no sides now: every member's team is its seat.

  bt     3 players, individual table, all send 31 arg 0 -> the distribution
         gives teams 0, 1, 2 (distinct), and the 38s log flags with 0x200
  twin   the same 3 at a TEAM table picking 0, 0, 1 -> those sides, not seats

    python doc_bt_teams_e2e.py        # ~40 s; DOC_E2E_PORT picks the port
"""
import io
import os
import re
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import docudp as D                                          # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening          # noqa: E402
from doc_battle_e2e import world_req, gs_req, check, FAILS  # noqa: E402

PORT = int(os.environ.get("DOC_E2E_PORT", "41715"))
CIDS = (0x0002A664, 0x00041018, 0x00041020)


def run(tag, individual, picks=(0, 0, 0)):
    import docpg
    docpg.e2e_database("doc_bt_teams_e2e")
    log_path = os.path.join(os.environ.get("TEMP", HERE), "doc_bt_teams_e2e_%s.log" % tag)
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--bt-no-onfly-reserve",
            "--gs-battle-length=10", "--gs-battle-go-after=1",
            "--gs-real-dist-settle=1", "--gs-battle-reset-after=1",
            "--gs-battle-after-join=30", "--gs-auto-team-after=3",
            "--session-idle-drop=0", "--intro=off"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    try:
        wait_listening(log, srv)
        dst = ("127.0.0.1", PORT)
        so = {}
        for cid in CIDS:
            so[cid] = udp_socket()
            so[cid].bind(("127.0.0.1", 0))
            so[cid].settimeout(0.2)
        rec = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                                   maximum=4, map_idx=2, mode=1,
                                                   comment=tag))
        if individual:
            struct.pack_into("<I", rec, D.BT_OFF_FLAGS,
                             struct.unpack_from("<I", rec, D.BT_OFF_FLAGS)[0]
                             | D.BT_FLAG_INDIVIDUAL)
        so[CIDS[0]].sendto(world_req(CIDS[0], D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.5)
        for cid in CIDS[1:]:
            so[cid].sendto(world_req(cid, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
            time.sleep(0.4)
        so[CIDS[0]].sendto(world_req(CIDS[0], D.LOBBY_CMD_SELECTOR_REQ,
                                     struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.8)
        # the BT briefing: every console sends request 31 with team 0
        for _ in range(4):
            for cid, pk in zip(CIDS, picks):
                so[cid].sendto(gs_req(cid, 31, arg=pk, session=1), dst)
            time.sleep(1.5)
        deadline = time.time() + 12.0
        while time.time() < deadline:
            for cid, pk in zip(CIDS, picks):
                so[cid].sendto(gs_req(cid, 31, arg=pk, session=1), dst)
            time.sleep(1.0)
            if "PLAYER DISTRIBUTION" in io.open(log_path, encoding="utf-8",
                                                errors="replace").read():
                break
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
            srv.wait()
        log.close()
    return io.open(log_path, encoding="utf-8", errors="replace").read()


def dist_teams(text):
    """{cid: team} of the logged kind-20 distribution, or {}."""
    m = re.search(r"PLAYER DISTRIBUTION\) over the REAL roster \[([^\]]*)\]", text)
    if not m:
        return {}
    return {int(c, 16): int(t) for c, t in re.findall(r"'0x([0-9a-f]+):t(\d+):s\d+'",
                                                      m.group(1))}


def main():
    text = run("bt", True)
    teams = dist_teams(text)
    check("[bt] no traceback", "Traceback" not in text)
    check("[bt] the distribution went out with every player on its OWN team",
          len(teams) == 3 and len(set(teams.values())) == 3, "%r" % teams)
    check("[bt] no 'everyone is on team 0' hold and no rebalance",
          "stand on OPPOSITE teams" not in text and "REBALANCED" not in text)
    check("[bt] the 38s log the record flags with the individual bit",
          re.search(r"record flags 0x[0-9a-f]*[2367abef][0-9a-f]{2}\b", text) is not None)

    text = run("twin", False, picks=(0, 0, 1))
    teams = dist_teams(text)
    check("[twin] TWIN: a TEAM table keeps the chosen sides (0, 0, 1), not seats",
          [teams.get(c) for c in CIDS] == [0, 0, 1], "%r" % teams)
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
