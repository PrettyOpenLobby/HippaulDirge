#!/usr/bin/env python3
"""LOOPBACK end-to-end for the WEEKLY medals (2026-09-26), through the real
docudp main() with --stats. The four (lobby.bin 60:[35..38], medal ids 19..22)
are not battle medals: they reach the client in the world door's medal mask
(selector 2, body[56], bit n = medal id n) after the week closes.

  run "rollover"   the career clock is shifted (test-only --test-clock-offset)
                   so a Monday 00:00 JST boundary falls ~80 s into the run.
                   A and B fight a Team Survival table (mode 2); A KOs B after
                   30 s, B's side is wiped: A has the week's rank points, kill
                   and team win, nobody has a solo win.
                     before the boundary  A's door: no bit 19..22 (TWIN)
                     after it             the log closes the week on the
                                          ROLLOVER; A's door has 19, 20, 21,
                                          not 22; B's has none of them
  run "catchup"    a stats file with a BT won by C in a week that ENDED while
                   the server was down: docudp closes it on STARTUP and C's
                   door has 19, 20 and 22 (solo win); D's has none. A restart
                   closes nothing again (idempotent, counts stay 1).
  run "off"        the same file with --weekly-medals off: nothing is closed,
                   C's door has no weekly bit (TWIN: the gate is real)

    python doc_weekly_e2e.py        # ~2 min; DOC_E2E_PORT picks the port
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
import docudp as D                                          # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening  # noqa: E402
import doc_stats as S                                       # noqa: E402
from doc_battle_e2e import world_req, gs_req, check, notifies, FAILS  # noqa: E402

PORT = int(os.environ.get("DOC_E2E_PORT", "41581"))
TMP = os.environ.get("TEMP", HERE)
A_CID, B_CID = 0x0002A664, 0x00041018
C_CID, D_CID = 0x00061001, 0x00062002
WEEKLY_IDS = {f: i - S.MEDAL_BASE for f, i in S.WEEKLY_MEDALS}   # 19..22
ROLL = 80.0                     # the boundary, seconds after the server starts


def key(cid):
    return "anon/0x%08x" % cid


def drain(sock):
    got = []
    try:
        while True:
            got.append(sock.recv(65535))
    except socket.timeout:
        pass
    return got


def sock():
    c = udp_socket()
    c.bind(("127.0.0.1", 0))
    c.settimeout(0.4)
    return c


def door_mask(so, cid):
    """A world door (1 -> 2) for `cid`: the medal mask at body[56], or None."""
    tail = bytearray(80)
    struct.pack_into("<I", tail, 80 - 12, cid)        # body[80] = the selected char
    drain(so)
    so.sendto(world_req(cid, 1, bytes(tail)), ("127.0.0.1", PORT))
    time.sleep(0.6)
    d = [p for p in drain(so) if len(p) > D.BODY_OFF + 60
         and p[D.BODY_OFF + 1] == 2]
    if not d:
        return None
    return struct.unpack_from("<I", d[0], D.BODY_OFF + S.LOGIN_MEDAL_MASK_OFF)[0]


def weekly_bits(mask):
    if mask is None:
        return None
    return sorted(f for f, i in WEEKLY_IDS.items() if mask >> i & 1)


def start(tag, stats, extra=()):
    log_path = os.path.join(TMP, "doc_weekly_e2e_%s.log" % tag)
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--bt-no-onfly-reserve",
            "--gs-battle-length=120", "--gs-battle-go-after=1",
            "--gs-real-dist-settle=1", "--gs-battle-reset-after=1",
            "--gs-battle-after-join=30", "--session-idle-drop=0", "--intro=off",
            "--stats", stats] + list(extra)
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    wait_listening(log, srv)
    check("[%s] docudp is up" % tag, srv.poll() is None)
    return srv, log, log_path


def stop(srv, log, log_path):
    srv.terminate()
    try:
        srv.wait(5)
    except Exception:
        srv.kill()
        srv.wait()          # until it has exited it still holds the port
    log.close()
    return io.open(log_path, encoding="utf-8", errors="replace").read()


def fresh(path):
    try:
        os.remove(path)
    except OSError:
        pass
    return path


def run_rollover():
    stats = fresh(os.path.join(TMP, "doc_weekly_e2e_rollover_stats.json"))
    t0 = time.time()
    phase = S.parse_week_start(S.WEEK_START)
    boundary = S.week_of(t0 + ROLL, phase) + S.WEEK_SECS   # the next Monday JST
    offset = boundary - (t0 + ROLL)                         # career clock shift
    srv, log, lp = start("rollover", stats,
                         ("--test-clock-offset=%.3f" % offset,))
    got = {A_CID: [], B_CID: []}
    try:
        dst = ("127.0.0.1", PORT)
        so = {cid: sock() for cid in (A_CID, B_CID)}

        def pump():
            for cid in so:
                got[cid] += drain(so[cid])

        rec = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                                   maximum=4, map_idx=2,
                                                   mode=2, comment="weekly"))
        so[A_CID].sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.5)
        so[B_CID].sendto(world_req(B_CID, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
        time.sleep(0.5)
        so[A_CID].sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                                   struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.8)
        so[A_CID].sendto(gs_req(A_CID, 31, arg=0, session=1), dst)
        so[B_CID].sendto(gs_req(B_CID, 31, arg=1, session=1), dst)
        time.sleep(2.5)
        so[A_CID].sendto(gs_req(A_CID, 47, session=1), dst)
        time.sleep(0.2)
        so[B_CID].sendto(gs_req(B_CID, 47, session=1), dst)
        # past doc_stats.RP_MIN_SECONDS, so the battle pays rank points
        for _ in range(32):
            time.sleep(1.0)
            pump()
        # A KOs B: B's client reports its own death (request 30, killer A)
        so[B_CID].sendto(gs_req(B_CID, 30, arg=A_CID, hdr_arg=B_CID, session=1), dst)
        deadline = time.time() + 20.0
        while time.time() < deadline and not (
                notifies(got[A_CID], 4) and notifies(got[B_CID], 4)):
            time.sleep(0.5)
            pump()
        check("[rollover] the battle ended (kind 4 to both)",
              bool(notifies(got[A_CID], 4) and notifies(got[B_CID], 4)))
        left = t0 + ROLL - time.time()
        check("[rollover] the battle ended BEFORE the boundary", left > 3,
              "%.1f s left" % left)
        # TWIN: the same door before the week closes carries no weekly bit
        ma = door_mask(so[A_CID], A_CID)
        check("[rollover] TWIN: A's door BEFORE the boundary has no weekly bit",
              weekly_bits(ma) == [], "mask %r" % ma)
        wk = json.load(open(stats, encoding="utf-8")).get("weekly", {})
        ta = wk.get(str(boundary - S.WEEK_SECS), {}).get(key(A_CID))
        check("[rollover] A's week tally: rank points, 1 kill, 1 team win",
              ta is not None and ta["rp"] > 0 and ta["kills"] == 1
              and ta["team_w"] == 1 and ta["solo_w"] == 0, "%r" % wk)
        # the rollover: nothing is sent; the server's own deadline fires
        while time.time() < t0 + ROLL + 3.0:
            time.sleep(0.5)
            pump()
        ma = door_mask(so[A_CID], A_CID)
        mb = door_mask(so[B_CID], B_CID)
    finally:
        text = stop(srv, log, lp)
    check("[rollover] no traceback", "Traceback" not in text)
    check("[rollover] the week closed on the ROLLOVER (not at startup)",
          "WEEK CLOSED (week rollover)" in text
          and "WEEK CLOSED (startup" not in text)
    _door_a = "[stats] selector 2 [%s]" % key(A_CID)
    check("[rollover] ...on the server's own deadline: BEFORE A's next door "
          "asked", 0 < text.find("WEEK CLOSED") < text.rfind(_door_a))
    check("[rollover] the log names A for Rank Points, Defeats, Team Wins; "
          "nobody for Solo Wins",
          all("WEEKLY %s" % S.MEDALS[i] in text and key(A_CID) in
              text.split("WEEKLY %s" % S.MEDALS[i])[1].split("\n")[0]
              for i in (35, 36, 37))
          and "WEEKLY Weekly Solo Wins 1st" in text
          and "nobody" in text.split("WEEKLY Weekly Solo Wins 1st")[1]
          .split("\n")[0])
    check("[rollover] A's NEXT door: medal ids 19 20 21 set, 22 not",
          weekly_bits(ma) == sorted(["rp", "kills", "team_w"]), "mask %r" % ma)
    check("[rollover] B's door: no weekly bit", weekly_bits(mb) == [],
          "mask %r" % mb)


def seed_catchup(path):
    """A stats file whose only week (9 days back) has ENDED: C won a BT (1 kill)."""
    st = S.Stats(fresh(path))
    st.clock = lambda: time.time() - 9 * 86400
    st.record_battle("BT", [{"key": key(C_CID), "id": C_CID, "team": 1, "kills": 1},
                            {"key": key(D_CID), "id": D_CID, "team": 2}], 1, 120)
    return path


def run_catchup():
    stats = seed_catchup(os.path.join(TMP, "doc_weekly_e2e_catchup_stats.json"))
    srv, log, lp = start("catchup", stats)
    try:
        so = sock()
        mc, md = door_mask(so, C_CID), door_mask(so, D_CID)
    finally:
        text = stop(srv, log, lp)
    check("[catchup] no traceback", "Traceback" not in text)
    check("[catchup] the missed week closed at STARTUP",
          "WEEK CLOSED (startup catch-up)" in text)
    check("[catchup] C's door: medal ids 19 20 22 (rank points, kill, solo win)",
          weekly_bits(mc) == sorted(["rp", "kills", "solo_w"]), "mask %r" % mc)
    check("[catchup] D's door: no weekly bit", weekly_bits(md) == [],
          "mask %r" % md)
    # IDEMPOTENT: a restart closes nothing and pays nothing more
    srv, log, lp = start("catchup2", stats)
    text = stop(srv, log, lp)
    c = json.load(open(stats, encoding="utf-8"))["chars"][key(C_CID)]
    check("[catchup] a restart closes nothing again; C's counts stay 1",
          "WEEK CLOSED" not in text
          and all(c["medals"].get(str(i)) == 1 for i in (35, 36, 38)),
          "%r" % c["medals"])


def run_off():
    stats = seed_catchup(os.path.join(TMP, "doc_weekly_e2e_off_stats.json"))
    srv, log, lp = start("off", stats, ("--weekly-medals=off",))
    try:
        mc = door_mask(sock(), C_CID)
    finally:
        text = stop(srv, log, lp)
    check("[off] TWIN: --weekly-medals off closes nothing; C's door has no "
          "weekly bit", "WEEK CLOSED" not in text and weekly_bits(mc) == [],
          "mask %r" % mc)


def main():
    run_catchup()
    run_off()
    run_rollover()
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
