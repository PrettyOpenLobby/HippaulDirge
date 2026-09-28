#!/usr/bin/env python3
"""TWO CONSOLES, ONE HOUSE: docudp's session keying, end to end (sec 4gz).

    python tests/test_doc_session_nat.py                  # the tree's docudp
    python tests/test_doc_session_nat.py OTHER_docudp.py  # e.g. a baseline copy
    python tests/test_doc_session_nat.py --cases hp        # a subset

This starts a REAL `tools/docudp.py` on 127.0.0.1 and drives it with synthetic
datagrams from several UDP sockets that share one source ADDRESS and differ only
in source PORT -- which is exactly what two PS2s behind one household NAT look
like to a public server. The datagrams are mode 0 (the verified no-op cipher,
so docudp's own describe_inner() authenticates them) and carry the client's
charid at packet[16..19], the field the client's header builder 0x00bdb190
stamps into everything it sends (sec 4dv).

Keyed on the source IP alone -- the state this file was written against --
`docudp_baseline.py` fails `household` outright: ONE session for two consoles,
the charid and uid flipping on every datagram, and no peer relay at all,
because each console was the only session there was.

Cases (letters for --cases):
  h  household          two clients, one IP -> two sessions, no clobbering
  p  portmove           a moved NAT mapping -> ONE session, state intact
  n  portmove-noadopt   the falsifier: --no-session-adopt loses that state
  c  collision          two LIVE clients on one charid -> refuse to merge
  s  store              a loaded roster survives the move
  r  reap               --session-idle-drop forgets the dead port only
  t  sidetable          the NPC-spawn state (kept outside Session) moves too
  T  sidetable-noadopt  the falsifier for that: the client is re-sprayed
"""
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time

LOGDIR = os.environ.get("DOC_TEST_LOGS") or tempfile.mkdtemp(
    prefix="doc-session-nat-")
os.makedirs(LOGDIR, exist_ok=True)

BODY_OFF = 24
WORLD_TYPE = 127
POSE_TYPE = 0x83

CA, CB = 0x0004103C, 0x0004100C          # two characters (chara_id_for shape)
UA, UB = 0xA756A69A, 0xA455A599          # the two entrance uids seen live


def folded_cksum(pkt):
    b = bytearray(pkt)
    b[10] = b[11] = 0
    s = sum(b)
    return ((s >> 16) + s) & 0xFFFF


def mk(itype, flags, ident, body, mode=0, seq=0, ack=0):
    """A datagram in MODE 0 -- the verified no-op cipher, so the inner header
    is plaintext and docudp's own describe_inner() authenticates it."""
    n = BODY_OFF + len(body)
    p = bytearray(n)
    p[0] = 0x04
    p[1] = mode
    struct.pack_into("<H", p, 2, n)
    struct.pack_into("<I", p, 4, int(time.time() * 1000) & 0xFFFFFFFF)
    p[8] = itype
    p[9] = flags
    struct.pack_into("<H", p, 12, ack)
    struct.pack_into("<H", p, 14, seq)
    struct.pack_into("<I", p, 16, ident)       # record+4 = the charid
    p[BODY_OFF:] = body
    struct.pack_into("<H", p, 10, folded_cksum(p))
    return bytes(p)


def world_req(charid, selector=12, total=176):
    body = bytearray(total - BODY_OFF)
    body[0] = 7                 # subchannel, <= [kelsvc+16]
    body[1] = selector          # the request selector; the answer is +1
    return mk(WORLD_TYPE, 0x01, charid, bytes(body))


def pose(charid, uid, x=1935.19, y=-1.0, z=-42.71):
    body = bytearray(40)
    struct.pack_into("<I", body, 0, uid)
    struct.pack_into("<fff", body, 4, x, y, z)
    struct.pack_into("<fff", body, 0x10, -0.694, 0.0, 0.719)
    return mk(POSE_TYPE, 0x09, charid, bytes(body))


class Server:
    def __init__(self, script, tools, port, extra=()):
        self.log = os.path.join(LOGDIR, "run-%s-%d.log"
                                % (os.path.basename(script).replace(".py", ""),
                                   port))
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8",
                   PYTHONPATH=tools)
        self.port = port
        self.fh = open(self.log, "wb")
        self.p = subprocess.Popen(
            [sys.executable, script, "--bind", "127.0.0.1",
             "--port", str(port),
             "--mode=subtype", "--subtype=4", "--frag3",
             "--lobby-ip=127.0.0.1", "--lobby-keepalive-ms=0",
             "--peer-relay=raw", "--user-list", "--world-self-charaid"]
            + list(extra),
            cwd=tools, env=env, stdout=self.fh,
            stderr=subprocess.STDOUT)
        self.wait_for("listening on 127.0.0.1:%d" % port, 30)

    def text(self):
        with open(self.log, "rb") as f:
            return f.read().decode("utf-8", "replace")

    def wait_for(self, needle, timeout):
        end = time.time() + timeout
        while time.time() < end:
            if needle in self.text():
                return True
            if self.p.poll() is not None:
                raise SystemExit("docudp exited %d:\n%s"
                                 % (self.p.returncode, self.text()[-4000:]))
            time.sleep(0.1)
        raise SystemExit("timed out waiting for %r in\n%s"
                         % (needle, self.text()[-4000:]))

    def stop(self):
        self.p.terminate()
        try:
            self.p.wait(10)
        except subprocess.TimeoutExpired:
            self.p.kill()
        self.fh.close()
        return self.text()


class Client:
    """One console: one UDP socket, i.e. ONE source port (measured: the title
    binds a single fixed port for the lobby and the game-server channel both)."""

    def __init__(self, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.s.settimeout(0.05)
        self.port = port

    def send(self, pkt, srv):
        self.s.sendto(pkt, ("127.0.0.1", srv.port))
        time.sleep(0.45)        # a decrypt is ~12 ms; leave the loop time
        self.drain()

    def drain(self):
        try:
            while True:
                self.s.recvfrom(65535)
        except OSError:
            pass

    def close(self):
        self.s.close()


def count(txt, needle):
    return txt.count(needle)


RESULTS = []


def check(case, ok, what, detail=""):
    RESULTS.append((case, bool(ok), what, detail))
    print("  %-4s %s%s" % ("PASS" if ok else "FAIL", what,
                           (" -- " + detail) if detail else ""), flush=True)


def case_household(script, tools, port, label):
    """Two consoles, one public address, two source ports, interleaved."""
    print("[%s] household: two clients on 127.0.0.1, ports 41001/41002" % label,
          flush=True)
    srv = Server(script, tools, port)
    a, b = Client(41001), Client(41002)
    try:
        for _ in range(3):
            a.send(world_req(CA), srv)
            b.send(world_req(CB), srv)
        for _ in range(2):
            a.send(pose(CA, UA), srv)
            b.send(pose(CB, UB), srv)
    finally:
        txt = srv.stop()
        a.close()
        b.close()
    new = count(txt, "NEW CLIENT SESSION")
    cid = len(re.findall(r"\[charid\] the client's own", txt))
    uid = len(re.findall(r"\[uid\] client's own user id", txt))
    check(label, new == 2, "two distinct sessions", "NEW CLIENT SESSION x%d" % new)
    check(label, cid == 2, "each charid learned ONCE (no clobber)",
          "[charid] x%d (a flip per packet = one shared session)" % cid)
    check(label, uid == 2, "each uid learned ONCE (no clobber)",
          "[uid] x%d" % uid)
    check(label, "0x%08x" % CA in txt and "0x%08x" % CB in txt,
          "both charids present", "")
    check(label, "[session] WARNING" not in txt,
          "no bogus charid-collision warning", "")
    # the cross-client relay only has somewhere to send if the sessions differ
    check(label, count(txt, "[peer-relay]") > 0,
          "A's position reaches B (a second session exists to relay to)",
          "[peer-relay] x%d" % count(txt, "[peer-relay]"))
    return txt


def case_portmove(script, tools, port, label, extra=(), expect_adopt=True):
    """One console whose NAT mapping moves: same charid, new source port."""
    print("[%s] portmove: 41010 -> (6 s silence) -> 41011, charid 0x%08x"
          % (label, CA), flush=True)
    srv = Server(script, tools, port, extra=extra)
    a = Client(41010)
    try:
        a.send(world_req(CA), srv)
        a.send(pose(CA, UA), srv)
        before_uid = len(re.findall(r"\[uid\] client's own user id",
                                    srv.text()))
        before_cid = len(re.findall(r"\[charid\] the client's own", srv.text()))
        time.sleep(6.0)                  # > --session-adopt-idle (5 s default)
        c = Client(41011)
        c.send(world_req(CA), srv)
        c.send(pose(CA, UA), srv)
    finally:
        txt = srv.stop()
        a.close()
        try:
            c.close()
        except NameError:
            pass
    adopt = count(txt, "SESSION ADOPTED")
    uid_after = len(re.findall(r"\[uid\] client's own user id", txt))
    cid_after = len(re.findall(r"\[charid\] the client's own", txt))
    if expect_adopt:
        check(label, adopt == 1, "the moved client is ADOPTED once",
              "SESSION ADOPTED x%d" % adopt)
        check(label, "uid 0x%08x" % UA in txt,
              "the adopted session carries the uid it learned on the old port",
              "")
        check(label, "1 client(s) now" in txt.split("SESSION ADOPTED")[-1],
              "one session after the move", "")
        check(label, uid_after == before_uid,
              "the uid is NOT relearned (state survived the move)",
              "[uid] x%d before, x%d after" % (before_uid, uid_after))
        # The charid-learn site runs AFTER the adoption in the SAME iteration
        # and reads the BOXED LOCAL (seen_charid[0]). A second [charid] line
        # would mean that box is no longer the session's -- the __slots__/
        # rebinding hazard, caught behaviourally.
        check(label, cid_after == before_cid,
              "the boxed locals still point at the adopted state (no relearn "
              "inside the same iteration)",
              "[charid] x%d before, x%d after" % (before_cid, cid_after))
    else:
        check(label, adopt == 0, "control: adoption is OFF, no merge",
              "SESSION ADOPTED x%d" % adopt)
        check(label, uid_after > before_uid,
              "control: without the merge the state IS lost (uid relearned)",
              "[uid] x%d before, x%d after" % (before_uid, uid_after))
        check(label, count(txt, "NEW CLIENT SESSION") == 2,
              "control: the one player ends up as TWO sessions", "")
        check(label, cid_after > before_cid,
              "control: the charid is relearned from scratch",
              "[charid] x%d before, x%d after" % (before_cid, cid_after))
    return txt


def case_store(script, tools, port, label):
    """A port move with REAL per-account state behind it: a chara store, so the
    session has a loaded roster (roster_uid + chara_ids, a dict) to lose."""
    # the store is the doc_character table: a fresh database, seeded
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import docpg
    docpg.e2e_database("test_doc_session_nat")
    docpg.seed("characters",
               {"0x%08x" % UA: [{"slot": 0, "name": "Lex", "gender": 0,
                                 "app92": 0x12, "app93": 0x10, "voice": 0}]})
    print("[%s] store: roster loaded on 41030, then the same charid on 41031"
          % label, flush=True)
    srv = Server(script, tools, port, extra=("--chara-store=on",))
    a = Client(41030)
    try:
        a.send(pose(CA, UA), srv)         # -> refresh_roster(uid): roster_uid + chara_ids
        a.send(world_req(CA), srv)
        time.sleep(6.0)
        c = Client(41031)
        c.send(world_req(CA), srv)
        c.send(pose(CA, UA), srv)
    finally:
        txt = srv.stop()
        a.close()
        try:
            c.close()
        except NameError:
            pass
    adopted = txt.split("SESSION ADOPTED")[-1] if "SESSION ADOPTED" in txt else ""
    check(label, count(txt, "SESSION ADOPTED") == 1, "adopted once", "")
    check(label, "roster uid 0x%08x" % UA in adopted,
          "the loaded roster uid came across", adopted.splitlines()[0][:150]
          if adopted else "")
    check(label, "1 chara ids" in adopted,
          "the chara-id map (a dict) came across", "")
    check(label, "1 client(s) now" in adopted, "one session after the move", "")
    return txt


def case_reap(script, tools, port, label):
    """--session-idle-drop bounds the registry: a dead port is forgotten, a
    live one is not."""
    print("[%s] reap: --session-idle-drop=3" % label, flush=True)
    srv = Server(script, tools, port, extra=("--session-idle-drop=3",
                                             "--no-session-adopt"))
    a, b = Client(41040), Client(41041)
    try:
        a.send(world_req(CA), srv)
        for _ in range(9):                # ~4 s of B traffic to drive the loop
            b.send(world_req(CB), srv)
    finally:
        txt = srv.stop()
        a.close()
        b.close()
    check(label, "session 127.0.0.1:41040 REAPED" in txt,
          "the silent session is reaped", "")
    check(label, "session 127.0.0.1:41041 REAPED" not in txt,
          "the live session is NOT reaped", "")
    check(label, "1 client(s) now" in txt.split("REAPED")[-1],
          "the registry is back to one", "")
    return txt


def case_sidetable(script, tools, port, label, extra=(), expect=1):
    """A port move must also carry the per-client state that lives OUTSIDE
    Session (it has __slots__): the NPC-spawn bookkeeping is one such dict, and
    once it says `done` the client must not be sprayed with the 33 NPCs again."""
    print("[%s] sidetable: NPC spawn state across a port move" % label,
          flush=True)
    srv = Server(script, tools, port,
                 extra=("--npc-spawn=on", "--npc-spawn-delay=0.5",
                        "--npc-spawn-every=0") + tuple(extra))
    a = Client(41060)
    try:
        for _ in range(3):
            a.send(pose(CA, UA), srv)
        srv.wait_for("[npc-spawn] SENT", 10)
        time.sleep(6.0)
        c = Client(41061)
        for _ in range(4):
            c.send(pose(CA, UA), srv)
    finally:
        txt = srv.stop()
        a.close()
        try:
            c.close()
        except NameError:
            pass
    sent = count(txt, "[npc-spawn] SENT")
    check(label, sent == expect,
          "the NPC push happens %d time(s) across the move" % expect,
          "[npc-spawn] SENT x%d" % sent)
    return txt


def case_collision(script, tools, port, label):
    """Two LIVE clients claiming one charid: two players whose accounts
    resolved to the same character. Must NOT be merged."""
    print("[%s] collision: 41020 and 41021 both send charid 0x%08x, live"
          % (label, CA), flush=True)
    srv = Server(script, tools, port)
    a, b = Client(41020), Client(41021)
    try:
        for _ in range(2):
            a.send(world_req(CA), srv)
            b.send(world_req(CA), srv)
    finally:
        txt = srv.stop()
        a.close()
        b.close()
    check(label, count(txt, "SESSION ADOPTED") == 0,
          "two live clients are NOT merged", "")
    check(label, "BOTH claim charid 0x%08x" % CA in txt,
          "the collision is reported", "")
    check(label, count(txt, "NEW CLIENT SESSION") == 2,
          "both keep their own session", "")
    return txt


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    args = [x for x in sys.argv[1:] if not x.startswith("--")]
    script = os.path.abspath(args[0]) if args else os.path.join(
        here, "..", "tools", "docudp.py")
    script = os.path.abspath(script)
    tools = os.path.abspath(os.path.join(here, "..", "tools"))
    if "--tools" in sys.argv:
        tools = os.path.abspath(sys.argv[sys.argv.index("--tools") + 1])
    label = os.path.basename(script).replace(".py", "")
    cases = "hpncsrtT"
    if "--cases" in sys.argv:
        cases = sys.argv[sys.argv.index("--cases") + 1]
    if "h" in cases:
        case_household(script, tools, 55141, label + "/household")
    if "p" in cases:
        case_portmove(script, tools, 55142, label + "/portmove")
    if "n" in cases:
        case_portmove(script, tools, 55143, label + "/portmove-noadopt",
                      extra=("--no-session-adopt",), expect_adopt=False)
    if "c" in cases:
        case_collision(script, tools, 55144, label + "/collision")
    if "s" in cases:
        case_store(script, tools, 55145, label + "/store")
    if "r" in cases:
        case_reap(script, tools, 55146, label + "/reap")
    if "t" in cases:
        case_sidetable(script, tools, 55149, label + "/sidetable")
    if "T" in cases:
        case_sidetable(script, tools, 55150, label + "/sidetable-noadopt",
                       extra=("--no-session-adopt",), expect=2)
    print(chr(10) + "logs: %s" % LOGDIR, flush=True)
    bad = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed" % (len(RESULTS), len(bad)), flush=True)
    for c, _, w, d in bad:
        print("  FAILED %s: %s %s" % (c, w, d), flush=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
