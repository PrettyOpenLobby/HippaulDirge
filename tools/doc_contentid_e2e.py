#!/usr/bin/env python3
"""LOOPBACK end-to-end for --chara-id-source (2026-10-05), through the real
docudp main(): a NEW character takes its POL member's DoC Content ID.

The client keeps a memory-card gun loadout only for an owner among the
handle's DoC Content IDs (static RE, scratchpad re-loadout/), so a character
id must BE one. Seeded: a POL member with a session at 127.0.0.1 and one
active code-10 Content ID on its handle.

  run "content"  REGISTER -> the log names the Content ID, and the
                 CHARAMAKE answer's record (body[12], wire+0) carries it
  run "derived"  TWIN: the same REGISTER keeps the derived id

    python doc_contentid_e2e.py
"""
import io
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import docudp as D                                          # noqa: E402
import docdb                                                # noqa: E402
import docpg                                                # noqa: E402
import doc_charastore as CS                                 # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening          # noqa: E402
from doc_battle_e2e import seal, pose, check, FAILS         # noqa: E402

PORT = int(os.environ.get("DOC_E2E_PORT", "41711"))
UID = 0x0A1B2C3D
NAME = "Fitter"


def seed_member():
    """A member with a session at 127.0.0.1 and one DoC Content ID; returns
    (member id, content id)."""
    acc = docdb.accounts()
    conn = acc.connect()
    try:
        acc.create_polid(conn, "CIDTEST01", "pw-cidtest")
        mid = acc.add_member(conn, "CIDTEST01", "cid-tester", "pw-cidtest")
        hid = acc.set_handle(conn, mid, "CIDTESTER", primary=True)
        cid = acc.allocate_content_id(conn)
        conn.execute("INSERT INTO handle_content (handle_id, content_code, slot,"
                     " content_id, status, linked_at)"
                     " VALUES (%s, %s, 0, %s, 'active', now())",
                     (hid, CS.DOC_CONTENT_CODE, cid))
        acc.open_session(conn, mid, nick="CIDTEST", peer_ip="127.0.0.1")
        try:
            conn.commit()
        except Exception:
            pass
        ids = acc.member_content_id_list(conn, mid, CS.DOC_CONTENT_CODE)
    finally:
        conn.close()
    return mid, int(ids[0])


def register_pkt():
    """A 232-byte REGISTER (name at wire+104, look nibbles +92/+93, voice +127)."""
    pkt = bytearray(232)
    pkt[0] = 0x04
    nm = NAME.encode("ascii")
    pkt[CS.NAME_OFF:CS.NAME_OFF + len(nm)] = nm
    pkt[CS.APP_92], pkt[CS.APP_93], pkt[CS.VOICE_OFF] = 0x21, 0x01, 2
    return seal(pkt)


def run(source):
    url = docpg.e2e_database("doc_contentid_e2e")
    mid, cid = seed_member()
    tmp = os.environ.get("TEMP", HERE)
    log_path = os.path.join(tmp, "doc_contentid_e2e_%s.log" % source)
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--session-idle-drop=0", "--intro=off",
            "--chara-store", "on", "--pol-members", "on",
            "--chara-id-source", source]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1",
               POL_DATABASE_URL=url)
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    got = []
    try:
        wait_listening(log, srv)
        check("[%s] docudp is up" % source, srv.poll() is None)
        dst = ("127.0.0.1", PORT)
        c = udp_socket()
        c.bind(("127.0.0.1", 0))
        c.settimeout(0.3)
        c.sendto(seal(bytearray(96)), dst)          # the lobby keepalive template
        c.sendto(pose(UID), dst)                    # the uid (body[0] of a 0x83)
        time.sleep(0.6)
        c.sendto(register_pkt(), dst)
        t_end = time.time() + 3.0
        while time.time() < t_end:
            try:
                got.append(c.recv(65535))
            except socket.timeout:
                pass
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
            srv.wait()
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check("[%s] no traceback" % source, "Traceback" not in text)
    check("[%s] REGISTERED the character for member:%d" % (source, mid),
          ("REGISTERED '%s'" % NAME) in text, log_path)
    ids = [struct.unpack_from("<I", p, D.BODY_OFF + 12)[0] & 0x3FFFFFFF
           for p in got if len(p) >= D.BODY_OFF + 12 + 96]
    return text, cid, mid, ids


def main():
    text, cid, mid, ids = run("content")
    check("[content] the log names the member's Content ID",
          ("Content ID %d (0x%08x)" % (cid, cid)) in text)
    check("[content] the CHARAMAKE answer's record carries the Content ID",
          cid in ids, "%r vs %d" % ([hex(i) for i in ids], cid))
    text, cid, mid, ids = run("derived")
    derived = D.chara_id_for(0x1000, UID, "member:%d" % mid, 0)
    check("TWIN [derived]: no Content ID; the answer carries the derived id",
          ("'%s' (member:" % NAME) not in text and derived in ids and cid not in ids,
          "%r vs derived 0x%x" % ([hex(i) for i in ids], derived))
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
