#!/usr/bin/env python3
"""LOOPBACK end-to-end for the per-mission enemy setup (2026-09-29), through
the real docudp main().

Every set-up mission (2026-09-29: first the seven that had no row --
2, 4, 8, 22, 25, 37 and 38 -- then all of them, once the controllers' POOLS
were read: 18, 21 and 36 placed fewer enemies than they asked for).
Missions 2, 4, 8, 22, 25, 37 and 38 had no row in doc_missions.MISSION_SETUP,
so they spawned no enemies of their own (the Map Exercises 37 / 38 asked for
50 / 100 kills with nothing to shoot). For each of them this plays one
player through CREATE (mission table) -> START -> team 31 -> 47 -> GO and
checks the kind 15 Add Npc that follows: one entry per enemy code in the row,
each entry's TYPE the code's index in its situation's model set (the index
is what picks the model on the client).

    python doc_mission_setup_e2e.py            # ~1 min
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
import docudp as D            # noqa: E402
import doc_missions as M      # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening  # noqa: E402
from doc_battle_e2e import world_req, gs_req, check, FAILS   # noqa: E402
from doc_mission_npc_e2e import kind_of   # noqa: E402

PORT = int(os.environ.get("DOC_E2E_PORT", "41579"))
TMP = os.environ.get("TEMP", HERE)
# 2026-09-29: every mission whose controller exists (31's does not: it
# borrows); 18 / 21 / 36 were SHORT before the controller pools
QUESTS = tuple(sorted(q for q in M.MISSION_SETUP if q != 31))


def k15_entries(pkts, with_pos=False):
    """[(id, type)] (or (id, type, (x, y, z), hp)) of every kind-15 entry."""
    out = []
    for p in pkts:
        if kind_of(p) == D.doc_npc_spawn.KIND_ADD_NPC:
            n = struct.unpack_from("<I", p, D.BODY_OFF + 16)[0]
            for k in range(n):
                e = D.BODY_OFF + 20 + 24 * k
                ent = (struct.unpack_from("<I", p, e)[0],
                       struct.unpack_from("<H", p, e + 8)[0])
                if with_pos:
                    ent += (struct.unpack_from("<3h", p, e + 10),
                            struct.unpack_from("<I", p, e + 4)[0])
                out.append(ent)
    return out


def group_plan_ok(q, zone, sit, ents):
    """2026-10-05 (--mission-spawn-groups on): each enemy stands on one of the
    controller's pool nodes and has a drawable type of THAT node's spawn
    group; the row's count is kept (fewer only when fewer nodes can draw);
    the mission's named target is fielded when any node offers it. Returns
    (ok, detail), or None when the extract carries no groups."""
    rec = D.MISSION_SPAWNS.get(str(zone), {}).get(str(sit)) or {}
    pool, groups = rec.get("pool") or [], rec.get("pool_groups") or []
    if not pool or len(groups) != len(pool):
        return None
    drawable = [i for i, g in enumerate(groups)
                if g and any(M.can_draw(zone, sit, t) for t, _w in g[1])]
    want = min(len(M.MISSION_SETUP[q][2]), len(drawable))
    bad = []
    for _nid, t, pos, _hp in ents:
        hit = [i for i, n in enumerate(pool)
               if all(abs(round(n[j]) - pos[j]) <= 1 for j in range(3))]
        if not hit or not any(t in [gt for gt, _w in (groups[i] or [0, []])[1]]
                              and M.can_draw(zone, sit, t) for i in hit):
            bad.append((t, pos))
    target = [i for i in drawable
              if any(M.kill_target_type(q, zone, t) for t, _w in groups[i][1])]
    has_target = any(M.kill_target_type(q, zone, t) for _n, t, _p, _h in ents)
    ok = len(ents) == want and not bad and (has_target or not target)
    return ok, "%d of %d, off-group %r, target %s" % (
        len(ents), want, bad, has_target if target else "n/a")


def main():
    if not D.MISSION_SPAWNS:
        print("SKIP no doc_mission_spawns.json beside docudp.py: the mission "
              "run needs your own enemy spawn nodes")
        return 0
    import docpg
    docpg.e2e_database("doc_mission_setup_e2e")
    log_path = os.path.join(TMP, "doc_mission_setup_e2e.log")
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--bt-no-onfly-reserve",
            "--gs-battle-go-after=1", "--gs-real-dist-settle=1",
            "--gs-battle-reset-after=1", "--gs-battle-after-join=2",
            "--session-idle-drop=0", "--intro=off", "--npc-arena-after=1",
            "--mission-ledger=off", "--stats", "on"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    counts = {}
    try:
        wait_listening(log, srv)
        check("docudp is up", srv.poll() is None)
        dst = ("127.0.0.1", PORT)
        for i, q in enumerate(QUESTS):
            zone, sit, types, _players = M.mission_setup(q)
            cid = 0x00041100 + i
            c = udp_socket()
            # one address per player: one IP is one account in this server
            c.bind(("127.0.%d.%d" % (1 + i // 200, 10 + i % 200), 0))
            c.settimeout(0.05)
            got = []

            def pump(secs):
                t_end = time.time() + secs
                while time.time() < t_end:
                    try:
                        got.append(c.recv(65535))
                    except socket.timeout:
                        pass

            rec = D.build_battletable_record(table_id=0, leader=0, cur=1,
                                             maximum=1, map_idx=0, mode=1,
                                             comment="q%d" % q,
                                             flags=D.BT_FLAG_MISSION, mission=q)
            c.sendto(world_req(cid, D.BT_REQ_CREATE, bytes(rec)), dst)
            pump(0.6)
            c.sendto(world_req(cid, D.LOBBY_CMD_SELECTOR_REQ,
                               struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
            pump(0.6)
            # the console echoes ITS table's key (selector 38): table i + 1
            c.sendto(gs_req(cid, 31, arg=0, session=i + 1), dst)
            pump(4.0)
            c.sendto(gs_req(cid, 47, session=i + 1), dst)
            pump(4.0)
            ents = k15_entries(got, with_pos=True)
            gp = group_plan_ok(q, zone, sit, ents)
            if gp is not None:
                check("quest %d (zone %d, situation %d): the arena's spawn "
                      "groups pick every enemy (type of its own node's group)"
                      % (q, zone, sit), gp[0], gp[1])
                counts[q] = len(ents)
            else:
                check("quest %d (zone %d, situation %d): kind 15 Add Npc x%d, "
                      "types %s" % (q, zone, sit, len(types), types),
                      sorted(t for _i, t, _p, _h in ents) == sorted(types),
                      "%r" % ents)
                counts[q] = len(types)
            # 2026-10-05: each enemy carries its own max HP (was a flat 100)
            check("quest %d: every enemy's HP is its chardef max HP" % q,
                  ents and all(hp == M.npc_hp(zone, t, -1) for _n, t, _p, hp in ents),
                  "%r" % [(t, hp) for _n, t, _p, hp in ents])
            c.sendto(world_req(cid, D.LOBBY_CMD_SELECTOR_REQ,
                               struct.pack("<II", 4, 0)), dst)   # leave
            pump(1.5)
            c.close()
    finally:
        srv.kill()
        srv.wait()
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check("no traceback in the server log", "Traceback" not in text)
    for q in QUESTS:
        zone, sit, types, _p = M.mission_setup(q)
        n = counts.get(q, len(types))
        check("log: quest %d placed %d NPC(s) at zone %d controller %d's OWN "
              "spawn nodes" % (q, n, zone, sit),
              ("zone %d controller %d: %d NPC(s)" % (zone, sit, n)) in text
              and ("controller %d has no spawn nodes in zone %d" % (sit, zone))
              not in text)
    print("log: %s" % log_path)
    print("ALL PASS" if not FAILS else "FAILED %d: %s" % (len(FAILS), "; ".join(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
