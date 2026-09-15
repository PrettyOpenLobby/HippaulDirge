#!/usr/bin/env python3
"""Per-character PLAY TIME for Dirge of Cerberus, and the Player Search helper.

## PLAY TIME is lobby COMMAND 20 -- not a server clock (2026-09-13, static)

Read out of a savestate of the lobby (2026-09-13 02:57):

    Status window, own profile -> lobby phase 65 (0x00ad4870):
      kelsvc vt+1016 0x00bd5b10  sends lobby command 20 (selector 240), ONLY
                                 while [kelsvc+256] == 0
      kelsvc vt+1024 0x00bd5bc8  poll: *out = [kelsvc+256]
                                 + (now - [kelsvc+260]) / 1000   (ms -> s)
                                 with out = lobby mgr+300
      kelsvc vt+1032             selector 139, the 268-byte career record
                                 at mgr+32 (doc_stats.py)
    241 sub 20, 0x00bc9318:      [kelsvc+256] = answer body[16] (u32 SECONDS)
                                 [kelsvc+260] = the local ms tick
    window init 0x00ac9e48:      win+944 = [mgr+300], win+948 = tick
    draw 0x00ac9f58:             win+944 + (now - win+948) / 1000
                                 -> "PLAY TIME %d:%02d:%02d" (KelStr 0x7c10)

vt+1024 has ONE caller (0x00ad48b0, phase 65) and mgr+300 ONE reader (that
window), so body[16] is the character's play time. sec 4dc named command 20
the "server clock" and docudp served Unix seconds there (--lobby-clock=unix):
~1.78e9 s = a PLAY TIME of ~496,000 hours. The client asks once per login and
advances the value itself, so the server owes the total at the moment it is
asked -- and never 0: a 0 leaves [kelsvc+256] empty, the client asks again, and
the poll falls through to the generic vt+64 path without filling mgr+300.

## Player Search is a LOCAL prefix search of the peer table

System menu action 1 -> KelMenuSys menu 13 (0x00ac29a0): a 336-byte player-list
window, mode 1. The typed name goes 0x00ad6c08 -> kelsvc vt+664 0x00bd5468 ->
0x00bda970([kelsvc+284], name, out, 100), which compares strlen(name) bytes
(0x003c9f40, a plain memcmp: CASE-SENSITIVE PREFIX) against every 64-byte peer
slot's name at +0 and returns slot+24, the id. Each id becomes a row through the
profile-cache getter 0x00bd36d0 -- a miss drops the row, profile+62 bit 3 hides
it -- and the ROW shows the PROFILE's name (+32), not the peer slot's. Nothing
goes to the server.

So a search finds exactly what we put in the peer table. --peer-push pushed
every user-list id there under the ASKER's name, the 32 --user-list-sweep ids
included: slot 9 holds ids 1..32 all named "Lex", so "C" listed ~30 rows named
"Slot1".."Slot29" (their profile-cache names). peer_push_ids() keeps the sweep
out of the peer table; the sweep still reaches the profile cache, after the real
players, which the user list lists first.

    python doc_playtime.py        # self-test
"""
import json
import os
import tempfile

GAP_CAP = 45.0      # s of silence still counted as play: PCSX2 drops an idle
                    # guest port at ~48 s, so a longer gap is a dead session
SAVE_EVERY = 60.0   # s between writes while time accrues
U32_MAX = 0xFFFFFFFF


class PlayTime:
    """Seconds played per character, keyed like the shop wallet
    (`member:N/0xCHARID`). Accrues from the gaps between one client's datagrams,
    so it counts time in the lobby and in battle, from world entry on."""

    def __init__(self, path=""):
        self.path = path
        self.data = {}
        self._mark = {}         # client ip -> (key, time of its last datagram)
        self._dirty_at = None
        self.load()

    def load(self):
        if not self.path:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = {k: float(v) for k, v in json.load(f).items()}
        except (OSError, ValueError, AttributeError):
            self.data = {}

    def save(self):
        self._dirty_at = None
        if not self.path:
            return
        d = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".playtime-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({k: int(v) for k, v in self.data.items()}, f,
                          indent=1, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass

    def seconds(self, key):
        return int(self.data.get(key, 0))

    def touch(self, ip, key, now):
        """One datagram from `ip`, playing `key`: credit the gap since its last
        one, if that gap is short enough to be play and the key is unchanged."""
        if not key:
            return
        prev = self._mark.get(ip)
        self._mark[ip] = (key, now)
        if prev is not None and prev[0] == key and 0 < now - prev[1] <= GAP_CAP:
            self.data[key] = self.data.get(key, 0.0) + (now - prev[1])
            if self._dirty_at is None:
                self._dirty_at = now
        if self._dirty_at is not None and now - self._dirty_at >= SAVE_EVERY:
            self.save()

    def answer(self, key):
        """Command 20's body[16]: whole seconds, clamped to 1..U32_MAX."""
        if self._dirty_at is not None:
            self.save()
        return max(1, min(self.seconds(key), U32_MAX))


def peer_push_ids(self_id, players, listed_ids, sweep_ids=()):
    """The ids --peer-push puts in a client's peer table: the client itself
    first (even 0, the pre-sec-4dv fallback), then every known player, then
    any other listed id -- but never a --user-list-sweep id, which would land
    in Player Search under the asker's name."""
    sweep = set(sweep_ids)
    out = [self_id]
    for i in list(players) + list(listed_ids):
        if i and i != self_id and i not in out and i not in sweep:
            out.append(i)
    return out


def _selftest():
    fails = []

    def check(name, cond):
        print("  %s %s" % ("ok  " if cond else "FAIL", name))
        if not cond:
            fails.append(name)

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "doc-playtime.json")
        p = PlayTime(path)
        k = "member:15/0x0004103c"
        check("new character answers 1, never 0", p.answer(k) == 1)
        p.touch("192.0.2.1", k, 1000.0)
        p.touch("192.0.2.1", k, 1010.0)
        p.touch("192.0.2.1", k, 1040.0)
        check("gaps within the cap accrue (10 + 30 s)", p.seconds(k) == 40)
        p.touch("192.0.2.1", k, 1100.0)
        check("a 60 s silence is not play", p.seconds(k) == 40)
        p.touch("192.0.2.1", k, 1105.0)
        check("accrual resumes after the silence", p.seconds(k) == 45)
        p.touch("192.0.2.1", "member:15/0x0004103d", 1110.0)
        check("switching character credits neither", p.seconds(k) == 45
              and p.seconds("member:15/0x0004103d") == 0)
        p.touch("192.0.2.2", k, 1111.0)
        p.touch("192.0.2.2", k, 1121.0)
        check("each client ip has its own clock", p.seconds(k) == 55)
        p.touch("192.0.2.1", "", 1112.0)
        check("no key = no accrual", len(p.data) == 1)
        check("answer = the whole seconds", p.answer(k) == 55)
        check("answer persisted it", PlayTime(path).seconds(k) == 55)
        p.touch("192.0.2.2", k, 1130.0)
        p.touch("192.0.2.2", k, 1175.0)
        p.touch("192.0.2.2", k, 1190.0)
        check("throttled save after SAVE_EVERY of accrual",
              PlayTime(path).seconds(k) == p.seconds(k) == 124)
        big = PlayTime("")
        big.data[k] = 5e9
        check("answer clamps to u32", big.answer(k) == U32_MAX)
        check("no path = in memory only", big.path == "" and big.answer(k))

    ids = peer_push_ids(0x4103c, {0x41018: {}, 0x4103c: {}},
                        [0xa455a599, 0x4103c, 0x41018] + list(range(1, 33)),
                        sweep_ids=range(1, 33))
    check("peer push = self, players, asked id; no sweep",
          ids == [0x4103c, 0x41018, 0xa455a599])
    check("peer push keeps self 0 (old fallback)",
          peer_push_ids(0, {}, [7], sweep_ids=())[0] == 0)
    check("peer push without a sweep keeps listed ids",
          peer_push_ids(5, {}, [7, 8, 5]) == [5, 7, 8])

    print("%d check(s) failed" % len(fails) if fails else "ALL PASS")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
