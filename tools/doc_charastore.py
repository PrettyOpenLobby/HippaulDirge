#!/usr/bin/env python3
"""A tiny per-account character store for Dirge of Cerberus (sec 4dq).

Until now the DoC responder seeded four fixed "Quarry" slots (`--lobby-chara-*`)
and threw away every REGISTER and DELETE: creating a character was acknowledged
and forgotten, and a second account saw the first one's roster.  This is the
persistent store that replaces the seeding -- one JSON file, keyed by the
account uid the client reveals at the entrance (docudp.early_uid).

Record, as parsed off the 232-byte REGISTER submission (sec 4bc/4bd, all
PLAINTEXT on the wire -- mode 2 enciphers only the 16-byte inner header):

    wire+104, 16 B   name        ASCII, NUL-padded
    wire+93 low      gender      0 = Male
    wire+92 lo/hi, +93 hi        face / armor / color   (three nibbles, order
                                 not fully pinned -- stored raw so a later boot
                                 can name them without re-capturing)
    wire+127         voice       zero-based (Type N = N-1)

The store is deliberately dumb and synchronous: this responder serves ONE
client at a time (`--peer`), so there is no concurrency to manage, and a
per-write fsync keeps a create durable across the reconnect a reservation
triggers.  Slots are 0..3 (four is the client's roster size).
"""
import datetime
import json
import os
import sqlite3
import struct
import tempfile
import urllib.request

MAX_SLOTS = 4
NAME_OFF = 104
NAME_LEN = 16
APP_92 = 92
APP_93 = 93
VOICE_OFF = 127


def chr_code(char):
    """The 16-bit o099 costume code for a stored charamake character (sec 4dr).

    PROVEN 2026-09-11 by emulating the client's own repacker 0x005a2598 and
    matching the result byte-for-byte to the creation preview: the code is simply
    the two charamake appearance bytes packed little-endian --

        R = app92 | (app93 << 8)

    For Fox (app92=0x12, app93=0x10) that is R = 0x1012, and repack(0x1012) =
    0x00080806, which EQUALS the measured [render_obj+0x444] in the creation-
    screen savestate (doc_x_slot02). So serving R dresses the lobby avatar
    exactly as the creation preview did. repack decodes R as gender=bit6,
    armor=bits3-5, face=bits12-13, color=bits0-1, flag=bit7.

    WARNING: This must be written to the o099 render object, NOT the self position
    object 0x009f3b80 -- on the wire that means body+98/+102 of the selector-2
    reply, not body+96/+100 (those scatter into the position object and are inert
    for the avatar). Earlier field-shuffle formulas were wrong; the raw
    app92|app93<<8 packing is what the client itself uses.
    """
    app92 = char.get("app92", 0) & 0xFF
    app93 = char.get("app93", 0) & 0xFF
    return (app92 | (app93 << 8)) & 0xFFFF


def parse_register(body):
    """Pull a character out of a 232-byte REGISTER body (docudp `body[]`, i.e.
    packet[24:]).  Returns a dict or None if the buffer is too short.

    WARNING: Offsets are WIRE offsets from sec 4bd, and `body` here is packet[24:],
    so the wire+104 name sits at body[104-24] = body[80].  The caller passes
    the raw packet; we index from packet start to keep the sec 4bd numbers
    literal and auditable.
    """
    if len(body) < VOICE_OFF + 1:
        return None
    name = body[NAME_OFF:NAME_OFF + NAME_LEN].split(b"\x00", 1)[0]
    try:
        name = name.decode("ascii", "replace")
    except Exception:
        name = ""
    return {
        "name": name,
        "gender": body[APP_93] & 0x0F,
        "app92": body[APP_92],
        "app93": body[APP_93],
        "voice": body[VOICE_OFF],
    }


#: WARNING:KEY: **THE ENTRANCE UID IS PER-SESSION, SO IT CANNOT BE THE STORE KEY.**
#: Measured on prod 2026-09-12: inside ONE docudp process -- no restart between,
#: and `--peer` admits one source address only -- the uid moved
#: `0xa756a69a -> 0xa455a599` ("per-session state reset", docudp's own log), and
#: the store held one "Fox" under EACH. Keyed on that value, a player's roster
#: splits between sessions and the characters made last time are simply gone
#: from the next one's list. Same bug shape as `feident.py`'s reason for
#: existing, with one player instead of two.
#:
#: STAGE 1 (this): the key is an ACCOUNT the server admin configures
#: (`--account`, compose `POL_DOC_ACCOUNT`, e.g. `member:3` -- the same key shape
#: `fmostore` and `festore` use, which is also what lets the lobby find the
#: roster for the POL content profile). Prod pins DoC to one client with
#: `POL_DOC_PEER`, so one configured account is exact for as long as that holds.
#: STAGE 2 is resolving it from the lobby's `session` table the way `feident`
#: does; it needs `/data` mounted into the doc container and only matters when a
#: second person plays DoC.
#:
#: No account configured = the old uid keying, unchanged, so the emulator and
#: every dev run behave exactly as before.
class CharaStore:
    def __init__(self, path, account=None):
        self.path = path
        self.account = (account or "").strip() or None
        self.data = {}
        self.load()
        if self.account:
            self._adopt_if_unambiguous()

    def _adopt_if_unambiguous(self):
        """First run under an account: carry an existing roster over -- but only
        when there is exactly ONE to carry.

        The rotating uid left rosters behind under keys like `0xa455a599`. With
        exactly one, it is this player's and adopting it is the obvious move.
        With several, WHICH is theirs is a question for the player, not for a
        heuristic: two rosters can both hold a "Fox", and merging by slot would
        overwrite one with the other. So several -> nothing, logged, and
        `python doc_charastore.py --adopt <uid> --account <key> <store>` settles
        it explicitly. The uid rosters are never deleted either way -- they stay
        on disk as the record of what was there.
        """
        if self.account in self.data:
            return
        uids = [k for k in self.data if k.startswith("0x")]
        if len(uids) == 1:
            self.adopt(uids[0])
            print("[chara] account %r had no roster; ADOPTED the only uid roster "
                  "%s (%d character(s)). The uid entry is kept as a backup."
                  % (self.account, uids[0], len(self.data[self.account])),
                  flush=True)
        elif uids:
            # ASCII on purpose: run_all runs this on a Windows console (cp1252),
            # where a warning glyph raised UnicodeEncodeError and killed the run.
            print("[chara] WARNING account %r has no roster and %d uid rosters exist "
                  "(%s) -- NOT adopting any: which one is this player's is not "
                  "something to guess. Run doc_charastore.py --adopt <uid> "
                  "--account %s %s"
                  % (self.account, len(uids), ", ".join(sorted(uids)),
                     self.account, self.path), flush=True)

    def adopt(self, uid_key):
        """Copy the roster stored under `uid_key` to this store's account.
        Non-destructive: the source entry is left in place."""
        if not self.account:
            raise ValueError("adopt needs an account")
        src = self.data.get(uid_key)
        if src is None:
            raise KeyError("no roster under %r" % uid_key)
        self.data[self.account] = [dict(c) for c in src]
        self.save()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {}

    def save(self):
        d = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".chara-", suffix=".tmp")
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

    def _key(self, uid):
        """The configured ACCOUNT when there is one, else the entrance uid.
        See the note above the class for why the uid alone is not enough."""
        if isinstance(uid, str):
            return uid           # sec 4ft: a key the caller already resolved
        if self.account:
            return self.account
        return "0x%08x" % (uid & 0xFFFFFFFF)

    def owners(self):
        """Keys holding at least one character -- the tie-break when several POL
        members have signed in at one address (sec 4ft)."""
        return {k for k, v in self.data.items() if v}

    def roster(self, uid):
        """The account's characters, a list indexed by slot 0..3 (None = empty)."""
        chars = self.data.get(self._key(uid), [])
        slots = [None] * MAX_SLOTS
        for c in chars:
            s = c.get("slot", 0)
            if 0 <= s < MAX_SLOTS:
                slots[s] = c
        return slots

    def add(self, uid, char):
        """Store a freshly registered character in the lowest free slot.

        Returns the slot used, or None if the account is full.  Idempotent on a
        retransmit: a REGISTER with a name already present in a slot updates
        that slot rather than consuming another (the client resends the 232-byte
        message every 500 ms until we answer).
        """
        key = self._key(uid)
        chars = self.data.setdefault(key, [])
        used = {c.get("slot") for c in chars}
        for c in chars:
            if c.get("name") == char.get("name"):
                c.update(char)
                self.save()
                return c.get("slot")
        for slot in range(MAX_SLOTS):
            if slot not in used:
                c = dict(char, slot=slot)
                chars.append(c)
                self.save()
                return slot
        return None

    def delete(self, uid, slot):
        """Remove the character in `slot`.  Returns True if one was removed."""
        key = self._key(uid)
        chars = self.data.get(key, [])
        before = len(chars)
        self.data[key] = [c for c in chars if c.get("slot") != slot]
        if len(self.data[key]) != before:
            self.save()
            return True
        return False


def _utcnow_str():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


#: WARNING:KEY: sec 4ft (2026-09-13): STAGE 2 -- ONE --account IS ONE ROSTER FOR EVERYONE.
#: POL_DOC_PEER went to two machines (sec 4fq) with --account=member:3 still set,
#: and _key() returns the account for EVERY uid: the Deck (POL member 6) and the
#: PC (member 15) shared one list, and the Deck's delete removed the PC's "Test".
#: The fix is the one services/feident.py already uses for Fantasy Earth: the
#: login service writes a `session` row (member_id, nick, peer_ip, created_at)
#: on every POL sign-in, a PS2 title follows a POL login from the same box, and
#: prod runs host networking, so peer_ip is the real client address.
class AccountResolver:
    """The store key for a client address: its POL member, remembered.

    Order, and why each step exists:
      1. the freshest POL `session` row at the address inside WINDOW. Several
         members at one address (a PC with the Windows viewer AND PCSX2 signed
         in) -> the one that already owns DoC characters; if that does not
         separate them, the freshest, logged AMBIGUOUS and not remembered;
      2. the member last resolved at that address. POL purges session rows an
         hour after they are made, on every login, and the doc container is
         recreated far more often than a player signs in;
      3. `addr:<ip>` -- per machine, NEVER one shared bucket.
    Never raises: a database fault falls through to 2/3 and is logged.
    """
    WINDOW = 24 * 3600

    def __init__(self, accounts_db, memory_path, store=None, window=None):
        self.accounts_db = accounts_db
        self.memory_path = memory_path
        self.store = store
        self.window = self.WINDOW if window is None else window

    def _memory(self):
        try:
            with open(self.memory_path, "r", encoding="utf-8") as f:
                m = json.load(f)
            return m if isinstance(m, dict) else {}
        except (OSError, ValueError):
            return {}

    def _remember(self, ip, key):
        m = self._memory()
        if (m.get(ip) or {}).get("key") == key:
            return
        m[ip] = {"key": key, "at": _utcnow_str()}
        d = os.path.dirname(os.path.abspath(self.memory_path)) or "."
        try:
            fd, tmp = tempfile.mkstemp(dir=d, prefix=".ipmem-", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(m, f, indent=1, sort_keys=True)
            os.replace(tmp, self.memory_path)
        except OSError as e:
            print("[chara] WARN could not remember %s -> %s (%r)" % (ip, key, e),
                  flush=True)

    def _sessions(self, ip):
        cutoff = (datetime.datetime.now(datetime.timezone.utc)
                  - datetime.timedelta(seconds=self.window)
                  ).strftime("%Y-%m-%dT%H:%M:%SZ")
        uri = "file:%s?mode=ro" % urllib.request.pathname2url(
            os.path.abspath(self.accounts_db))
        db = sqlite3.connect(uri, uri=True, timeout=2)
        try:
            rows = db.execute(
                "SELECT member_id, nick, created_at FROM session"
                " WHERE peer_ip = ? AND created_at >= ?"
                " ORDER BY created_at DESC LIMIT 32", (ip, cutoff)).fetchall()
        finally:
            db.close()
        seen = {}
        for mid, nick, at in rows:
            seen.setdefault(mid, (mid, nick, at))
        return list(seen.values())

    def resolve(self, ip):
        try:
            cands = self._sessions(ip) if self.accounts_db else []
        except Exception as e:                  # noqa: BLE001 -- see docstring
            print("[chara] WARN POL member lookup for %s failed (%r; %s) -- "
                  "falling back" % (ip, e, self.accounts_db), flush=True)
            cands = []
        if cands:
            pick, how = cands[0], "sole"
            if len(cands) > 1:
                owners = self.store.owners() if self.store is not None else set()
                own = [c for c in cands if ("member:%d" % c[0]) in owners]
                pick, how = ((own[0], "roster") if len(own) == 1
                             else (cands[0], "AMBIGUOUS"))
            key = "member:%d" % pick[0]
            print("[chara] %s -> %s (POL login %r at %s, %s%s)"
                  % (ip, key, pick[1], pick[2], how,
                     "" if len(cands) == 1 else "; candidates %s"
                     % sorted(c[0] for c in cands)), flush=True)
            if how != "AMBIGUOUS":
                self._remember(ip, key)
            return key
        key = (self._memory().get(ip) or {}).get("key")
        if key:
            print("[chara] %s -> %s (REMEMBERED: no POL session row in the last "
                  "%dh)" % (ip, key, self.window // 3600), flush=True)
            return key
        key = "addr:%s" % ip
        print("[chara] WARN %s -> %s: no POL session row and nothing remembered "
              "-- this machine gets its OWN roster, never a shared one"
              % (ip, key), flush=True)
        return key


if __name__ == "__main__":
    import sys
    if "--adopt" in sys.argv or "--show" in sys.argv:
        # python doc_charastore.py --show <store>
        # python doc_charastore.py --adopt <uid-key> --account <key> <store>
        argv = sys.argv[1:]
        def _opt(name):
            i = argv.index(name)
            return argv[i + 1]
        store_path = [x for i, x in enumerate(argv)
                      if not x.startswith("--")
                      and (i == 0 or argv[i - 1] not in ("--adopt", "--account"))][-1]
        if "--show" in argv:
            for k, v in sorted(CharaStore(store_path).data.items()):
                print("%-14s %s" % (k, [(ch.get("slot"), ch.get("name")) for ch in v]))
            sys.exit(0)
        st = CharaStore(store_path)          # NO account yet: no auto-adopt here
        st.account = _opt("--account")
        st.adopt(_opt("--adopt"))
        print("adopted %s -> %s: %s (source kept)" % (
            _opt("--adopt"), st.account,
            [ch.get("name") for ch in st.data[st.account]]))
        sys.exit(0)
    # tiny self-test
    p = os.path.join(tempfile.gettempdir(), "doc_charastore_selftest.json")
    try:
        os.remove(p)
    except OSError:
        pass
    st = CharaStore(p)
    body = bytearray(232)
    nm = b"Zackary"
    body[NAME_OFF:NAME_OFF + len(nm)] = nm
    body[APP_93] = 0x10
    body[APP_92] = 0x11
    body[VOICE_OFF] = 3
    c = parse_register(bytes(body))
    assert c["name"] == "Zackary" and c["voice"] == 3 and c["gender"] == 0, c
    uid = 0xA455A599
    assert st.add(uid, c) == 0
    assert st.add(uid, c) == 0            # idempotent on the same name
    c2 = dict(c, name="Vince")
    assert st.add(uid, c2) == 1
    st2 = CharaStore(p)                    # reloads from disk
    r = st2.roster(uid)
    assert r[0]["name"] == "Zackary" and r[1]["name"] == "Vince" and r[2] is None
    assert st2.delete(uid, 0) is True
    assert CharaStore(p).roster(uid)[0] is None
    os.remove(p)

    # --- THE ACCOUNT KEY (2026-09-12). Each case is the prod failure or the
    # hazard its fix could introduce. ------------------------------------------
    # 1. The bug: uid keying splits one player's roster when the uid rotates.
    st = CharaStore(p)
    st.add(0xA756A69A, dict(c, name="Fox"))
    assert CharaStore(p).roster(0xA455A599)[0] is None, \
        "control: under uid keying a new session uid sees an EMPTY roster"
    os.remove(p)
    # 2. The fix: under an account, both session uids see the same roster.
    st = CharaStore(p, account="member:3")
    st.add(0xA756A69A, dict(c, name="Fox"))
    again = CharaStore(p, account="member:3")
    assert again.roster(0xA455A599)[0]["name"] == "Fox", \
        "a rotated uid must see the roster the previous session made"
    os.remove(p)
    # 3. Adoption: exactly ONE leftover uid roster -> carried over, kept as backup.
    CharaStore(p).add(0xA455A599, dict(c, name="Fox"))
    st = CharaStore(p, account="member:3")
    assert st.roster(0)[0]["name"] == "Fox", "the single uid roster is adopted"
    assert "0xa455a599" in st.data, "the source is NOT deleted"
    os.remove(p)
    # 4. The hazard: SEVERAL uid rosters (prod's actual state) -> adopt NONE.
    base = CharaStore(p)
    base.add(0xA455A599, dict(c, name="Fox"))
    base.add(0xA455A599, dict(c, name="Test"))
    base.add(0xA756A69A, dict(c, name="Fox"))
    st = CharaStore(p, account="member:3")
    assert "member:3" not in st.data, \
        "two uid rosters must not be merged or picked between by guesswork"
    # ...and the explicit adopt settles it, non-destructively.
    st.adopt("0xa455a599")
    names = [s["name"] for s in CharaStore(p, account="member:3").roster(0) if s]
    assert names == ["Fox", "Test"], names
    assert "0xa756a69a" in CharaStore(p).data, "the other roster survives"
    os.remove(p)
    # 5. No account = the old behaviour exactly (the emulator, dev runs).
    assert CharaStore(p)._key(0xA455A599) == "0xa455a599"
    try:
        os.remove(p)
    except OSError:
        pass
    # --- sec 4ft: PER-CLIENT keying by the POL member at the address. -------
    adb = os.path.join(tempfile.gettempdir(), "doc_charastore_selftest_acc.db")
    mem = os.path.join(tempfile.gettempdir(), "doc_charastore_selftest_ip.json")
    for f in (p, adb, mem):
        try:
            os.remove(f)
        except OSError:
            pass
    now = _utcnow_str()
    db = sqlite3.connect(adb)
    db.execute("CREATE TABLE session (member_id INTEGER, nick TEXT, "
               "peer_ip TEXT, created_at TEXT)")
    db.executemany("INSERT INTO session VALUES (?,?,?,?)",
                   [(15, "PCSX2", "192.0.2.1", now),
                    (6, "DECK", "192.0.2.2", now)])
    db.commit()
    db.close()
    st = CharaStore(p)
    rs = AccountResolver(adb, mem, st)
    # 1. The 09-13 bug: two machines, two members, two rosters -- and the
    #    Deck's delete must not touch the PC's characters.
    k_pc, k_deck = rs.resolve("192.0.2.1"), rs.resolve("192.0.2.2")
    assert (k_pc, k_deck) == ("member:15", "member:6"), (k_pc, k_deck)
    st.add(k_pc, dict(c, name="Fox"))
    st.add(k_pc, dict(c, name="Test"))
    st.add(k_deck, dict(c, name="Deck"))
    assert st.delete(k_deck, 0) is True
    names = [s["name"] for s in CharaStore(p).roster("member:15") if s]
    assert names == ["Fox", "Test"], names
    # 2. POL purged the rows: the remembered member still resolves.
    db = sqlite3.connect(adb)
    db.execute("DELETE FROM session")
    db.commit()
    db.close()
    assert AccountResolver(adb, mem, st).resolve("192.0.2.1") == "member:15"
    # 3. Unknown address, nothing remembered: its own key, never a shared one.
    assert (AccountResolver(adb, mem, st).resolve("192.0.2.99")
            == "addr:192.0.2.99")
    # 4. Two members at one address (Windows viewer + PCSX2): the one that
    #    owns DoC characters wins, even though the other row is fresher.
    db = sqlite3.connect(adb)
    db.executemany("INSERT INTO session VALUES (?,?,?,?)",
                   [(15, "PCSX2", "192.0.2.1", "2026-01-01T00:00:00Z"),
                    (15, "PCSX2", "192.0.2.1", now),
                    (3, "VIEWER", "192.0.2.1", now + "~")])
    db.commit()
    db.close()
    assert AccountResolver(adb, mem, st).resolve("192.0.2.1") == "member:15"
    # 5. A database that cannot be opened must not raise -- memory answers.
    assert (AccountResolver(os.path.join(tempfile.gettempdir(), "nope", "x.db"),
                            mem, st).resolve("192.0.2.1") == "member:15")
    # 6. A resolved key passes through _key(); an int uid keys as before.
    assert CharaStore(p, account="member:3")._key("member:6") == "member:6"
    assert CharaStore(p)._key(0xA455A599) == "0xa455a599"
    for f in (p, adb, mem):
        try:
            os.remove(f)
        except OSError:
            pass
    print("doc_charastore self-test PASS")
    sys.exit(0)
