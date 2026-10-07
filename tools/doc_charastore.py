#!/usr/bin/env python3
"""A tiny per-account character store for Dirge of Cerberus (sec 4dq).

Until now the DoC responder seeded four fixed "Quarry" slots (`--lobby-chara-*`)
and threw away every REGISTER and DELETE: creating a character was acknowledged
and forgotten, and a second account saw the first one's roster.  This is the
persistent store that replaces the seeding -- one roster per account, in the
doc_character table of the stack's PostgreSQL database (docdb.py; it was
doc-characters.json on the logs volume), keyed by the account the client is
resolved to (see AccountResolver) or the uid it reveals at the entrance
(docudp.early_uid).

Record, as parsed off the 232-byte REGISTER submission (sec 4bc/4bd, all
PLAINTEXT on the wire -- mode 2 enciphers only the 16-byte inner header):

    wire+104, 16 B   name        ASCII, NUL-padded
    wire+93 low      gender      0 = Male
    wire+92 lo/hi, +93 hi        face / armor / color   (three nibbles, order
                                 not fully pinned -- stored raw so a later boot
                                 can name them without re-capturing)
    wire+127         voice       zero-based (Type N = N-1)

The store is deliberately dumb and synchronous: the responder is one
process, so there is no concurrency to manage, and every change is written
before the answer goes out, so a create is durable across the reconnect a
reservation triggers.  Slots are 0..3 (four is the client's roster size).
"""
import datetime
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import docdb  # noqa: E402

MAX_SLOTS = 4
NAME_OFF = 104
NAME_LEN = 16
APP_92 = 92
APP_93 = 93
VOICE_OFF = 127


#: 2026-10-05: a character's POL CONTENT ID ("cid"), DoC = service code 10.
#: Static RE (scratchpad re-loadout/): the client purges every memory-card
#: loadout slot whose owner is not one of the handle's code-10 content ids,
#: so a character whose id is ours alone loses its gun setup at every boot.
#: A stored "cid" IS the character's id (charrecords.chara_id_of); bits 30/31
#: must stay clear (NPC ids, sec 4bw/4ch), as allocated ids always are.
DOC_CONTENT_CODE = 10
CONTENT_ID_MAX = 0x40000000


def content_id_of(char):
    """The character's stored Content ID, or 0 (none / not a valid id)."""
    try:
        v = int((char or {}).get("cid") or 0)
    except (TypeError, ValueError):
        return 0
    return v if 0 < v < CONTENT_ID_MAX else 0


def chr_code(char):
    """The 16-bit o099 costume code for a stored charamake character (sec 4dr).

    PROVEN 2026-09-11 by emulating the client's own repacker 0x005a2598 and
    matching the result byte-for-byte to the creation preview: the code is simply
    the two charamake appearance bytes packed little-endian --

        R = app92 | (app93 << 8)

    For Lex (app92=0x12, app93=0x10) that is R = 0x1012, and repack(0x1012) =
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


#: SE's character-name rules, from the client's own error table
#: (data/etc/kelerr.bin) and creation prompt (group 35 [21]): 3 to 15
#: characters of A-Z, 0-9, hyphen, underscore; a hyphen or underscore may not
#: begin or end the name, nor follow another.
NAME_MIN, NAME_MAX = 3, 15
CER_NAME_LENGTH = 42310
CER_NAME_CHARS = 42311
CER_NAME_TAKEN = 45201
_NAME_SYMBOLS = "-_"


def name_error(name):
    """None for a name SE's rules accept, else the CER code that refuses it."""
    name = name or ""
    if not NAME_MIN <= len(name) <= NAME_MAX:
        return CER_NAME_LENGTH
    if any(not (ch.isascii() and (ch.isalnum() or ch in _NAME_SYMBOLS))
           for ch in name):
        return CER_NAME_CHARS
    if name[0] in _NAME_SYMBOLS or name[-1] in _NAME_SYMBOLS:
        return CER_NAME_CHARS
    if any(a in _NAME_SYMBOLS and b in _NAME_SYMBOLS
           for a, b in zip(name, name[1:])):
        return CER_NAME_CHARS
    return None


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
#: Measured live inside ONE docudp process -- no restart between,
#: and `--peer` admits one source address only -- the uid moved
#: `0xa756a69a -> 0xa455a599` ("per-session state reset", docudp's own log), and
#: the store held one "Lex" under EACH. Keyed on that value, a player's roster
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
#:
#: `store` is where the rosters live: docdb.store("characters") (the
#: doc_character table), or None for rosters kept in memory only.
class CharaStore:
    def __init__(self, store, account=None):
        if isinstance(store, str):
            raise TypeError("CharaStore takes docdb.store('characters') or None, "
                            "not a file path (the rosters are in PostgreSQL)")
        self.store = store
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
        heuristic: two rosters can both hold a "Lex", and merging by slot would
        overwrite one with the other. So several -> nothing, logged, and
        `python doc_charastore.py --adopt <uid> --account <key>` settles
        it explicitly. The uid rosters are never deleted either way -- they stay
        in the store as the record of what was there.
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
                  "--account %s"
                  % (self.account, len(uids), ", ".join(sorted(uids)),
                     self.account), flush=True)

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
        """Read every roster. A database that cannot be reached raises: a
        responder that started on an empty store would hand out slots that
        are taken."""
        self.data = self.store.load() if self.store is not None else {}

    def save(self):
        if self.store is not None:
            self.store.save(self.data)

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

    def name_taken(self, name, key):
        """True when another roster already holds `name` (any case). Rosters
        keyed by a bare entrance uid ("0x..") are the pre-account backups of
        the same players (see adopt), so they are not counted against an
        account; against another uid roster they are."""
        low = (name or "").lower()
        for k, chars in self.data.items():
            if k == key or (k.startswith("0x") and not key.startswith("0x")):
                continue
            if any((c.get("name") or "").lower() == low for c in chars):
                return True
        return False

    def register(self, uid, char):
        """The REGISTER rules SE's server enforced (2026-10-01): (slot, None)
        when stored, (None, CER code) when refused. The codes are SE's own,
        data/etc/kelerr.bin: 42310 length, 42311 characters, 45201 "mainly a
        duplicate name". A REGISTER identical to a stored character (the
        client resends it every 500 ms until answered) returns that slot; one
        with an existing name and a DIFFERENT look is a second character of
        that name and is refused -- add() used to overwrite the first."""
        err = name_error(char.get("name"))
        if err:
            return None, err
        key = self._key(uid)
        chars = self.data.setdefault(key, [])
        low = char["name"].lower()
        for c in chars:
            if (c.get("name") or "").lower() == low:
                same = all(c.get(f) == char.get(f) for f in
                           ("name", "gender", "app92", "app93", "voice"))
                return (c.get("slot"), None) if same else (None, CER_NAME_TAKEN)
        if self.name_taken(char["name"], key):
            return None, CER_NAME_TAKEN
        used = {c.get("slot") for c in chars}
        for slot in range(MAX_SLOTS):
            if slot not in used:
                chars.append(dict(char, slot=slot))
                self.save()
                return slot, None
        return None, None

    def assign_content_id(self, uid, slot, ids):
        """2026-10-05: give the character in `slot` a Content ID from `ids`
        (the member's code-10 ids, in POL order): the first one no character
        in the whole store holds. A character that already has one keeps it
        (an id never moves: every store row is keyed on it). Returns the id,
        or 0 when the slot is empty or no id is free."""
        key = self._key(uid)
        char = next((c for c in self.data.get(key, []) if c.get("slot") == slot), None)
        if char is None:
            return 0
        have = content_id_of(char)
        if have:
            return have
        held = {content_id_of(c) for cs in self.data.values() for c in (cs or ())}
        for raw in ids or ():
            try:
                v = int(raw)
            except (TypeError, ValueError):
                continue
            if 0 < v < CONTENT_ID_MAX and v not in held:
                char["cid"] = v
                self.save()
                return v
        return 0

    def content_ids_held(self):
        """How many characters carry a Content ID (the startup line)."""
        return sum(1 for cs in self.data.values() for c in (cs or ())
                   if content_id_of(c))

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
#: prod runs host networking, so peer_ip is the real client address. The rows
#: are read through OpenLobby's accounts.sessions_by_ip().
class AccountResolver:
    """The store key for a client address: its POL member, remembered.

    Order, and why each step exists:
      1. the freshest POL `session` row at the address inside WINDOW. Several
         members at one address (a PC with the Windows viewer AND PCSX2 signed
         in) -> the one that already owns DoC characters; if that does not
         separate them, the freshest, logged AMBIGUOUS and not remembered;
      2. the member last resolved at that address (`memory`, the
         doc_ip_member table). POL purges session rows an hour after they are
         made, on every login, and the doc container is recreated far more
         often than a player signs in;
      3. `addr:<ip>` -- per machine, NEVER one shared bucket.
    Never raises: a database fault falls through to 2/3 and is logged.

    `connect` opens a connection to the account database (default
    accounts.connect); `memory` is docdb.store("ip_members").
    """
    WINDOW = 24 * 3600

    def __init__(self, memory, store=None, window=None, connect=None):
        if isinstance(memory, str):
            raise TypeError("AccountResolver takes docdb.store('ip_members'), "
                            "not a file path")
        self.memory = memory
        self.store = store
        self.window = self.WINDOW if window is None else window
        self.connect = connect or (lambda: docdb.accounts().connect())

    def _memory(self):
        try:
            m = self.memory.load()
            return m if isinstance(m, dict) else {}
        except docdb.errors() as e:
            print("[chara] WARN could not read the remembered members (%r)" % (e,),
                  flush=True)
            return {}

    def _remember(self, ip, key):
        m = self._memory()
        if (m.get(ip) or {}).get("key") == key:
            return
        m[ip] = {"key": key, "at": _utcnow_str()}
        if not self.memory.save(m):
            print("[chara] WARN could not remember %s -> %s" % (ip, key),
                  flush=True)

    def _sessions(self, ip):
        conn = self.connect()
        try:
            rows = docdb.accounts().sessions_by_ip(conn, ip, self.window, 32)
        finally:
            conn.close()
        seen = {}
        for mid, nick, at in rows:
            seen.setdefault(mid, (mid, nick, at))
        return list(seen.values())

    def resolve(self, ip):
        try:
            cands = self._sessions(ip)
        except Exception as e:                  # noqa: BLE001 -- see docstring
            print("[chara] WARN POL member lookup for %s failed (%r; %s) -- "
                  "falling back" % (ip, e, docdb.where()), flush=True)
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


def _cli(argv):
    """python doc_charastore.py --show
    python doc_charastore.py --adopt <uid-key> --account <key>

    Both work on the doc_character table of the database POL_DATABASE_URL
    names."""
    def _opt(name):
        i = argv.index(name)
        return argv[i + 1]
    if "--show" in argv:
        for k, v in sorted(CharaStore(docdb.store("characters")).data.items()):
            print("%-14s %s" % (k, [(ch.get("slot"), ch.get("name")) for ch in v]))
        return 0
    st = CharaStore(docdb.store("characters"))   # NO account yet: no auto-adopt
    st.account = _opt("--account")
    st.adopt(_opt("--adopt"))
    print("adopted %s -> %s: %s (source kept)" % (
        _opt("--adopt"), st.account,
        [ch.get("name") for ch in st.data[st.account]]))
    return 0


def _selftest():
    import docpg
    docpg.need_database("doc_charastore")
    table = docdb.store("characters")

    def fresh():
        """What deleting the store file was: an empty table."""
        table.clear()

    def S(account=None):
        """A new store object, reading the table afresh (a reload)."""
        return CharaStore(docdb.store("characters"), account=account)

    fresh()
    st = S()
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
    st2 = S()                              # reloads from the database
    r = st2.roster(uid)
    assert r[0]["name"] == "Zackary" and r[1]["name"] == "Vince" and r[2] is None
    assert st2.delete(uid, 0) is True
    assert S().roster(uid)[0] is None
    fresh()
    # a file path is not a store any more: refused, not silently ignored
    try:
        CharaStore("doc-characters.json")
        raise AssertionError("a path must be refused")
    except TypeError:
        pass
    # memory only (no store): works, and nothing reaches the table
    mem_only = CharaStore(None)
    assert mem_only.add(uid, c) == 0 and table.count() == 0

    # --- THE ACCOUNT KEY (2026-09-12). Each case is the prod failure or the
    # hazard its fix could introduce. ------------------------------------------
    # 1. The bug: uid keying splits one player's roster when the uid rotates.
    st = S()
    st.add(0xA756A69A, dict(c, name="Lex"))
    assert S().roster(0xA455A599)[0] is None, \
        "control: under uid keying a new session uid sees an EMPTY roster"
    fresh()
    # 2. The fix: under an account, both session uids see the same roster.
    st = S(account="member:3")
    st.add(0xA756A69A, dict(c, name="Lex"))
    again = S(account="member:3")
    assert again.roster(0xA455A599)[0]["name"] == "Lex", \
        "a rotated uid must see the roster the previous session made"
    fresh()
    # 3. Adoption: exactly ONE leftover uid roster -> carried over, kept as backup.
    S().add(0xA455A599, dict(c, name="Lex"))
    st = S(account="member:3")
    assert st.roster(0)[0]["name"] == "Lex", "the single uid roster is adopted"
    assert "0xa455a599" in st.data, "the source is NOT deleted"
    assert "0xa455a599" in S().data, "...in the database either"
    fresh()
    # 4. The hazard: SEVERAL uid rosters (prod's actual state) -> adopt NONE.
    base = S()
    base.add(0xA455A599, dict(c, name="Lex"))
    base.add(0xA455A599, dict(c, name="Test"))
    base.add(0xA756A69A, dict(c, name="Lex"))
    st = S(account="member:3")
    assert "member:3" not in st.data, \
        "two uid rosters must not be merged or picked between by guesswork"
    # ...and the explicit adopt settles it, non-destructively.
    st.adopt("0xa455a599")
    names = [s["name"] for s in S(account="member:3").roster(0) if s]
    assert names == ["Lex", "Test"], names
    assert "0xa756a69a" in S().data, "the other roster survives"
    fresh()
    # 5. No account = the old behaviour exactly (the emulator, dev runs).
    assert S()._key(0xA455A599) == "0xa455a599"
    fresh()
    # --- sec 4ft: PER-CLIENT keying by the POL member at the address. -------
    # The session rows are the core's own, made the way its login makes them.
    acc = docdb.accounts()
    conn = acc.connect()
    acc.create_polid(conn, "DOCTEST01", "pw-doctest")
    m_pc = acc.add_member(conn, "DOCTEST01", "doctest-pc", "pw-doctest")
    m_deck = acc.add_member(conn, "DOCTEST01", "doctest-deck", "pw-doctest")
    m_viewer = acc.add_member(conn, "DOCTEST01", "doctest-viewer", "pw-doctest")
    acc.open_session(conn, m_pc, nick="PCSX2", peer_ip="192.0.2.1")
    acc.open_session(conn, m_deck, nick="DECK", peer_ip="192.0.2.2")
    k_pc_want, k_deck_want = "member:%d" % m_pc, "member:%d" % m_deck
    memory = docdb.store("ip_members")
    memory.clear()
    st = S()
    rs = AccountResolver(memory, st)
    # 1. The 09-13 bug: two machines, two members, two rosters -- and the
    #    Deck's delete must not touch the PC's characters.
    k_pc, k_deck = rs.resolve("192.0.2.1"), rs.resolve("192.0.2.2")
    assert (k_pc, k_deck) == (k_pc_want, k_deck_want), (k_pc, k_deck)
    st.add(k_pc, dict(c, name="Lex"))
    st.add(k_pc, dict(c, name="Test"))
    st.add(k_deck, dict(c, name="Deck"))
    assert st.delete(k_deck, 0) is True
    names = [s["name"] for s in S().roster(k_pc_want) if s]
    assert names == ["Lex", "Test"], names
    # 2. POL purged the rows: the remembered member still resolves.
    for m in (m_pc, m_deck):
        acc.close_sessions(conn, m)
    assert acc.sessions_by_ip(conn, "192.0.2.1", 3600) == []
    assert (AccountResolver(docdb.store("ip_members"), st).resolve("192.0.2.1")
            == k_pc_want)
    # 3. Unknown address, nothing remembered: its own key, never a shared one.
    assert (AccountResolver(docdb.store("ip_members"), st).resolve("192.0.2.99")
            == "addr:192.0.2.99")
    # 4. Two members at one address (Windows viewer + PCSX2): the one that
    #    owns DoC characters wins, even though the other row is fresher.
    now = _utcnow_str()
    old_tok = acc.open_session(conn, m_pc, nick="PCSX2", peer_ip="192.0.2.1")
    acc.open_session(conn, m_pc, nick="PCSX2", peer_ip="192.0.2.1")
    new_tok = acc.open_session(conn, m_viewer, nick="VIEWER", peer_ip="192.0.2.1")
    # fixture only: the rows' ages, which open_session always stamps "now"
    conn.execute("UPDATE session SET created_at = %s WHERE token = %s",
                 ("2026-01-01T00:00:00Z", old_tok))
    conn.execute("UPDATE session SET created_at = %s WHERE token = %s",
                 (now + "~", new_tok))
    conn.commit()
    docdb.store("ip_members").clear()      # the roster decides, not memory
    assert (AccountResolver(docdb.store("ip_members"), st).resolve("192.0.2.1")
            == k_pc_want)
    # 5. A database that cannot be reached must not raise -- memory answers.
    def broken():
        raise docdb.db.OperationalError("the account database is down")
    assert (AccountResolver(docdb.store("ip_members"), st, connect=broken)
            .resolve("192.0.2.1") == k_pc_want)
    # 6. A resolved key passes through _key(); an int uid keys as before.
    assert S(account="member:3")._key("member:6") == "member:6"
    assert S()._key(0xA455A599) == "0xa455a599"
    # 7. 2026-10-01: SE's name rules (kelerr.bin 42310 / 42311 / 45201).
    assert name_error("Vincent") is None and name_error("A-1_b") is None
    assert name_error("Vi") == CER_NAME_LENGTH
    assert name_error("V" * 16) == CER_NAME_LENGTH
    for bad in ("-Vin", "Vin_", "Vi--n", "Vi-_n", "Vi n", "Vin!", "Vin\xe9"):
        assert name_error(bad) == CER_NAME_CHARS, bad
    fresh()
    ra, rb = S(account="member:1"), None
    ca = dict(name="Shalua", gender=1, app92=0x11, app93=0x01, voice=2)
    assert ra.register("member:1", ca) == (0, None)
    assert ra.register("member:1", dict(ca)) == (0, None)     # a retransmit
    assert ra.register("member:1", dict(ca, voice=4)) == (None, CER_NAME_TAKEN)
    assert ra.roster("member:1")[0]["voice"] == 2              # not overwritten
    rb = S(account="member:2")
    assert rb.register("member:2", dict(ca, name="shalua")) == (None, CER_NAME_TAKEN)
    assert rb.register("member:2", dict(ca, name="Shelke")) == (0, None)
    assert rb.register("member:2", dict(ca, name="X")) == (None, CER_NAME_LENGTH)
    conn.close()
    fresh()
    docdb.store("ip_members").clear()
    print("doc_charastore self-test PASS")
    return 0


if __name__ == "__main__":
    if "--adopt" in sys.argv or "--show" in sys.argv:
        sys.exit(_cli(sys.argv[1:]))
    sys.exit(_selftest())
