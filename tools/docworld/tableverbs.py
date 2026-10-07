"""The battletable store and the console's table verbs: create, config, join, reserve, cancel, dissolve, invite."""
import struct
from . import advertise, battleroom, framing, tablerecords, worlddoor



# --- the BATTLETABLE CONSOLE VERBS and their STORE (sec 4dz) ------------------
# Read off the lobby phase table (an offline run of the client's own code (doc_phaseflow)) joined with the
# arm map: every console verb is a request phase that sends ONE selector and
# parks [kelsvc+12]; the poll phase after it needs the answer's arm to put the
# state back to 2.  The verbs, by the KelStr group-39 line each phase prints:
#
#   phase 38  sel 24 -> 25  CREATE TABLE      request body[12..131] = the 120-byte
#                           record (0x00bd1688 packs it, key 0); arm 0x00bcb558
#                           (gate 10) reads the answer's record at body[12..131]:
#                           rec+24 -> [kelsvc+268] (the table id), rec+12/+20 ->
#                           the GAME SERVER ip/port via 0x00bc0320, rec+8 leader.
#   phase 36  sel 26 -> 27  TABLE CONFIG      body[12..13] = key; arm 0x00bcb740
#                           (gate 11) converts body[12..131] and copies rec+28
#                           member ids (u32, max 32) from body[132].
#   phase 40  sel 28 -> 29  ADJUST RULES      request carries the record like 24
#                           (0x00bd1808, key at rec+24); arm 0x00bcb7e0 (gate 12).
#   phase 42  sel 22 -> 23  PRE-RESERVE       36-byte, result -> [kelsvc+1064].
#   phase 44  sel 20 -> 21  JOIN (endpoint)   body[12..13] = key; 30 -> 31 is the
#                           same with the password at body[16..23].  On success
#                           phase 45 prints "You have reserved a spot at the
#                           battletable." and sets the phase to 0 -- the lobby
#                           machine ENDS there; what follows is server-driven
#                           (selector 38 / game-server msg 37 = battle ready).
#   phase 46  sel 155 -> 156  CANCEL          arm logs "Cancel %d", clears the
#                           reservation flag itself (0x00be33b0) when result >= 0.
#   phase 48  sel 151 -> 152  RESERVE BY ID   body[12..13] = key; the arm reads
#                           the answer's u16 at body[16] and hands it to
#                           0x00be3348 (sets the reserved flag + table id).
#             sel 153 -> 154  ...with password (body[16..23]); logs "Reserve With
#                           pass %d res %d".
#   phase 50  sel 125 -> 126  DISSOLVE        arm 0x00bcc240: peer lookup, then
#                           [kelsvc+266] = old id, [kelsvc+268] = 0xffff.
#   phase 52  sel 127 -> 128  INVITE          a1 = target character id; arm
#                           0x00bcd4a4 = state 2 + clear pending, nothing else.
#   phases 54/56 KICK / APPOINT LEADER ride the COMMAND channel (240 -> 241,
#                           commands 2 and 1, target id at body[16..19]).
#
# Everything below is proven against the client's own arms in the emulator
# (an offline run of the client's own code (doc_bt_verbs_proof)), NOT on hardware.  The record layout is the
# browser's (BT_OFF_*); rec+12..15 / rec+20..21 are the game-server endpoint
# the create arm hands to 0x00bc0320 (bytes in order / big-endian port, the
# same encoding build_world_answer uses at body[52..57]).
#: 2026-10-06: the situation an INDIVIDUAL (BT) table loads: mdlResLoad
#: 1000..1098 = Res_bt1 (arenadata.BT_SITUATION)
BT_SITUATION_INDIVIDUAL = 1000
BT_REQ_CREATE = 24
BT_REQ_CONFIG = 26
BT_REQ_UPDATE = 28
BT_REQ_PREPARE = 22
BT_REQ_JOIN = 20
BT_REQ_JOIN_PW = 30
BT_REQ_RESERVE = 151
BT_REQ_RESERVE_PW = 153
BT_REQ_CANCEL = 155
BT_REQ_DISSOLVE = 125
# KEY: 2026-09-23 (retail build, doc_reservation_clear_proof.py): the push that
# actually CLEARS the client's reservation. Demux 0x00bd3978 case 110
# (0x00bd4494): record+4 == [kelsvc+272] -> 0x00be5d58 = R+756 (what
# getMyReservationTableId() returns) = 0xffff, R+0x2fa &= ~1 (the held bit),
# kelsvc+0x10c = 0xffff, and the reserved table's member list emptied. The
# selector-156 CLEAR sent since 09-13/09-22 touches none of that on this build
# (row 51) -- live it was sent twice and the "!!na!!" table stayed.
BT_RESERVATION_CLEAR_SEL = 110
BT_REQ_INVITE = 127
BT_VERB_REQS = (BT_REQ_CREATE, BT_REQ_CONFIG, BT_REQ_UPDATE, BT_REQ_RESERVE,
                BT_REQ_RESERVE_PW, BT_REQ_CANCEL, BT_REQ_DISSOLVE, BT_REQ_INVITE)
BT_JOIN_REQS = (BT_REQ_JOIN, BT_REQ_JOIN_PW)
BT_OFF_GS_IP = 12          # u32, bytes in address order -> 0x00bc0320 a1
BT_OFF_GS_PORT = 20        # u16 big-endian              -> 0x00bc0320 a2
BT_REQ_REC_OFF = 12        # where 0x00bd1688 / 0x00bd1808 put the record
BT_MEMBERS_OFF = 132       # u32 member ids in a selector-27 answer (a3+156)
BT_MAX_MEMBERS = 32        # 0x00bcb740 clamps the count here
BT_PASSWORD_OFF = 16       # 8 bytes, requests 30 and 153 (0x00bcda28)


class BattletableStore:
    """Every battletable the lobby knows about, keyed by the u16 at rec+24."""

    def __init__(self, records=(), gs_ip=None, gs_port=0, cur_min=0,
                 situation=0):
        self.tables = {}          # key -> dict(rec, members, leader, password)
        self.reservation = {}     # character id -> key
        self.next_key = 1
        self.gs_ip = gs_ip
        self.gs_port = gs_port
        # sec 4ex (2026-09-11): floor for the served CURRENT-participants field
        # (BT_OFF_CUR). The "Start Immediately" gate 0x00aa0d98 passes iff the
        # SERVED browser-list record has [config+2]=BT_OFF_CUR >= 2 (limit live)
        # OR flags bit 0x00010000 (Mission). A solo leader's table has 1 member
        # -> cur 1 -> 0x683b "victory not configured". cur_min=2 clamps the
        # SERVED cur to satisfy the gate (pairs with --gs-fake-teammates for the
        # real battle roster). Does not change reserve/seating logic.
        self.cur_min = cur_min
        # sec 4gc: the battle situation id stamped into a record that left
        # wire +34 at 0 (every client CREATE does) -> mdlResLoad's set.
        self.situation = situation
        # 2026-09-24: {quest: seconds} -- a MISSION record's time limit (the
        # HUD countdown the client reads off the served record), set by main()
        # from doc_missions.MISSION_TIME; `time_unit` = --bt-time-unit
        self.mission_time = {}
        self.time_unit = 1.0
        # 2026-10-04: {quest: roster map index} and {quest: max players} -- a
        # MISSION record's Map and "%d/%d" cap as the list and the join gate
        # read them. The client's CREATE leaves its own create-screen values
        # there (map 0 = Jungle, max 12), so Dual Horn Duel was listed as a
        # 12-player Jungle table while it is played in the Wastelands for 3.
        # Set by main() from the quest's zone and doc_missions.MAX_PLAYERS.
        self.mission_map = {}
        self.mission_max = {}
        # 2026-10-05: {quest: situation} -- the mission's situation at wire+34
        # in the record itself, so EVERY member's selector 38 carries it. Only
        # the leader's 38 got the quest rewrite; the others' record said
        # --bt-situation 1100, loaded the PvP model set (o099 only) and could
        # draw no enemy whatever type was sent.
        self.mission_situation = {}
        # 2026-10-05: {quest: Base Durability} for a BASE mission -- wire+16
        # nonzero is what makes the client create its base gimmick at all
        # (doc_missions.MISSION_BASES). Every other mission keeps 0, or its
        # situation's base would appear in a kill mission.
        self.mission_base_hp = {}
        # 2026-10-06: (record, individual) -> the PvP situation for the
        # record's arena, or None for the default (the server sets it:
        # arenadata.situation_for through its map -> zone table)
        self.situation_for = None
        for r in records:
            self.add_record(r)

    # -- records -------------------------------------------------------------
    def _stamp(self, t):
        rec = t["rec"]
        # a MISSION table passes the start gate on its flag, so it needs no
        # cur_min clamp (a solo quest table read "2/0" with it).
        _floor = (0 if struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0]
                  & tablerecords.BT_FLAG_MISSION else self.cur_min)
        struct.pack_into("<H", rec, tablerecords.BT_OFF_CUR,
                         max(len(t["members"]), _floor) & 0xFFFF)
        struct.pack_into("<I", rec, tablerecords.BT_OFF_LEADER, t["leader"] & 0xFFFFFFFF)
        # sec 4he: wire+30 bit 0 = "In Progress" (the row renderer prints
        # group 28 [80] instead of the count). Set for the life of the
        # table's BattleRoom, never before -- nothing on a live path set it.
        rec[tablerecords.BT_OFF_STATE] = ((rec[tablerecords.BT_OFF_STATE] & ~1)
                             | (1 if t.get("in_progress") else 0)) & 0xFF
        if (struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0] & tablerecords.BT_FLAG_MISSION
                and self.mission_time and self.time_unit > 0):
            _q = struct.unpack_from("<H", rec, tablerecords.BT_OFF_MISSION)[0]
            if _q in self.mission_time:
                struct.pack_into("<I", rec, tablerecords.BT_OFF_TIME,
                                 int(round(self.mission_time[_q] / self.time_unit)))
        if struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0] & tablerecords.BT_FLAG_MISSION:
            _q = struct.unpack_from("<H", rec, tablerecords.BT_OFF_MISSION)[0]
            if _q in self.mission_map:
                rec[tablerecords.BT_OFF_MAP] = self.mission_map[_q] & 0xFF
            if _q in self.mission_max:
                rec[tablerecords.BT_OFF_MAX] = self.mission_max[_q] & 0xFF
            if _q in self.mission_situation:
                struct.pack_into("<H", rec, tablerecords.BT_OFF_SITUATION,
                                 self.mission_situation[_q] & 0xFFFF)
            struct.pack_into("<I", rec, tablerecords.BT_OFF_BASE_HP,
                             self.mission_base_hp.get(_q, 0) & 0xFFFFFFFF)
        if self.situation and (t.get("auto_sit") or not struct.unpack_from(
                "<H", rec, tablerecords.BT_OFF_SITUATION)[0]):
            # 2026-10-06 (live, Train Graveyard BT / Kalm TBT "jail"): an
            # individual table takes the BT set (1000 = Res_bt1), and a
            # situation the arena lacks made the client build every fence
            # (arenadata.situation_for), so the arena picks: 1000 / 1100 or
            # its 9000 / 9100. Re-picked on every stamp -- the leader can
            # change the map after the CREATE.
            _ind = bool(struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0]
                        & tablerecords.BT_FLAG_INDIVIDUAL)
            _sit = BT_SITUATION_INDIVIDUAL if _ind else self.situation
            if self.situation_for is not None:
                _sit = self.situation_for(rec, _ind) or _sit
            struct.pack_into("<H", rec, tablerecords.BT_OFF_SITUATION, _sit & 0xFFFF)
            t["auto_sit"] = True
        if self.gs_ip:
            rec[BT_OFF_GS_IP:BT_OFF_GS_IP + 4] = bytes(
                int(x) for x in self.gs_ip.split("."))
            struct.pack_into(">H", rec, BT_OFF_GS_PORT, self.gs_port & 0xFFFF)
        return rec

    def add_record(self, rec, members=(), leader=None, password=b""):
        rec = bytearray(bytes(rec[:tablerecords.BT_REC_LEN]).ljust(tablerecords.BT_REC_LEN, b"\x00"))
        key = struct.unpack_from("<H", rec, tablerecords.BT_OFF_ID)[0]
        if key == 0 or key in self.tables:
            while self.next_key in self.tables or self.next_key == 0:
                self.next_key = (self.next_key + 1) & 0xFFFF
            key = self.next_key
            struct.pack_into("<H", rec, tablerecords.BT_OFF_ID, key)
        self.next_key = max(self.next_key, (key + 1) & 0xFFFF) or 1
        if leader is None:
            leader = struct.unpack_from("<I", rec, tablerecords.BT_OFF_LEADER)[0]
        t = dict(rec=rec, members=list(members), leader=leader,
                 password=bytes(password or b""), leader_cid=0,
                 in_progress=False)
        self.tables[key] = t
        self._stamp(t)
        return key

    def records(self):
        return [bytes(self._stamp(t)) for _, t in sorted(self.tables.items())]

    def get(self, key):
        return self.tables.get(key)

    def record(self, key):
        t = self.tables.get(key)
        return bytes(self._stamp(t)) if t else None

    def members(self, key):
        t = self.tables.get(key)
        return list(t["members"]) if t else []

    def table_of(self, ident):
        return self.reservation.get(ident)

    def in_progress(self, key):
        t = self.tables.get(key)
        return bool(t and t.get("in_progress"))

    def set_in_progress(self, key, flag):
        """sec 4he: a table whose BattleRoom is open is In Progress: the
        browser row says so and reserve() refuses new seats (-4)."""
        t = self.tables.get(key)
        if t is None:
            return False
        t["in_progress"] = bool(flag)
        self._stamp(t)
        return True

    def leader_cid(self, key):
        t = self.tables.get(key)
        return (t or {}).get("leader_cid") or 0

    def is_leader(self, key, ident, uid=0):
        """sec 4he: leader authority. The record's leader field is the
        creator's UID (the row resolves a name through the profile cache);
        the creator's CHARACTER id is kept beside it, so a member's own
        Dissolve / Kick / Appoint can be refused by either identity."""
        t = self.tables.get(key)
        if t is None:
            return False
        if not t.get("leader_cid") and not t["leader"]:
            return True                  # a table nobody owns (probe rows)
        if ident and t.get("leader_cid") == ident:
            return True
        return bool(uid and t["leader"] == uid)

    def vacate(self, ident):
        """A session that is GONE (reaped, or a fresh entrance under the same
        id): its seat goes with it. Same as CANCEL, without the answer."""
        return self.cancel(ident)

    # -- verbs ---------------------------------------------------------------
    def create(self, wire_rec, ident, leader_uid, password=b""):
        """Selector 24: the client's own record, keyed by us; the creator is
        its first member and its leader."""
        if self.reservation.get(ident) is not None:
            self.cancel(ident)
        key = self.add_record(wire_rec, members=[ident] if ident else [],
                              leader=leader_uid,
                              password=password or battleroom.record_password(wire_rec))
        self.tables[key]["leader_cid"] = ident or 0
        if ident:
            self.reservation[ident] = key
        return key

    def update(self, key, wire_rec, ident=None, uid=0):
        """Selector 28: take the client's rule fields, keep what we own.
        2026-10-01, manual p.29: "Adjust Rules" is the LEADER's command, so a
        member's request (by either identity, as is_leader) is refused, and so
        is any change while the battle runs or one whose maximum is below the
        players already seated."""
        t = self.tables.get(key)
        if t is None:
            return False
        if ident and not self.is_leader(key, ident, uid):
            return False
        if t.get("in_progress"):
            return False
        mx = bytes(wire_rec[:tablerecords.BT_REC_LEN]).ljust(
            tablerecords.BT_REC_LEN, b"\x00")[tablerecords.BT_OFF_MAX]
        if mx and mx < len(t["members"]):
            return False
        new = bytearray(bytes(wire_rec[:tablerecords.BT_REC_LEN]).ljust(tablerecords.BT_REC_LEN, b"\x00"))
        keep = bytes(t["rec"])
        new[tablerecords.BT_OFF_LEADER:tablerecords.BT_OFF_LEADER + 4] = keep[tablerecords.BT_OFF_LEADER:tablerecords.BT_OFF_LEADER + 4]
        new[BT_OFF_GS_IP:BT_OFF_GS_IP + 4] = keep[BT_OFF_GS_IP:BT_OFF_GS_IP + 4]
        new[BT_OFF_GS_PORT:BT_OFF_GS_PORT + 2] = keep[BT_OFF_GS_PORT:BT_OFF_GS_PORT + 2]
        struct.pack_into("<H", new, tablerecords.BT_OFF_ID, key)
        t["rec"] = new
        t["password"] = battleroom.record_password(new)
        self._stamp(t)
        return True

    def reserve(self, key, ident, password=None, rp=None):
        """Selectors 20/30/151/153: seat `ident` at `key`.  Returns
        (result, key): 0 = seated, -1 = no such table, -2 = wrong password,
        -3 = full, -4 = in progress (sec 4he: a battle is running on it; a
        late seat used to block the distribution for everyone inside),
        BT_REFUSE_RP = the joiner's rank points `rp` are outside the table's
        Min/Max RP (rp_allowed; None = not checked). A member already seated
        is never re-checked."""
        t = self.tables.get(key)
        if t is None:
            return -1, key
        if t.get("in_progress") and ident not in t["members"]:
            return -4, key
        if t["password"] and password is not None and \
                bytes(password).rstrip(b"\x00") != t["password"].rstrip(b"\x00"):
            return -2, key
        if (rp is not None and ident not in t["members"]
                and not battleroom.rp_allowed(t["rec"], rp)[0]):
            return battleroom.BT_REFUSE_RP, key
        mx = t["rec"][tablerecords.BT_OFF_MAX] or BT_MAX_MEMBERS
        if ident and ident not in t["members"]:
            if len(t["members"]) >= min(mx, BT_MAX_MEMBERS):
                return -3, key
            old = self.reservation.get(ident)
            if old is not None and old != key:
                self.cancel(ident)
            t["members"].append(ident)
        if ident:
            self.reservation[ident] = key
        self._stamp(t)
        return 0, key

    def cancel(self, ident):
        """Selector 155: leave whatever table `ident` is seated at."""
        key = self.reservation.pop(ident, None)
        t = self.tables.get(key) if key is not None else None
        if t is not None:
            if ident in t["members"]:
                t["members"].remove(ident)
            if not t["members"]:
                del self.tables[key]
            else:
                if (t.get("leader_cid") == ident or t["leader"] in (0, ident)):
                    # 2026-10-01: the row's Leader column is t["leader"] (the
                    # creator's id as create() was given it: the charid when
                    # one is known, as appoint() writes too). Moving only
                    # leader_cid left the departed player named as leader.
                    t["leader_cid"] = t["members"][0]
                    t["leader"] = t["members"][0]
                self._stamp(t)
        return key

    def dissolve(self, key, ident=None, uid=0, force=False):
        """Selector 125: the LEADER tears the table down. With an ident that
        is not the leader's (and not `force`) nothing happens (sec 4he: a
        member's own Dissolve used to take the leader's table down)."""
        t = self.tables.get(key)
        if t is None:
            return False
        if ident and not force and not self.is_leader(key, ident, uid):
            return False
        t = self.tables.pop(key, None)
        for m in t["members"]:
            if self.reservation.get(m) == key:
                del self.reservation[m]
        return True

    def kick(self, key, target, ident=None, uid=0):
        t = self.tables.get(key)
        if t is None or target not in t["members"]:
            return False
        if ident and not self.is_leader(key, ident, uid):
            return False
        t["members"].remove(target)
        self.reservation.pop(target, None)
        self._stamp(t)
        return True

    def appoint(self, key, target, ident=None, uid=0):
        t = self.tables.get(key)
        if t is None or target not in t["members"]:
            return False
        if ident and not self.is_leader(key, ident, uid):
            return False
        t["leader_cid"] = target
        t["leader"] = target
        self._stamp(t)
        return True


def build_battletable_verb_answer(req, selector, rec, members=(), seq=0,
                                  subchannel=7, ptype=127, mode_byte=0,
                                  ident=None, result=0, pad_to=176,
                                  peer_ip=None, default_gs_ip=None):
    """A selector-25 / 27 / 29 answer: the 120-byte record at body[12..131]
    (rec+24 = the key, so the u32 at body[12] is the record's flags word, NOT a
    result -- these arms never read one), member ids from body[132].

    The record's rec+28 is BOTH the participant count the browser prints and
    the member-list count 0x00bcb740 copies from body[136] (clamped to 32), so
    it is rewritten here from the list we actually send -- a count over bytes
    we did not write is the sec 4bo wild-write class.
    """
    # WARNING:KEY: sec 4gv addendum (2026-09-23): THE RECORD IS A SECOND WRITER OF THE
    # CLIENT'S GAME-SERVER ENDPOINT, so it must be rewritten per recipient the
    # way the list and selector-38 paths already are. rec+12/+20 feed
    # 0x00bc0320(chan, ip, port), and 0x00bc0320 is the SOLE writer of
    # [chan+184..191] -- the same sockaddr selector 104's arm installs through
    # it (0x00bca938 tail) and the same one the client's keepalive sender reads
    # back at [chan+186]/[chan+188] (JP 0x00bc0c18 -> record +0x14c/+0x150).
    # BattletableStore._stamp writes the RAW --lobby-ip into every record, so
    # every verb answer served from here overwrote whatever 104 had just
    # declared. Only the LEADER runs these verbs, which is exactly why the
    # leader's game-server channel goes dead at a table where the joiner's
    # works.
    # WARNING: only a record that ALREADY carries an endpoint: the "table gone" answer
    # is a deliberately ALL-ZERO record (see BT_REQ_CONFIG below) and writing an
    # address into it would stop it being one.
    if (peer_ip and default_gs_ip and len(rec) >= BT_OFF_GS_IP + 4
            and any(rec[BT_OFF_GS_IP:BT_OFF_GS_IP + 4])):
        rec = advertise.rec_for(rec, default_gs_ip, peer_ip)
    mem = [int(m) & 0xFFFFFFFF for m in list(members)[:BT_MAX_MEMBERS]]
    body = bytearray(max(pad_to, BT_MEMBERS_OFF + 4 * len(mem)))
    body[0] = subchannel & 0xFF
    body[1] = selector & 0xFF
    struct.pack_into("<H", body, 4, 0)                 # failure flag clear
    R = tablerecords.BATTLETABLE_REC_OFF
    body[R:R + tablerecords.BT_REC_LEN] = bytes(rec[:tablerecords.BT_REC_LEN]).ljust(tablerecords.BT_REC_LEN, b"\x00")
    if result < 0:
        # a failure: no record to file. [kelsvc+24] (what the dispatcher takes
        # from body[12]) goes negative and the handlers bail on it.
        body[R:R + tablerecords.BT_REC_LEN] = bytes(tablerecords.BT_REC_LEN)
        struct.pack_into("<i", body, 12, result)
    struct.pack_into("<H", body, R + tablerecords.BT_OFF_CUR, len(mem))
    for i, m in enumerate(mem):
        struct.pack_into("<I", body, BT_MEMBERS_OFF + 4 * i, m)

    mid = bytearray(16)
    mid[0] = ptype & 0xFF
    struct.pack_into("<H", mid, 6, seq & 0xFFFF)
    if ident is None and req is not None and len(req) >= 20:
        ident = struct.unpack_from("<I", req, 16)[0]
    struct.pack_into("<I", mid, 8, (ident or 0) & 0xFFFFFFFF)

    pkt = bytearray([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", framing.HDR_LEN + len(body))
    pkt += struct.pack("<I", framing.now_ms() & 0xFFFF)
    pkt += mid + body
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(pkt))
    return bytes(pkt)


#: 2026-10-01: the BATTLETABLE INVITATION push (selector 129, arm 0x00bd4524
#: -> 0x00bd3500, no state gate; MEASURED on the retail lobby state by an
#: offline run of the client's own code, re-invites/doc_invite_proof.py).
#: Header ident = the INVITER's character id (the "%s" of 39:11); body[12..13]
#: u16 the table; body[14..21] 8 bytes kept verbatim and later pre-filled
#: into the password dialog when the invitee picks it (the table password,
#: NUL padded; zeros for an open table). The client ignores an invite to its
#: own reservation and a repeat of one it holds, keeps 20 (oldest dropped),
#: and filters the ordinary 16 -> 17 list down to the invited tables for its
#: "Show Invitation List" -- there is no list to serve.
BT_PUSH_INVITE = 129
INVITE_PUSH_LEN = 64
#: request 127's body[12] when the invitation goes to a whole group (phase 49,
#: "Send All Battletable Invitation"); body[16..23] then names the group
INVITE_ALL = 0xFFFFFFFF


def build_invite_push(table_key, password=b"", subchannel=7):
    b = bytearray(INVITE_PUSH_LEN)
    b[0] = subchannel & 0xFF
    b[1] = BT_PUSH_INVITE
    struct.pack_into("<H", b, 12, table_key & 0xFFFF)
    b[14:22] = bytes(password or b"")[:8].ljust(8, b"\x00")
    return bytes(b)


def invite_targets(store, inviter, target, online):
    """(table key, [character ids to push 129 to]) for request 127 from
    `inviter` naming `target`. Manual p.27: only a player holding a
    reservation can invite, so no table = nobody. The target must be online
    (`online` = live character ids) and not already seated at that table; an
    invitation never goes back to its sender."""
    key = store.table_of(inviter) if inviter else None
    if key is None:
        return None, []
    seated = set(store.members(key))
    if target in (0, INVITE_ALL) or target == inviter or target in seated:
        return key, []
    return key, [target] if target in online else []


def build_reserve_echo(req, key, seq=0, subchannel=7, ptype=127, pad_to=176,
                       ident=None):
    """sec 4fl (2026-09-12): the RESERVATION ECHO -- an unsolicited selector-152
    answer sent right AFTER a CREATE-ok (25) or a successful JOIN-ok (21).

    The "Start Immediately" status (0x00AA55A0 case 7, 0x00aa5834) refuses with
    0x683b ("Conditions for victory are not configured") when sub->[1118] ==
    0xffff.  sub->[1118] is recomputed (0x00AA19E8) from getVictoryCond
    0x00AD5F50 -> store method 0x00bd36d0 (key == [kelsvc+272] -> SELF path
    0x00bdd960) -> copier 0x00be67e0 over the SELF record R = [0x00bf4530]+304:
    returns u16 R+2970 iff (u32 R+684) & 0x0004, else 0xffff.  The ONLY
    reachable setter of that pair is 0x00be3348, called from the selector-152/
    154 arm (0x00bcd6b0): `if body[12] (s32) >= 0: R+2970 = u16 body[16];
    R+684 |= 4` (the ori at 0x00be3378 is in a branch DELAY SLOT).  The CREATE-
    ok processor (0x00bcb638) and the JOIN-ok processor (0x00bca9cc) both call
    the CLEAR 0x00be33b0 unconditionally, so the echo must trail the 25/21.

    A leader who CREATEs a table never sends 151 for it (live logs 09-12: only
    24/26/28), so without this echo they never hold a reservation on their own
    table and Start Immediately is refused; on 09-11 a tester only got past
    it by RESERVING by hand.  body[12..15] = 0 (success), body[16..17] = key --
    exactly what battletable_verb answers a real 151 with.  SE's text for this
    state is misleading; the field is the reservation, not a victory type."""
    return worlddoor.build_world_answer(req, selector=BT_REQ_RESERVE + 1, result=0,
                              cmd_arg=key, seq=seq, subchannel=subchannel,
                              ptype=ptype, pad_to=pad_to, ident=ident)


def battletable_verb(store, req, body, req_sel, ident, uid, seq=0,
                     subchannel=7, ptype=127, pad_to=176, probe=False,
                     quest=None, peer_ip=None, default_gs_ip=None, rp=None):
    """Answer one console verb out of the store.  Returns (packet, note) or
    (None, note) when the verb is not ours to answer (unreadable body).  A
    config request for a table we do not hold answers result -1; `probe` is
    kept for callers but no longer used here (it painted a phantom table)."""
    kw = dict(seq=seq, subchannel=subchannel, ptype=ptype, ident=ident)
    # kw goes to build_world_answer too, which takes neither of these -- only
    # the RECORD answers rewrite the endpoint.
    kwrec = dict(kw, peer_ip=peer_ip, default_gs_ip=default_gs_ip)
    key = struct.unpack_from("<H", body, 12)[0] if len(body) >= 14 else 0
    if req_sel == BT_REQ_CREATE:
        if len(body) < BT_REQ_REC_OFF + tablerecords.BT_REC_LEN:
            return None, "create request body is %d bytes, need %d" % (
                len(body), BT_REQ_REC_OFF + tablerecords.BT_REC_LEN)
        wire = bytearray(body[BT_REQ_REC_OFF:BT_REQ_REC_OFF + tablerecords.BT_REC_LEN])
        # sec 4fe (LIVE 2026-09-12): the create screen's only offered type sends
        # MODE 0, which is not a real battle mode -- the config screen then shows
        # "Settings: !!na!!" and "Map: !!na!!" and Start Immediately silently
        # does nothing (every WORKING table on the wire is mode 1; measured over
        # PINE: served tables mode=1 render, the created mode=0 table does not).
        # Coerce an invalid mode-0 create to mode 1 (Battle) so the table is a
        # real, startable table. map 0 is fine (Jungle; served jungle table is
        # map 0 too) -- the differentiator was the mode, not the map.
        _mode_fix = wire[tablerecords.BT_OFF_MODE] == 0
        if _mode_fix:
            wire[tablerecords.BT_OFF_MODE] = 1
        # 2026-09-13: the LEADER is the creator's CHARID. The list row resolves
        # a name from it; the entrance uid is one value shared by every machine
        # (0xa756a69a) or a per-machine one the OTHER client never learns, so
        # a uid leader read as the wrong player, then as no name at all.
        # 2026-09-13 (live + static): a SOLO table = list kind 4 at wire+108
        # (the client's list filter 0x00aa2fc8 shows a row only where record
        # +52 == the window's kind). Its create carried flags|0x8, mission 0,
        # max 0 -> the row read "TBT 2/0 | !!na!!". Stamp it a MISSION: flags
        # 0x00010000 (the "MS" mode label + the start gate 0x00aa0d98), wire+26
        # = the quest the creator picked (the row's 3rd column = 0xBBFF+id),
        # max 1 if 0. _stamp skips the cur_min clamp for mission tables.
        _solo = wire[tablerecords.BT_OFF_UNK108] == 4
        if _solo:
            _fl = struct.unpack_from("<I", wire, tablerecords.BT_OFF_FLAGS)[0]
            struct.pack_into("<I", wire, tablerecords.BT_OFF_FLAGS,
                             _fl | tablerecords.BT_FLAG_MISSION | 0x8)
            if quest:
                struct.pack_into("<H", wire, tablerecords.BT_OFF_MISSION, quest & 0xFFFF)
            if wire[tablerecords.BT_OFF_MAX] == 0:
                wire[tablerecords.BT_OFF_MAX] = 1
        key = store.create(bytes(wire), ident, ident or uid)
        return (build_battletable_verb_answer(
                    req, BT_REQ_CREATE + 1, store.record(key),
                    store.members(key), pad_to=pad_to, **kwrec),
                "CREATE -> table %d (map %d, mode %d%s, max %d)%s for 0x%08x" % (
                    key, wire[tablerecords.BT_OFF_MAP], wire[tablerecords.BT_OFF_MODE],
                    " [coerced 0->1]" if _mode_fix else "",
                    wire[tablerecords.BT_OFF_MAX],
                    (" SOLO -> MISSION, quest %s" % quest) if _solo else "",
                    ident or 0))
    if req_sel == BT_REQ_CONFIG:
        rec = store.record(key)
        if rec is None:
            # 2026-09-13: a table that is GONE (dissolved, or a stale row the
            # client still holds) gets an ALL-ZERO record (key 0 = no table,
            # no flags, 0 members), never the sec 4do sentinel probe -- the
            # probe's values rendered as a stranger's password table ("Below
            # 3,881,520 RP", 0 players, 0 minutes) after the player
            # dissolved their own table 3. NOT result=-1: body[12] is the
            # record's FLAGS word here and the 27 arm 0x00bcb740 never treats
            # the answer as a failure (doc_phantom_table_proof.py, emulated) --
            # -1 would set every flag, the password bit included. The real
            # cure is the reservation CLEAR sent after a DISSOLVE-ok (main).
            return (build_battletable_verb_answer(
                        req, BT_REQ_CONFIG + 1, bytes(tablerecords.BT_REC_LEN), (),
                        pad_to=pad_to, **kwrec),
                    "CONFIG of unknown table %d -> empty record (table gone)" % key)
        return (build_battletable_verb_answer(
                    req, BT_REQ_CONFIG + 1, rec, store.members(key),
                    pad_to=pad_to, **kwrec),
                "CONFIG table %d, %d member(s)" % (key, len(store.members(key))))
    if req_sel == BT_REQ_UPDATE:
        if len(body) < BT_REQ_REC_OFF + tablerecords.BT_REC_LEN:
            return None, "update request body is %d bytes" % len(body)
        wire = body[BT_REQ_REC_OFF:BT_REQ_REC_OFF + tablerecords.BT_REC_LEN]
        key = struct.unpack_from("<H", wire, tablerecords.BT_OFF_ID)[0] or \
            store.table_of(ident) or 0
        ok = store.update(key, wire, ident, uid=uid or 0)
        rec = store.record(key) if ok else bytes(wire)
        return (build_battletable_verb_answer(
                    req, BT_REQ_UPDATE + 1, rec, store.members(key),
                    result=0 if ok else -1, pad_to=pad_to, **kwrec),
                "ADJUST RULES table %d%s" % (key, "" if ok else " (unknown)"))
    if req_sel in (BT_REQ_RESERVE, BT_REQ_RESERVE_PW):
        pw = (body[BT_PASSWORD_OFF:BT_PASSWORD_OFF + 8]
              if req_sel == BT_REQ_RESERVE_PW else None)
        res, key = store.reserve(key, ident, pw, rp=rp)
        return (worlddoor.build_world_answer(req, selector=req_sel + 1, result=res,
                                   cmd_arg=key, pad_to=pad_to, **kw),
                "RESERVE table %d -> %d%s" % (
                    key, res, " (with password)" if pw is not None else ""))
    if req_sel == BT_REQ_CANCEL:
        key = store.cancel(ident)
        return (worlddoor.build_world_answer(req, selector=req_sel + 1, result=0,
                                   pad_to=pad_to, **kw),
                "CANCEL -> left table %s" % key)
    if req_sel == BT_REQ_DISSOLVE:
        key = store.table_of(ident) or key
        ok = store.dissolve(key, ident, uid=uid or 0)
        return (worlddoor.build_world_answer(req, selector=req_sel + 1,
                                   result=0 if ok else -1, pad_to=pad_to, **kw),
                "DISSOLVE table %s -> %s" % (
                    key, "gone" if ok else
                    ("REFUSED, not the leader" if key in store.tables
                     else "unknown")))
    if req_sel == BT_REQ_INVITE:
        # 128's arm (0x00bd4600) reads nothing from the body and cannot report
        # a failure: a bare answer always. The invitee's 129 is pushed by the
        # world server (invite_targets / build_invite_push), which knows the
        # sessions.
        target = struct.unpack_from("<I", body, 12)[0] if len(body) >= 16 else 0
        return (worlddoor.build_world_answer(req, selector=req_sel + 1, result=0,
                                   pad_to=pad_to, **kw),
                "INVITE 0x%08x -> 128" % target)
    return None, "not a battletable verb"
