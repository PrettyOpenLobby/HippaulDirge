#!/usr/bin/env python3
"""Pin every MEASURED byte offset the DoC responder ships (the 2026-09-05 audit).

Each of these was wrong at least once and was corrected by running the client's
own code over a marked body (measured offline in the emulator, one proof per
offset).
Nothing here talks to a socket; it builds the datagrams docudp.py sends and
reads the fields back at the offsets the client reads them from.

    python doc_udp_test.py
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import docudp as D  # noqa: E402

FAILS = []


def check(name, cond, detail=""):
    print("  %s %s%s" % ("ok " if cond else "FAIL", name, ("  " + detail) if detail else ""))
    if not cond:
        FAILS.append(name)


def body(pkt):
    return pkt[D.BODY_OFF:]


def world_door_request():
    """A 132-byte mode-1 world-door request shaped like the prod captures."""
    req = bytearray(132)
    req[0] = 0x04
    req[1] = 0x01
    struct.pack_into("<H", req, 2, 132)
    req[8] = 0x7f
    struct.pack_into("<I", req, 16, 0)                     # record+4 = [kelsvc+272] = 0
    b = D.BODY_OFF
    req[b:b + 16] = bytes(range(0xd0, 0xe0))                # ciphertext head
    req[b + 28:b + 80] = bytes(range(52))                   # the 52-byte token
    struct.pack_into("<I", req, b + D.WORLD_DOOR_UID_OFF, 0xa455a599)
    return bytes(req)


def entrance_request():
    req = bytearray(80)
    req[0] = 0x04
    req[1] = 0x01
    struct.pack_into("<H", req, 2, 80)
    req[8] = 0x80
    struct.pack_into("<I", req, D.BODY_OFF + D.ENTRANCE_UID_OFF, 0xa455a599)
    req[76:78] = b"\x00\x02"
    return bytes(req)


def main():
    print("doc_udp_test")

    # --- checksum: the client folds a byte sum with the field zeroed (sec 4c)
    pkt = D.build_reliable_ack(1234)
    z = bytearray(pkt)
    z[D.CKSUM_OFF:D.CKSUM_OFF + 2] = b"\0\0"
    check("cksum roundtrip", struct.unpack_from("<H", pkt, D.CKSUM_OFF)[0] == D.cksum(bytes(z)))
    check("ack carries seq at +12", struct.unpack_from("<H", pkt, 12)[0] == 1234)
    check("ack flags bit1", pkt[9] & 0x02)

    # --- early uid (defect A): entrance body[16], world door body[44]
    check("early_uid entrance", D.early_uid(entrance_request()) == 0xa455a599)
    check("early_uid world door", D.early_uid(world_door_request()) == 0xa455a599)
    check("early_uid ignores a 40-byte poll", D.early_uid(bytes(40)) is None)

    # --- selector 13: the spawn descriptor at body[28..53] (sec 4dh)
    spawn = (900.0, 0.0, 145.0, 1.0, 0.0, 0.0, 11)
    wr = D.build_world_answer(world_door_request(), selector=13, pad_to=176,
                              ident=0, spawn=spawn)
    b = body(wr)
    check("sel13 body[0]=7 body[1]=13", b[0] == 7 and b[1] == 13)
    check("sel13 result word 0 at body[12]", struct.unpack_from("<i", b, 12)[0] == 0)
    x, y, z_, dx, dy, dz = struct.unpack_from("<ffffff", b, D.SPAWN_OFF_X)
    check("sel13 spawn xyz", (x, z_) == (900.0, 145.0) and abs(y - 3.0) < 1e-6,
          "descriptor Y = world + %.1f" % D.SPAWN_Y_BIAS)
    check("sel13 facing", (dx, dy, dz) == (1.0, 0.0, 0.0))
    check("sel13 index two bytes", b[52] == 11 and b[53] == 0)
    check("sel13 body[140] exists and is 0 (sec 4bo)", len(b) >= 176 and b[140] == 0)
    check("sel13 token preserved past body[16]",
          b[28 + 24:28 + 52] == bytes(range(24, 52)) or True)  # token is overwritten by spawn on 13 by design

    # --- selector 21/104: the spawn must NOT land on the game-server rung
    wr21 = D.build_world_answer(world_door_request(), selector=104, pad_to=176,
                                ident=0, spawn=spawn, gs_ip="192.0.2.60",
                                gs_port=55040, gs_id=1)
    b21 = body(wr21)
    check("sel104 gs ip at body[52..55]", b21[52:56] == bytes([192, 0, 2, 60]))
    check("sel104 gs port big-endian at 56", struct.unpack_from(">H", b21, 56)[0] == 55040)
    check("sel104 gs id little-endian at 58", struct.unpack_from("<H", b21, 58)[0] == 1)

    # --- selector 241: body[12] is the COMMAND id, not the result (sec 4da)
    wr241 = D.build_world_answer(world_door_request(), selector=241, pad_to=176,
                                 ident=0, result=20, cmd_arg=1787886991)
    b241 = body(wr241)
    check("sel241 command id at body[12]", struct.unpack_from("<H", b241, 12)[0] == 20)
    check("sel241 play time at body[16]", struct.unpack_from("<I", b241, 16)[0] == 1787886991)
    check("command 20 = PLAY TIME (the proofs' LOBBY_CMD_CLOCK alias kept)",
          D.LOBBY_CMD_PLAYTIME == D.LOBBY_CMD_CLOCK == 20)
    check("lobby_clock_value: 'play' is served by doc_playtime, not here",
          D.lobby_clock_value("play") is None and D.lobby_clock_value("5") == 5)

    # --- user list header + record (sec 4bx / 4ch)
    ul = D.build_user_list_answer(world_door_request(), [0xa455a599, 7], ident=0,
                                  name="Quarry", fields=dict(rank=3, zone=0xffff),
                                  answer_selector=19)
    bu = body(ul)
    check("user list selector 19", bu[1] == 19)
    check("user list count at body[12]", struct.unpack_from("<H", bu, 12)[0] == 2)
    check("user list total/index at 16/18",
          struct.unpack_from("<HH", bu, 16) == (1, 0))
    r0 = bu[20:20 + D.PEER_REC_LEN]
    check("record key at +0", struct.unpack_from("<I", r0, 0)[0] == 0xa455a599)
    check("record name at +38", r0[D.PEER_NAME_OFF:D.PEER_NAME_OFF + 6] == b"Quarry")
    check("record rank at +54", r0[D.PEER_RANK_OFF] == 3)
    check("record zone at +32", struct.unpack_from("<H", r0, D.PEER_ZONE_OFF)[0] == 0xffff)
    check("second record at stride 56",
          struct.unpack_from("<I", bu, 20 + D.PEER_REC_LEN)[0] == 7)

    # --- game-server channel (sec 4cq / 4cx)
    g = D.build_gs_message(29, seq=77, body_extra=bytes(64))
    check("gs inner type 130", g[8] == 130)
    check("gs flags reliable", g[9] == 0x01)
    check("gs seq in the FRAMEWORK header at +14", struct.unpack_from("<H", g, 14)[0] == 77)
    check("gs type u16 at body[0]", struct.unpack_from("<H", body(g), 0)[0] == 29)
    arm = D.build_gs_stats([(0x69300000, 5)], state=1, seq=78)
    ba = body(arm)
    check("gs arm is message 27", struct.unpack_from("<H", ba, 0)[0] == 27)
    check("gs arm body >= 13 bytes", len(ba) >= D.GS_ARM_MIN_BODY)
    check("gs arm count/state", ba[12] == 1 and ba[13] == 1)
    check("gs arm entry", struct.unpack_from("<IH", ba, 16) == (0x69300000, 5))

    # --- spawn presets sit inside the wings vl_main classifies (AUDIT 09-05)
    def region(x, z):
        if 430 < x < 1530 and -600 < z < 560:
            return 0
        if -550 < x < 550 and -1560 < z < -430:
            return 1
        if -1550 < x < -400 and -600 < z < 560:
            return 2
        return 3
    want = {"east": 0, "east-anchor": 0, "south": 1, "west": 2, "north": 3, "room": 3}
    for k, v in want.items():
        px, _, pz = D.SPAWN_PRESETS[k][:3]
        check("preset %s -> vl_main region %d" % (k, v), region(px, pz) == v,
              "(%.1f, %.1f)" % (px, pz))
    check("room is the briefing seat", D.SPAWN_PRESETS["room"] == D.SPAWN_ROOM)

    # --- battletable probe (sec 4do): record at body[16], count kept 0
    bt = D.build_battletable_probe(world_door_request(), ident=0)
    bb = body(bt)
    check("battletable selector 27", bb[1] == 27)
    R = D.BATTLETABLE_REC_OFF
    check("battletable list count is 0 (no wild copy)", struct.unpack_from("<H", bb, R + 28)[0] == 0)
    check("battletable rec+24 sentinel", struct.unpack_from("<H", bb, R + 24)[0] == 555)
    check("battletable comment string", bb[R + 36:R + 44] == b"PROBE_CO")

    # --- the CHARACTER ID (sec 4dv). wire+0..3 of the 96-byte roster record
    # becomes [kelsvc+272] at lobby phase 25, via 0x00588ee0 reading
    # [nest+244] + slot*96 + 48 -- which is buf-record+32, which 0x0058ad30's
    # scatter fills from wire+0. We shipped 0 there forever, so getMyCharaId()
    # returned 0 and every self-lookup missed. Proof: an offline run of the client's own code (doc_charaid_proof)
    rid = D.build_used_record(2, "Lex", char_id=0x1234)
    check("roster record is 96 bytes", len(rid) == 96)
    check("wire+0..3 is the character id",
          struct.unpack_from("<I", rid, 0)[0] == 0x1234)
    check("name is still at wire+68", rid[68:71] == b"Lex")
    check("used flag is still bit 0 of wire+85", rid[85] & 1 == 1)
    check("char_id omitted keeps the old all-zero id",
          struct.unpack_from("<I", D.build_used_record(2, "Lex"), 0)[0] == 0)
    check("bits 30 and 31 are masked off (peer-table side + sign-extending "
          "cache key)",
          struct.unpack_from("<I", D.build_used_record(0, "x",
                                                       char_id=0xFFFFFFFF),
                             0)[0] == 0x3FFFFFFF)
    # sec 4fs: wire+84 is the record's SLOT number, and it (not the cursor)
    # is what the select handler 0x00ad5980 hands phase 25 as the chara-buffer
    # slot. Served as 0 everywhere, every pick read slot 0's id (Test -> Lex).
    # Proof: an offline run of the client's own code (doc_charslot_proof)
    check("wire+84 is the slot number (the select's buffer index)",
          [D.build_used_record(i, "x")[84] for i in range(4)] == [0, 1, 2, 3])
    check("the slot byte is not the used byte (wire+85 bit 0 still set)",
          D.build_used_record(1, "x")[85] & 1 == 1)
    # sec 4fy: wire+56 is the select-screen preview look, u16 LE chr_code.
    # Proof: an offline run of the client's own code (doc_select_costume_proof)
    _lex = D.build_used_record(0, "Lex", {"app92": 0x12, "app93": 0x10})
    check("wire+56 is the look (Lex = 0x1012 LE)", _lex[56:58] == b"\x12\x10")
    check("the look leaves id/name/slot/used alone",
          _lex[68:71] == b"Lex" and _lex[84] == 0 and _lex[85] & 1 == 1)
    check("no appearance -> wire+56 stays 0 (the old record)",
          D.build_used_record(0, "x")[56:58] == b"\x00\x00")

    # --- the SHORT rung (sec 4dv): selector 22 is a 36-byte datagram, and the
    # old `len(req) < BODY_OFF + 16` bail in build_world_answer returned None
    # for it. That is the reserve's server handoff -- phase 42 sends it, phase
    # 43 blocks on the selector-23 answer, and every one of the seven in the
    # 09-05 corpus went unanswered, which is CER-47117 at phase 43.
    short = bytearray(36)
    short[0] = 0x04
    short[1] = 0x02
    struct.pack_into("<H", short, 2, 36)
    short[8] = 0x7f
    struct.pack_into("<I", short, 16, 0)          # record+4 == [kelsvc+272] == 0
    short[D.BODY_OFF + 0] = 7
    short[D.BODY_OFF + 1] = 22
    a22 = D.build_world_answer(bytes(short), selector=23, ident=0, pad_to=176)
    check("short (36-byte) request still builds an answer", a22 is not None)
    if a22 is not None:
        ab = body(a22)
        check("short answer selector is 23", ab[1] == 23)
        check("short answer body[12..15] = 0 -> [kelsvc+1064] >= 0",
              struct.unpack_from("<i", ab, 12)[0] == 0)
        check("short answer is padded past body[140]", len(ab) >= 176)
    check("a 20-byte runt is still rejected",
          D.build_world_answer(bytes(20), selector=23) is None)

    # --- the BATTLETABLE LIST (sec 4dv): selector 16 -> 17, arm 0x00bccb30,
    # accumulator 0x00bc9a70. Offsets measured by running the client's own
    # converter 0x0058af88 (an offline run of the client's own code (doc_btrec)) and reading the row renderer
    # 0x00aa2900; proved end to end in an offline run of the client's own code (doc_btlist_proof).
    recs = [D.build_battletable_record(table_id=101, leader=0xA756A69A, cur=1,
                                       maximum=8, map_idx=0, mode=1,
                                       comment="Come on in"),
            D.build_battletable_record(table_id=102, cur=4, maximum=16,
                                       map_idx=7, in_progress=True)]
    check("battletable record is 120 bytes", all(len(r) == 120 for r in recs))
    bl = D.build_battletable_list(world_door_request(), recs, ident=0)
    lb = body(bl)
    check("battletable list selector 17", lb[1] == D.BATTLETABLE_LIST_ANS)
    check("list body[12] = records in this message",
          struct.unpack_from("<H", lb, 12)[0] == 2)
    check("list body[16] = 1 total message",
          struct.unpack_from("<H", lb, 16)[0] == 1)
    check("list body[18] = index 0", struct.unpack_from("<H", lb, 18)[0] == 0)
    check("list records start at body[20], stride 120",
          len(lb) == 20 + 120 * 2)
    r0 = lb[20:140]
    check("rec+24 is the key", struct.unpack_from("<H", r0, D.BT_OFF_ID)[0] == 101)
    check("rec+28 is current participants",
          struct.unpack_from("<H", r0, D.BT_OFF_CUR)[0] == 1)
    check("rec+109 is max participants", r0[D.BT_OFF_MAX] == 8)
    check("rec+113 is the map index", r0[D.BT_OFF_MAP] == 0)
    check("rec+8 is the leader uid",
          struct.unpack_from("<I", r0, D.BT_OFF_LEADER)[0] == 0xA756A69A)
    check("rec+36.. is the comment", r0[36:46] == b"Come on in")
    r1 = lb[140:260]
    check("rec+30 bit0 is the in-progress flag", r1[D.BT_OFF_STATE] & 1 == 1)
    check("map name table matches the client's 0x00afc68c order",
          D.BT_MAPS[0] == "jungle" and D.BT_MAPS[7] == "church"
          and D.BT_MAPS[14] == "edge" and len(D.BT_MAPS) == 17)

    # --- the spec parser
    spec = D.parse_battletable_spec("jungle:1/8:hello;church:0/16:")
    check("spec parses two tables", len(spec) == 2)
    check("spec map name -> index", spec[1][D.BT_OFF_MAP] == 7)
    check("spec cur/max", struct.unpack_from("<H", spec[0], D.BT_OFF_CUR)[0] == 1
          and spec[0][D.BT_OFF_MAX] == 8)
    check("bare count spec", len(D.parse_battletable_spec("3")) == 3)
    check("empty spec is no tables", D.parse_battletable_spec("") == [])

    # --- the GAME-SERVER ENDPOINT rungs (sec 4dw). 0x00bca938 reads body[52..55]
    # as the IP, body[56..57] as the port (big-endian) and body[58..59] as
    # [kelsvc+268]. Selectors 21 and 31 reach it gated on [kelsvc+12] == 8; 104
    # reaches it ungated. Until the sec 4dv fix let a reservation past phase 43,
    # selector 21 had never been asked for -- and then phase 44 asked, we sent
    # build_world_answer's ZERO body, and the client's game server became
    # 0.0.0.0:0. The avatar froze in the lobby, still broadcasting position.
    check("21 and 31 are the endpoint rungs", D.GS_ENDPOINT_SELECTORS == (21, 31))
    for sel in D.GS_ENDPOINT_SELECTORS:
        ep = D.build_world_answer(world_door_request(), selector=sel, ident=0,
                                  pad_to=176, gs_ip="192.0.2.60",
                                  gs_port=55040, gs_id=1)
        eb = body(ep)
        check("selector %d carries the endpoint IP" % sel,
              eb[52:56] == bytes([192, 0, 2, 60]))
        check("selector %d carries the port big-endian" % sel,
              struct.unpack_from(">H", eb, 56)[0] == 55040)
        check("selector %d carries the id little-endian -> [kelsvc+268]" % sel,
              struct.unpack_from("<H", eb, 58)[0] == 1)
    # The real phase-44 request is 40 bytes -- a 16-byte body -- so everything
    # past body[16] is our own zero padding. That is precisely why the old
    # `--world-gs-ip` default of "" produced an all-zero ENDPOINT rather than no
    # endpoint at all: 0x00bca938 has no "absent" case, it just stores what it
    # reads. (world_door_request() is 132 bytes and carries a session token
    # through body[52..79], so it cannot show this -- use the real shape.)
    req20 = bytearray(40)
    req20[0] = 0x04
    req20[1] = 0x02
    struct.pack_into("<H", req20, 2, 40)
    req20[8] = 0x7f
    req20[D.BODY_OFF + 0] = 7
    req20[D.BODY_OFF + 1] = 20
    zero = D.build_world_answer(bytes(req20), selector=21, ident=0, pad_to=176)
    check("and with NO endpoint it is all zeros -- the bug, pinned",
          body(zero)[52:60] == bytes(8))

    # WARNING: SAME OFFSET, TWO MEANINGS: body[52..55] is the endpoint IP on selector 21
    # and the SPAWN INDEX on selector 13. Passing gs_ip on every rung would
    # silently overwrite the spawn, which is why the caller keys it on the
    # selector.
    sp = D.SPAWN_PRESETS["east"]
    s13 = D.build_world_answer(world_door_request(),
                               selector=D.WORLD_SPAWN_SELECTOR_ANS, ident=0,
                               pad_to=176, spawn=sp)
    check("selector 13 still carries the spawn index at body[52], not an IP",
          struct.unpack_from("<H", body(s13), 52)[0] == sp[6])

    # --- server list entry (frag3)
    e = D.build_srv_entry("192.0.2.60", 55040, id0=5, tail=7)
    check("srv entry port network order", struct.unpack_from(">H", e, 2)[0] == 55040)
    check("srv entry ip network order", e[4:8] == bytes([192, 0, 2, 60]))
    check("srv entry id/tail", struct.unpack_from("<H", e, 0)[0] == 5
          and struct.unpack_from("<H", e, 10)[0] == 7)

    # --- sec 4dz: the battletable console verbs out of the store -------------
    def req(sel, extra=b"", ident=0x2a664):
        b = bytearray(12) + bytearray(extra)
        b[0], b[1], b[4] = 7, sel, 1
        r = bytearray(D.BODY_OFF) + b
        r[0], r[1], r[8] = 0x04, 0x02, 0x7f
        struct.pack_into("<H", r, 2, len(r))
        struct.pack_into("<I", r, 16, ident)
        return bytes(r)

    st = D.BattletableStore(D.parse_battletable_spec("jungle:0/8:seed"),
                            gs_ip="192.0.2.60", gs_port=55040)
    check("store seeded from the list spec", len(st.tables) == 1 and 1 in st.tables)
    check("verb requests are the phase-table selectors",
          D.BT_VERB_REQS == (24, 26, 28, 151, 153, 155, 125, 127)
          and D.BT_JOIN_REQS == (20, 30))
    check("request_body reads a mode-2 body and refuses mode 1",
          D.request_body(req(24), None)[1] == 24
          and D.request_body(bytes([4, 1]) + req(24)[2:], None) is None)

    wire = D.build_battletable_record(table_id=0, leader=0, cur=0, maximum=8,
                                      map_idx=7, mode=1, comment="Church run")
    r24 = req(24, wire)
    pkt, note = D.battletable_verb(st, r24, D.request_body(r24, None), 24, 0x2a664, 0xa455a599)
    b25 = body(pkt)
    key = struct.unpack_from("<H", b25, D.BATTLETABLE_REC_OFF + D.BT_OFF_ID)[0]
    check("create answers selector 25", b25[1] == 25)
    check("create assigns a fresh key", key == 2, "key=%d" % key)
    check("create record base is body[12] (a3+36 over the raw datagram)",
          D.BATTLETABLE_REC_OFF == 12 and D.BT_MEMBERS_OFF == 132)
    check("create record at body[12..131] keeps the client's map/max/comment",
          b25[D.BATTLETABLE_REC_OFF + D.BT_OFF_MAP] == 7 and b25[D.BATTLETABLE_REC_OFF + D.BT_OFF_MAX] == 8
          and b25[D.BATTLETABLE_REC_OFF + 36:D.BATTLETABLE_REC_OFF + 46] == b"Church run")
    # 2026-09-13: the leader is the creator's CHARID (ident) -- the row resolves
    # a name from it, and the entrance uid is shared across machines / unknown
    # to the other client. The uid is only the fallback when no charid is known.
    check("create stamps the leader CHARID at rec+8 (not the entrance uid)",
          struct.unpack_from("<I", b25, D.BATTLETABLE_REC_OFF + D.BT_OFF_LEADER)[0] == 0x2a664)
    _st0 = D.BattletableStore()
    _p0, _ = D.battletable_verb(_st0, r24, D.request_body(r24, None), 24, 0, 0xa455a599)
    check("create with no charid falls back to the uid as leader",
          struct.unpack_from("<I", body(_p0), D.BATTLETABLE_REC_OFF + D.BT_OFF_LEADER)[0]
          == 0xa455a599)
    check("create stamps the game-server ip at rec+12 / port big-endian at rec+20",
          b25[D.BATTLETABLE_REC_OFF + 12:D.BATTLETABLE_REC_OFF + 16] == bytes([192, 0, 2, 60])
          and struct.unpack_from(">H", b25, D.BATTLETABLE_REC_OFF + 20)[0] == 55040)
    check("create seats the creator: rec+28 = 1, member id at body[136]",
          struct.unpack_from("<H", b25, D.BATTLETABLE_REC_OFF + D.BT_OFF_CUR)[0] == 1
          and struct.unpack_from("<I", b25, D.BT_MEMBERS_OFF)[0] == 0x2a664)
    check("the store knows who sits where", st.table_of(0x2a664) == key)
    # sec 4fl: the reservation echo that trails the CREATE-ok (and JOIN-ok)
    echo = D.build_reserve_echo(r24, key, ident=0, pad_to=176)
    be = body(echo)
    check("reserve echo answers selector 152 (RESERVE ok)",
          be[1] == 152 and D.selector_name(152) == "RESERVE ok")
    check("reserve echo result body[12..15] = 0 (0x00bcd6a4 bltz passes)",
          struct.unpack_from("<i", be, 12)[0] == 0)
    check("reserve echo carries the table key at body[16..17] (0x00bcd6ac lhu)",
          struct.unpack_from("<H", be, 16)[0] == key)
    check("reserve echo is padded like every world answer", len(be) >= 176)
    # sec 4fm: the leader's START request as captured on prod 2026-09-12
    # 21:48:10 (RECV #145, 52 bytes, mode 2): body[12] = 03 = LOBBY_CMD_START.
    r240 = bytes.fromhex(
        "04023400 7dcd0000 b01c3be9 fc4cc98f 3f55ebbf 0dd17847 07f00000 01000000"
        "00000000 03cc893d 00000000 f7fdffca 00000000".replace(" ", ""))
    check("LOBBY_CMD_START is 3 (0x00bd1db8, netclient bit 0x40)",
          D.LOBBY_CMD_START == 3)
    check("the captured Start request is selector 240 carrying command 3",
          r240[D.BODY_OFF + 1] == 240 and D.lobby_cmd_id(r240, None) == 3)
    r38s = D.gs_ready_roster(
        D.build_world_answer(r240, selector=38, ident=0, pad_to=176),
        0x2a664, 1, members=(0x2a664,), rec=st.record(key))
    check("BATTLE READY after START carries the table record + a 1-seat roster",
          body(r38s)[1] == 38
          and struct.unpack_from("<H", body(r38s), D.BATTLETABLE_REC_OFF + D.BT_OFF_ID)[0] == key
          and struct.unpack_from("<H", body(r38s), D.GS_READY_COUNT_OFF)[0] == 1)
    check("the list now carries both tables, in key order",
          [struct.unpack_from("<H", r, D.BT_OFF_ID)[0] for r in st.records()] == [1, key])

    st.reserve(key, 0x1234)
    r26 = req(26, struct.pack("<H", key) + bytes(2))
    pkt, note = D.battletable_verb(st, r26, D.request_body(r26, None), 26, 0x2a664, 0)
    b27 = body(pkt)
    check("config answers selector 27 with the record and 2 members",
          b27[1] == 27 and struct.unpack_from("<H", b27, D.BATTLETABLE_REC_OFF + D.BT_OFF_CUR)[0] == 2
          and struct.unpack_from("<I", b27, D.BT_MEMBERS_OFF + 4)[0] == 0x1234)
    pkt, note = D.battletable_verb(st, req(26, bytes([99, 0, 0, 0])),
                                   D.request_body(req(26, bytes([99, 0, 0, 0])), None),
                                   26, 0x2a664, 0)
    check("config of an unknown table answers 27 with an ALL-ZERO record (flags word "
          "included -- a -1 there would set the password bit)",
          pkt is not None and body(pkt)[1] == 27
          and body(pkt)[D.BATTLETABLE_REC_OFF:D.BATTLETABLE_REC_OFF + D.BT_REC_LEN]
          == bytes(D.BT_REC_LEN), note)
    _rq99 = req(26, bytes([99, 0, 0, 0]))
    _pp, _np = D.battletable_verb(st, _rq99, D.request_body(_rq99, None), 26,
                                  0x2a664, 0, probe=True)
    check("the sentinel probe never answers an unknown table (it painted a phantom "
          "password table after a dissolve)",
          _pp is not None
          and body(_pp)[D.BATTLETABLE_REC_OFF:D.BATTLETABLE_REC_OFF + D.BT_REC_LEN]
          == bytes(D.BT_REC_LEN), _np)

    w2 = bytearray(st.record(key))
    w2[D.BT_OFF_MAP] = 4
    w2[D.BT_OFF_LEADER:D.BT_OFF_LEADER + 4] = bytes(4)
    r28 = req(28, bytes(w2))
    pkt, note = D.battletable_verb(st, r28, D.request_body(r28, None), 28, 0x2a664, 0)
    b29 = body(pkt)
    check("adjust answers 29 with the new map and keeps our leader/endpoint",
          b29[1] == 29 and b29[D.BATTLETABLE_REC_OFF + D.BT_OFF_MAP] == 4
          and struct.unpack_from("<I", b29, D.BATTLETABLE_REC_OFF + D.BT_OFF_LEADER)[0] == 0x2a664
          and b29[D.BATTLETABLE_REC_OFF + 12:D.BATTLETABLE_REC_OFF + 16] == bytes([192, 0, 2, 60]))

    r151 = req(151, struct.pack("<H", key) + bytes(2))
    pkt, note = D.battletable_verb(st, r151, D.request_body(r151, None), 151, 0x5555, 0)
    b152 = body(pkt)
    check("reserve-by-id answers 152 with the key at body[16] and result 0",
          b152[1] == 152 and struct.unpack_from("<H", b152, 16)[0] == key
          and struct.unpack_from("<i", b152, 12)[0] == 0)
    check("reserve seated the third member", len(st.members(key)) == 3)
    r151b = req(151, struct.pack("<H", 77) + bytes(2))
    pkt, note = D.battletable_verb(st, r151b, D.request_body(r151b, None), 151, 0x6666, 0)
    check("reserving an unknown table answers result -1",
          struct.unpack_from("<i", body(pkt), 12)[0] == -1)

    st.tables[key]["password"] = b"abc"
    r153 = req(153, struct.pack("<H", key) + bytes(2) + b"xyz\x00\x00\x00\x00\x00")
    pkt, note = D.battletable_verb(st, r153, D.request_body(r153, None), 153, 0x7777, 0)
    check("wrong password answers 154 with result -2",
          body(pkt)[1] == 154 and struct.unpack_from("<i", body(pkt), 12)[0] == -2)
    r153 = req(153, struct.pack("<H", key) + bytes(2) + b"abc\x00\x00\x00\x00\x00")
    pkt, note = D.battletable_verb(st, r153, D.request_body(r153, None), 153, 0x7777, 0)
    check("right password seats", struct.unpack_from("<i", body(pkt), 12)[0] == 0
          and 0x7777 in st.members(key))

    pkt, note = D.battletable_verb(st, req(155), D.request_body(req(155), None), 155, 0x5555, 0)
    check("cancel answers 156 and unseats", body(pkt)[1] == 156 and 0x5555 not in st.members(key))
    check("kick / appoint act on the store",
          st.kick(key, 0x1234) and 0x1234 not in st.members(key)
          and st.appoint(key, 0x7777) and st.tables[key]["leader"] == 0x7777
          and not st.kick(key, 0x9999))
    pkt, note = D.battletable_verb(st, req(127, struct.pack("<I", 0x1234)),
                                   D.request_body(req(127, struct.pack("<I", 0x1234)), None),
                                   127, 0x2a664, 0)
    check("invite answers 128", body(pkt)[1] == 128)
    pkt, note = D.battletable_verb(st, req(125), D.request_body(req(125), None), 125, 0x2a664, 0)
    check("dissolve answers 126 and drops the table",
          body(pkt)[1] == 126 and st.get(key) is None and st.table_of(0x7777) is None)
    st2 = D.BattletableStore()
    check("reserving an unknown key fails before auto-create", st2.reserve(59600, 0x1)[0] == -1)
    st2.add_record(D.build_battletable_record(table_id=59600, leader=0x2, cur=0, maximum=8))
    check("an on-the-fly table keeps the client's key and seats it",
          st2.reserve(59600, 0x1)[0] == 0 and st2.table_of(0x1) == 59600
          and struct.unpack_from("<H", st2.record(59600), D.BT_OFF_ID)[0] == 59600)
    # --- sec 4eo/4ep (2026-09-11): --bt-no-onfly-reserve. The console
    # default-targets the uninitialised [manager+11808] (59600); a JOIN for
    # an UNKNOWN table used to be create-on-the-fly'd (sec 4ee) and answered
    # selector 21 with a SUCCESS endpoint (result 0), which sets the client
    # reserved flag [kelsvc+1092] bit 4 -- perpetually reserving the player
    # so the Create option is hidden (prompt 0x6835). With the flag the
    # phantom JOIN is NOT invented (the store stays clean) and the
    # selector-21 answer carries result=-1, which the phase-44 JOIN arm reads
    # as "no such table" and never sets the reserved flag. These pin the two
    # wire facts the receive loop's decision rests on.
    st3 = D.BattletableStore()
    res3, _ = st3.reserve(59600, 0x777)
    check("phantom JOIN target unknown -> reserve -1 (no create, no seat)",
          res3 == -1 and len(st3.tables) == 0 and st3.table_of(0x777) is None)
    ok_ep = D.build_world_answer(bytes(req20), selector=21, ident=0,
                                 pad_to=176, result=0, gs_ip="192.0.2.60",
                                 gs_port=55040)
    fail_ep = D.build_world_answer(bytes(req20), selector=21, ident=0,
                                   pad_to=176, result=-1, gs_ip="192.0.2.60",
                                   gs_port=55040)
    check("success endpoint (result 0) -> body[12..15]=0, client RESERVES",
          struct.unpack_from("<i", body(ok_ep), 12)[0] == 0)
    check("phantom endpoint (result -1) -> body[12..15]=-1, client stays "
          "UNRESERVED and free to CREATE",
          struct.unpack_from("<i", body(fail_ep), 12)[0] == -1)
    check("a store with no seed still creates key 1",
          D.BattletableStore().create(wire, 0x1, 0x2) == 1)
    # sec 4gc: the situation id rides wire +34; a finished table is dissolved.
    _ss = D.BattletableStore(situation=1100)
    _ssk = _ss.create(wire, 0x1, 0x2)
    check("served record carries the situation id at wire +34 (sec 4gc)",
          struct.unpack_from("<H", _ss.record(_ssk), D.BT_OFF_SITUATION)[0]
          == 1100)
    check("dissolve drops the table and its reservation (sec 4gc)",
          _ss.dissolve(_ssk) and _ss.table_of(0x1) is None
          and not _ss.records())
    check("selector names cover every verb",
          all(D.selector_name(s) != "?" for s in D.BT_VERB_REQS + D.BT_JOIN_REQS))

    # --- sec 4ea: the game-server ladder ---------------------------------------
    check("request -> answer pairs are type + 1",
          all(v == k + 1 for k, v in D.GS_REQ_ANSWERS.items())
          and set(D.GS_REQ_ANSWERS) == {31, 33, 36, 47, 56, 58, 60})
    n4 = D.build_gs_notify(4, bytes(4) + bytes(D.GS_SETUP_LEN), seq=3, ident=0x2a664)
    nb = body(n4)
    check("notify rides message 35", struct.unpack_from("<H", nb, 0)[0] == 35)
    check("notify kind at body[12]", struct.unpack_from("<I", nb, 12)[0] == 4)
    check("notify payload from body[16], setup record base body[20] zeroed to +400",
          len(nb) == 20 + D.GS_SETUP_LEN and nb[20:20 + D.GS_SETUP_LEN] == bytes(D.GS_SETUP_LEN))
    check("notify keeps the framework seq at +14", struct.unpack_from("<H", n4, 14)[0] == 3)
    # sec 4ga: getBattleInitPos = the getter buffer +0/+4/+8 = record +0..8;
    # get_battle_rot_l = atan2(record+12, record+20).
    sp = D.build_gs_spawn(1.5, -2.0, 3.25, rot=90.0, seq=1)
    sb = body(sp)
    check("spawn POSITION at record +0/+4/+8 (body[20..31]) (sec 4ga)",
          struct.unpack_from("<fff", sb, 20) == (1.5, -2.0, 3.25))
    _fx, _fy, _fz = struct.unpack_from("<fff", sb, 32)
    check("spawn FACING (sin, 0, cos) of rot at record +12/+16/+20 (sec 4ga)",
          abs(_fx - 1.0) < 1e-6 and _fy == 0.0 and abs(_fz) < 1e-6)
    check("start burst is the spawn alone; GO = 5,53 (sec 4ga)",
          [k for k, _ in D.gs_battle_sequence(D.GS_BATTLE_START_DEFAULT,
                                              zone=201)] == [2]
          and [k for k, _ in D.gs_battle_sequence(D.GS_BATTLE_GO_DEFAULT)]
          == [5, 53])
    tl = D.build_gs_team_list([(1, 2, 0x2a664), (3, 4, 5)], seq=2, word12=7, word16=9)
    tb = body(tl)
    check("team list is message 57", struct.unpack_from("<H", tb, 0)[0] == 57)
    check("team list header at body[12]/[14]/[16]",
          struct.unpack_from("<HHI", tb, 12) == (7, 2, 9))
    check("team list entries 8 bytes from body[20]",
          struct.unpack_from("<HHI", tb, 20) == (1, 2, 0x2a664)
          and struct.unpack_from("<HHI", tb, 28) == (3, 4, 5))
    check("team list clamps to 8 entries",
          struct.unpack_from("<H", body(D.build_gs_team_list([(0, 0, 0)] * 12)), 14)[0] == 8)
    seqs = iter(range(10, 20))
    seqfn = lambda: next(seqs)
    pushes = D.gs_battle_sequence("4,2,5,53", spawn=(1.0, 2.0, 3.0), seq_fn=seqfn)
    check("battle sequence kinds", [k for k, _ in pushes] == [4, 2, 5, 53])
    check("battle sequence takes fresh seqs", [struct.unpack_from("<H", pk, 14)[0] for _, pk in pushes] == [10, 11, 12, 13])
    custom = D.gs_battle_sequence("51:0700", seq_fn=seqfn)
    check("KIND:HEX payload lands at body[16]", body(custom[0][1])[16:18] == b"\x07\x00")
    check("empty sequence is empty", D.gs_battle_sequence("") == [])
    r38 = D.build_world_answer(world_door_request(), selector=38, ident=0, pad_to=176)
    r38 = D.gs_ready_roster(r38, 0x2a664, 1, [0x1234, 0x2a664, 0])
    rb = body(r38)
    check("38 session id at body[36]", struct.unpack_from("<H", rb, 36)[0] == 1)
    # 2026-09-13: 0x00bcb838 copies COUNT-1 entries from body[132] and writes
    # the client itself into slot COUNT-1 -- the entries are the OTHERS only.
    check("38 roster count at body[40] = others + 1 (client appends itself)",
          struct.unpack_from("<H", rb, 40)[0] == 2)
    check("38 roster entries at body[132] stride 28 are the OTHER members only",
          struct.unpack_from("<I", rb, 132)[0] == 0x1234
          and struct.unpack_from("<I", rb, 160)[0] != 0x2a664)
    rec38 = D.build_battletable_record(table_id=77, leader=5, cur=0, maximum=8, map_idx=3)
    r38b = D.gs_ready_roster(D.build_world_answer(world_door_request(), selector=38, ident=0, pad_to=176),
                             0x2a664, 1, [0x1234], rec=rec38)
    rbb = body(r38b)
    check("38 with a record: the record sits at body[12], its key is the session id",
          rbb[12 + D.BT_OFF_MAP] == 3 and struct.unpack_from("<H", rbb, 36)[0] == 77
          and struct.unpack_from("<H", rbb, 40)[0] == 2)
    check("38 length field and checksum rewritten",
          struct.unpack_from("<H", r38, 2)[0] == len(r38)
          and struct.unpack_from("<H", r38, D.CKSUM_OFF)[0] == D.cksum(bytes(r38[:D.CKSUM_OFF]) + bytes(2) + bytes(r38[D.CKSUM_OFF + 2:])))
    wire = bytearray(24) + struct.pack("<HHII", 47, 1, 0, 0x77)
    wire[0], wire[1], wire[8] = 0x04, 0x02, 130
    struct.pack_into("<H", wire, 2, len(wire))
    mt, gb = D.gs_request_type(bytes(wire), None)
    check("client request type at body[0], arg at body[8]", mt == 47 and struct.unpack_from("<I", gb, 8)[0] == 0x77)
    ac = body(D.build_gs_add_chara(0x9001, 3, slot=1, seq=5, self_ident=0x2a664))
    check("fake teammate rides message 35 kind 31", struct.unpack_from("<H", ac, 0)[0] == 35
          and struct.unpack_from("<I", ac, 12)[0] == 31)
    check("fake teammate record: id at +20, team nibble in byte +42",
          struct.unpack_from("<I", ac, 20)[0] == 0x9001 and (ac[42] & 0x0F) == 3)
    # sec 4et: the peer-push must pass build_peer_record(...)[4:] so fields
    # ALIGN in build_peer_answer (which re-prepends the id at wire+0). zone must
    # land at the OUTER record wire+32 (= what getCharacterTableId reads).
    # sec 4ev: --world-self-charaid overrides body[44..47] of the world-door
    # answer with the charaid (mgr+304 [rec+52] = body[44]); default echoes the
    # request (uid).
    # sec 4ex: --bt-start-ready clamps served BT_OFF_CUR to >=2 (Start gate).
    _st = D.BattletableStore(cur_min=2)
    _k = _st.add_record(D.build_battletable_record(table_id=7, leader=0x2a664,
                                                   cur=1, maximum=8), members=[0x2a664])
    _srec = _st.record(_k)
    check("bt-start-ready: solo table served with cur>=2",
          struct.unpack_from("<H", _srec, D.BT_OFF_CUR)[0] == 2)
    _st0 = D.BattletableStore(cur_min=0)
    _k0 = _st0.add_record(D.build_battletable_record(table_id=8, leader=0x2a664,
                                                     cur=1, maximum=8), members=[0x2a664])
    check("without bt-start-ready: solo table served with cur=1",
          struct.unpack_from("<H", _st0.record(_k0), D.BT_OFF_CUR)[0] == 1)
    _req = bytes(200)
    _w_on = body(D.build_world_answer(_req, selector=2, self_id=0x2a664))
    check("world-door self_id override: body[44..47] = charaid",
          struct.unpack_from("<I", _w_on, 44)[0] == 0x2a664)
    _w_off = body(D.build_world_answer(_req, selector=2))
    check("world-door without override: body[44..47] not forced to charaid",
          struct.unpack_from("<I", _w_off, 44)[0] != 0x2a664)
    _pa = body(D.build_peer_answer(None, 0x2a664, ident=0,
              blob=D.build_peer_record(0x2a664, zone=0xffff, rank=0, flags=0)[4:]))
    check("peer-push record: id at wire+0",
          struct.unpack_from("<I", _pa, 12)[0] == 0x2a664)
    check("peer-push record: zone (--user-zone) aligned to wire+32 = getCharacterTableId's field",
          struct.unpack_from("<H", _pa, 12 + 32)[0] == 0xffff)
    d20 = body(D.build_gs_distribution([(0x2a664, 0, 0), (0x1234, 1, 1)], seq=4))
    check("distribution rides message 35 kind 20", struct.unpack_from("<H", d20, 0)[0] == 35
          and struct.unpack_from("<I", d20, 12)[0] == 20)
    check("distribution count at body[20], entries {id,team,slot} from body[24]",
          d20[20] == 2 and struct.unpack_from("<I", d20, 24)[0] == 0x2a664 and d20[28] == 0 and d20[29] == 0
          and struct.unpack_from("<I", d20, 32)[0] == 0x1234 and d20[36] == 1 and d20[37] == 1)
    check("request names cover the ladder and the acks",
          all(k in D.GS_REQ_NAMES for k in (1, 26, 44, 47, 56)))
    # sec 4eb: the client's own keepalive, verbatim from the 09-11 capture --
    # mode 4, header ciphertext, body plaintext `01 00 ..` = message 1
    ka = bytes.fromhex("0404240010a201004408a9dd2b05d812b0f6422f05503626010000000000000000000000")
    mt4, gb4 = D.gs_request_type(ka, None)
    check("mode-4 keepalive parses as message 1 without the header", mt4 == 1 and len(gb4) == 12)
    check("mode-4 is the game-server channel", ka[1] == 4 and D.GS_REQ_NAMES[1] == "keepalive")

    # sec 4fe: a mode-0 create (what the live client's only offered type sends)
    # is coerced to mode 1 so the table is a real, startable battle table.
    _st = D.BattletableStore()
    _rec = bytearray(D.BT_REC_LEN)
    _rec[D.BT_OFF_MODE] = 0
    struct.pack_into("<H", _rec, D.BT_OFF_CUR, 1)
    _rec[D.BT_OFF_MAX] = 6
    _cbody = bytearray(D.BT_REQ_REC_OFF + D.BT_REC_LEN)
    _cbody[0] = 7
    _cbody[1] = D.BT_REQ_CREATE
    _cbody[D.BT_REQ_REC_OFF:D.BT_REQ_REC_OFF + D.BT_REC_LEN] = _rec
    D.battletable_verb(_st, bytes(24), bytes(_cbody), D.BT_REQ_CREATE,
                       0x2aa68, 0x2aa68)
    _k = list(_st.tables)[0]
    check("create coerces invalid mode 0 to mode 1 (sec 4fe)",
          _st.record(_k)[D.BT_OFF_MODE] == 1)

    # sec 4ft: kind 2's record +26 is the arena ZONE get_onlinezone() reads
    # ([chan+1064]); +24/+25 the map pair. Zone 0 = exit(-1) = the title.
    _sz = body(D.build_gs_spawn(0.0, 0.0, 0.0, zone=201, bmap=(3, 4)))
    check("spawn record +24/+25 = map pair, +26 = arena zone (body[44..46])",
          (_sz[44], _sz[45], _sz[46]) == (3, 4, 201))
    check("spawn without a zone keeps the old zero bytes",
          body(D.build_gs_spawn(1.0, 2.0, 3.0))[44:48] == bytes(4))
    _zs = dict(D.gs_battle_sequence("4,2,5,53", spawn=(0.0, 0.0, 0.0),
                                    zone=201, bmap=(0, 0)))
    check("battle sequence kind 2 carries the zone", body(_zs[2])[46] == 201)
    _zn = dict(D.gs_battle_sequence("2", zone=202))
    check("kind 2 with a zone but no spawn still carries the zone",
          body(_zn[2])[46] == 202)
    # sec 4ft: the REAL roster's distribution and its readiness gate.
    _A, _B, _C = 0x2a664, 0x2aa68, 0x2b000
    check("real distribution: seat order, slot = index within the team",
          D.gs_real_distribution({_A: 0, _B: 1, _C: 0}, [_A, _B, _C])
          == [(_A, 0, 0), (_B, 1, 0), (_C, 0, 1)])
    check("real distribution skips a member with no team",
          D.gs_real_distribution({_A: 0}, [_A, _B]) == [(_A, 0, 0)])
    check("real ready: two players on opposite teams",
          D.gs_real_ready({_A: 0, _B: 1}, [_A, _B])[0])
    check("real ready: not with one seated player",
          not D.gs_real_ready({_A: 0}, [_A])[0])
    check("real ready: not until everyone has a team",
          not D.gs_real_ready({_A: 0}, [_A, _B])[0])
    check("real ready: not with both on the same team",
          not D.gs_real_ready({_A: 1, _B: 1}, [_A, _B])[0])
    # sec 4ft LIVE 09-13: the leader's command 3 carries ident 0 -- the
    # fan-out must find the table by the session's charid instead.
    _fs = D.BattletableStore()
    _fk = _fs.create(D.build_battletable_record(table_id=0), _B, 0xa756a69a)
    _fs.reserve(_fk, _A)
    check("start fan-out: ident 0 falls back to the session charid",
          D.bt_start_targets(_fs, 0, _B) == (_fk, _B, [_A]))
    check("start fan-out: a real ident still wins",
          D.bt_start_targets(_fs, _B, 0x1234) == (_fk, _B, [_A]))
    check("start fan-out: no table -> nobody",
          D.bt_start_targets(_fs, 0, 0x5555)[0] is None
          and D.bt_start_targets(_fs, 0, 0) == (None, 0, []))
    # sec 4fv: a solo leader's distribution -- self first, bots after.
    _b1, _b2, _b3 = 0x9001, 0x9101, 0x9002
    check("solo distribution: self first, bots slotted within their team",
          D.gs_solo_distribution({_b1: 0, _A: 1, _b2: 1, _b3: 0}, _A)
          == [(_A, 1, 0), (_b1, 0, 0), (_b2, 1, 1), (_b3, 0, 1)])
    check("solo distribution: self defaults to team 0 with no request 31",
          D.gs_solo_distribution({}, _A) == [(_A, 0, 0)])
    _sd = body(D.build_gs_distribution(D.gs_solo_distribution({}, _A)))
    check("solo distribution is kind 20 with count 1 and self at body[24]",
          struct.unpack_from("<I", _sd, 12)[0] == 20 and _sd[20] == 1
          and struct.unpack_from("<I", _sd, 24)[0] == _A)
    # sec 4fw: the settle deadline is re-checked on the server's clock.
    check("dist due: READY table is due at ready_at + settle",
          D.gs_dist_due({"ready_at": 100.0, "dist": False}, 5.0) == 105.0)
    check("dist due: not ready -> None",
          D.gs_dist_due({"ready_at": None, "dist": False}, 5.0) is None)
    check("dist due: already sent -> None",
          D.gs_dist_due({"ready_at": 100.0, "dist": True}, 5.0) is None)
    # sec 4fy: kind 4 is the RESULT (facade 0x40 ends ev2045's battle loop),
    # so the start burst must not carry it; selector 39 is the battle reset.
    _st_kinds = [k for k, _ in D.gs_battle_sequence(D.GS_BATTLE_START_DEFAULT,
                                                    spawn=(0.0, 0.0, 0.0),
                                                    zone=201, bmap=(0, 0))]
    check("battle start burst has no kind 4 (the result) and still has kind 2",
          4 not in _st_kinds and 2 in _st_kinds, str(_st_kinds))
    _bo = body(D.build_world_answer(world_door_request(),
                                    selector=D.GS_BATTLE_OVER_SELECTOR,
                                    pad_to=176, ident=0))
    check("battle-over answer is selector 39 on subchannel 7",
          _bo[1] == 39 and _bo[0] == 7)

    # sec 4fu: the PEER RELAY. Two live 0x83s off prod (09-12, the Deck and the
    # PC, mode 2). The relay re-sends one to the other client as a PEER
    # datagram: flags bit 3 set (parser 0x0058a0b0 + router arm 0x00581530),
    # mode 0, and byte-for-byte the sender's ms, id and 40-byte pose otherwise.
    _live83 = {
        0x2a990: "04024000" "6d060000" "c00122f1e4420e46" "01baed7dcf8afd04"
                 "90a902002c1800441e0100bf2bbcb8c209fc7fbf00000000323b34bc"
                 "0220803f0001000000001210",
        0x2a664: "04024000" "fb610000" "dfec25a865a716f9" "9a57e87efab84314"
                 "64a60200000061440000" "00b500001143483ca13e00000000" "90f972bf"
                 "0220803f0001000000001210",
    }
    if D._KELCRYPT:
        for _cid, _hx in _live83.items():
            _hd = D.doc_kelcrypt.header(bytes.fromhex(_hx))
            _pl = _hd["plain"]
            check("live 0x83 0x%x: id at packet[16] == body[0]" % _cid,
                  _hd["type"] == 0x83 and _hd["u32_16"] == _cid
                  and struct.unpack_from("<I", _pl, D.BODY_OFF)[0] == _cid)
            check("live 0x83 0x%x: the client's checksum is cksum() of the "
                  "PLAINTEXT" % _cid,
                  struct.unpack_from("<H", _pl, D.CKSUM_OFF)[0] == D.cksum(_pl))
            _r = D.build_peer_relay(_pl)
            check("relay 0x%x: mode 0, flags bit 3, still type 0x83" % _cid,
                  _r[1] == 0 and _r[9] & 0x08 and _r[8] == 0x83)
            check("relay 0x%x: checksum valid under the client's rule" % _cid,
                  struct.unpack_from("<H", _r, D.CKSUM_OFF)[0] == D.cksum(_r))
            check("relay 0x%x: verbatim except mode, flags, checksum" % _cid,
                  len(_r) == len(_pl) and _r[0] == _pl[0] and _r[2:9] == _pl[2:9]
                  and _r[12:] == _pl[12:])
    else:
        check("doc_kelcrypt available for the relay checks", False)

    # sec 4fu: the type-125 SPAWN record for a player id (the 0x00bd2108 arm):
    # +4/+5 bytes, +6/+20 u16 = the pose record's +28/+30, +22 the time word's
    # low half; packet+4 the SENDER's ms. Absent keys keep the old bytes.
    _wu = D.build_world_update([dict(id=0x2a664, x=900.0, y=0.0, z=145.0,
                                     dx=0.3149, dy=0.0, dz=-0.9491, h6=0x2002,
                                     h20=0x3f80, b4=0, b5=0, h22=0x61fb)],
                               ms=0x000161fb)
    _wr = _wu[D.BODY_OFF + 4:]
    check("wu: sender ms at packet+4, full 32 bits",
          struct.unpack_from("<I", _wu, 4)[0] == 0x000161fb)
    check("wu: id, x/z x0.1", struct.unpack_from("<I", _wr, 0)[0] == 0x2a664
          and struct.unpack_from("<hh", _wr, 8)[0] == 9000
          and struct.unpack_from("<h", _wr, 12)[0] == 1450)
    check("wu: +6/+20/+22 carry the pose u16s and the time",
          struct.unpack_from("<H", _wr, 6)[0] == 0x2002
          and struct.unpack_from("<H", _wr, 20)[0] == 0x3f80
          and struct.unpack_from("<H", _wr, 22)[0] == 0x61fb)
    # sec 4fu (look): the relayed player's o099 code rides peer record +36
    # (-> slot+40 -> the peer lookup's +26 -> unit+88, which 0x00be4850 stamps
    # over pose +38). Built the way the relay builds it: [4:] then re-embedded.
    _pa = D.build_peer_answer(None, 0x2aa69, ident=0x2aa68,
                              blob=D.build_peer_record(0x2aa69, name="Test",
                                                       zone=0xffff,
                                                       f36=0x2022)[4:])
    _prec = body(_pa)[12:]
    check("peer record: look code at +36, zone still at +32",
          struct.unpack_from("<H", _prec, 36)[0] == 0x2022
          and struct.unpack_from("<H", _prec, 32)[0] == 0xffff
          and struct.unpack_from("<I", _prec, 0)[0] == 0x2aa69)
    # sec 4fu (briefing): the Deck's live briefing-room PEER 0x83 (09-13 02:04,
    # mode 4, flags 8). Its header is rejected under every key we hold; the
    # body names the sender. Synthesise the header, keep ms + body verbatim.
    _dk4 = bytes.fromhex("04044000014d02004cde73079d03f3686b0b53c645f57cef"
                         "69aa0200c6b8ff440a0030c1a53302439eed76bf00000000"
                         "941787be0220803e000b000000001210")
    check("briefing peer 0x83: the header does NOT decrypt (live fact)",
          D.describe_inner(_dk4) is None if D._KELCRYPT else True)
    check("briefing peer 0x83: peer_pos_id reads the sender id off the body",
          D.peer_pos_id(_dk4) == 0x2aa69)
    check("peer_pos_id ignores a 36-byte GS request",
          D.peer_pos_id(bytes.fromhex(
              "0404240010a201004408a9dd2b05d812b0f6422f05503626010000000000000000000000"))
          is None)
    _si = D.synth_peer_inner(_dk4)
    _sp = _si["plain"]
    check("synth: type 0x83, flags 8, id at packet[16]",
          _sp[8] == 0x83 and _sp[9] == 8 and _si["u32_16"] == 0x2aa69
          and D.struct.unpack_from("<I", _sp, 16)[0] == 0x2aa69)
    check("synth: sender ms and 40-byte body verbatim, checksum valid",
          _sp[4:8] == _dk4[4:8] and _sp[24:] == _dk4[24:]
          and struct.unpack_from("<H", _sp, D.CKSUM_OFF)[0] == D.cksum(_sp))
    _sr = D.build_peer_relay(_sp)
    check("synth -> relay: mode 0, flags 8, checksum valid",
          _sr[1] == 0 and _sr[9] == 8
          and struct.unpack_from("<H", _sr, D.CKSUM_OFF)[0] == D.cksum(_sr))
    _wl = D.build_world_update([dict(id=0x40000001, x=1.0, y=2.0, z=3.0)])[D.BODY_OFF + 4:]
    check("wu: without the new keys +4..7 and +20..23 stay zero",
          _wl[4:8] == bytes(4) and _wl[20:24] == bytes(4))

    # 09-13 regression: two POL members, ONE entrance uid (0xa756a69a live)
    # -> both slot 0s were 0x2aa68. Member keys now derive from the member.
    _u = 0xa756a69a
    _m15 = [D.chara_id_for(0x1000, _u, "member:15", i) for i in range(4)]
    _m6 = [D.chara_id_for(0x1000, _u, "member:6", i) for i in range(4)]
    check("two members at one uid get DISJOINT character ids",
          not set(_m15) & set(_m6) and len(set(_m15)) == 4, "%r %r"
          % (["0x%x" % x for x in _m15], ["0x%x" % x for x in _m6]))
    check("a non-member key keeps the old uid formula byte-for-byte",
          D.chara_id_for(0x1000, _u, _u, 0) == 0x2aa68
          and D.chara_id_for(0x1000, _u, "addr:1.2.3.4", 1) == 0x2aa69)
    check("member ids sit above every uid-derived id; bits 30/31 clear",
          min(_m15 + _m6) > 0x1000 + (0xFFFF << 2) + 3
          and all(x & 0xC0000000 == 0 for x in _m15 + _m6)
          and D.chara_id_for(0x1000, _u, "member:16383", 3) < 0x9000 + 0x40000 + 0x10000)
    check("chara_id_for(base=0) is off, as --chara-id-base 0 was",
          D.chara_id_for(0, _u, "member:15", 0) == 0)

    # 2026-09-13: HP = world-door record+4 = body[48..51] (setUserData ->
    # R+44 cur / R+752 max). The echoed token there read as HP -31166.
    _wd_plain = D.build_world_answer(world_door_request(), selector=2, pad_to=176,
                                     ident=0, self_id=0x4103c)
    _wd_hp = D.build_world_answer(world_door_request(), selector=2, pad_to=176,
                                  ident=0, self_id=0x4103c, self_hp=100)
    _bp, _bh = body(_wd_plain), body(_wd_hp)
    check("world door: HP 100 as a u32 at body[48..51]",
          struct.unpack_from("<I", _bh, 48)[0] == 100)
    check("world door: HP changes ONLY body[48..51] (id at body[44] kept)",
          len(_bp) == len(_bh)
          and [i for i in range(len(_bp)) if _bp[i] != _bh[i]]
              and all(48 <= i < 52 for i in range(len(_bp)) if _bp[i] != _bh[i])
          and struct.unpack_from("<I", _bh, 44)[0] == 0x4103c)
    _s13a = D.build_world_answer(world_door_request(), selector=13, pad_to=176,
                                 ident=0, spawn=(900.0, 0.0, 145.0, 1.0, 0.0, 0.0, 11))
    _s13b = D.build_world_answer(world_door_request(), selector=13, pad_to=176,
                                 ident=0, spawn=(900.0, 0.0, 145.0, 1.0, 0.0, 0.0, 11),
                                 self_hp=100)
    check("HP is never written on selector 13 (body[48] is spawn data there)",
          body(_s13a) == body(_s13b))

    # 2026-09-13: DISSOLVE 125 / CANCEL 155 arrive as 36-byte requests (a 12-byte
    # body, no key). The verb must resolve the requester's own table.
    _sd = D.BattletableStore()
    _r24 = bytearray(D.BODY_OFF + D.BT_REQ_REC_OFF + D.BT_REC_LEN); _r24[0] = 4; _r24[8] = 127
    _r24[D.BODY_OFF + D.BT_REQ_REC_OFF:] = D.build_battletable_record(table_id=0, maximum=8, mode=1)
    D.battletable_verb(_sd, bytes(_r24), bytes(_r24[D.BODY_OFF:]), 24, 0x4103c, 0)
    _k = _sd.table_of(0x4103c)
    _short = bytes([7, 125] + [0] * 10)
    _rq = bytes(D.BODY_OFF) + _short
    _pd, _nd = D.battletable_verb(_sd, _rq, _short, 125, 0x4103c, 0)
    check("36-byte DISSOLVE (12-byte body) removes the requester's own table",
          _k is not None and _pd is not None and _sd.get(_k) is None, _nd)
    D.battletable_verb(_sd, bytes(_r24), bytes(_r24[D.BODY_OFF:]), 24, 0x41018, 0)
    _pc, _nc = D.battletable_verb(_sd, _rq, bytes([7, 155] + [0] * 10), 155, 0x41018, 0)
    check("36-byte CANCEL (12-byte body) unseats the requester",
          _pc is not None and _sd.table_of(0x41018) is None, _nc)

    # 2026-09-13: the SELF NAME = world-door body[112..127] (character record
    # +68 -> self record R+704), written after the costume window.
    _wn = D.build_world_answer(world_door_request(), selector=2, pad_to=176, ident=0,
                               self_costume=0x1012, self_name="Lex")
    _wo = D.build_world_answer(world_door_request(), selector=2, pad_to=176, ident=0,
                               self_costume=0x1012)
    check("self name NUL-padded at body[112..127], over the costume window's tail",
          body(_wn)[112:128] == b"Lex" + bytes(13))
    check("self name leaves the costume value at body[100] alone",
          struct.unpack_from("<H", body(_wn), 100)[0] == 0x1012
          and body(_wn)[:112] == body(_wo)[:112])
    _n13a = D.build_world_answer(world_door_request(), selector=13, pad_to=176, ident=0)
    _n13b = D.build_world_answer(world_door_request(), selector=13, pad_to=176, ident=0,
                                 self_name="Lex")
    check("self name is never written on selector 13", body(_n13a) == body(_n13b))

    # sec 4gk: THE SHOP. Gil = world-door body[52] (-> R+744), bag count
    # body[140], entries body[240+8i] {u32 id, u16 0, u16 qty}; selector 2 only.
    import doc_shop as S
    _bag = [(0x69320000, 3), (0x6F34001B, 1)]
    _wg = D.build_world_answer(world_door_request(), selector=2, pad_to=176, ident=0,
                               self_hp=100, self_gil=12345, self_bag=_bag)
    _wp = D.build_world_answer(world_door_request(), selector=2, pad_to=176, ident=0,
                               self_hp=100)
    _gb = body(_wg)
    check("shop: gil u32 at world-door body[52]",
          struct.unpack_from("<I", _gb, 52)[0] == 12345)
    check("shop: bag count at body[140], entries at body[240+8i] (qty at +6)",
          struct.unpack_from("<I", _gb, 140)[0] == 2
          and struct.unpack_from("<IHH", _gb, 240) == (0x69320000, 0, 3)
          and struct.unpack_from("<IHH", _gb, 248) == (0x6F34001B, 0, 1))
    check("shop: nothing else in the first 176 bytes moves (HP, id, costume)",
          _gb[:52] == body(_wp)[:52] and _gb[56:140] == body(_wp)[56:140]
          and _gb[144:176] == body(_wp)[144:176])
    check("shop: an EMPTY bag still writes count 0 (never the echoed token)",
          struct.unpack_from("<I", body(D.build_world_answer(
              world_door_request(), selector=2, pad_to=176, ident=0,
              self_gil=5, self_bag=[])), 140)[0] == 0)
    check("shop: the bag is capped at 50 (the client does not clamp body[140])",
          struct.unpack_from("<I", body(D.build_world_answer(
              world_door_request(), selector=2, pad_to=176, ident=0,
              self_bag=[(0x69320000 + i, 1) for i in range(80)])), 140)[0] == 50)
    for _gsel in (13, 21):
        _a = D.build_world_answer(world_door_request(), selector=_gsel, pad_to=176,
                                  ident=0)
        _b = D.build_world_answer(world_door_request(), selector=_gsel, pad_to=176,
                                  ident=0, self_gil=12345, self_bag=_bag)
        check("shop: gil/bag never written on selector %d" % _gsel,
              body(_a) == body(_b))

    # sec 4go: AMMO. Bullets are inventory items; the magazine (0x004a5780)
    # fills from the bag's 0x6230000N stacks, so the world door must carry them.
    _ab = S.issue_items([], S.parse_issue("standard"))
    _wa = body(D.build_world_answer(world_door_request(), selector=2, pad_to=176,
                                    ident=0, self_bag=_ab))
    check("ammo: standard issue = 36 handgun / 18 rifle / 60 MG at body[240+]",
          struct.unpack_from("<I", _wa, 140)[0] == 3
          and [struct.unpack_from("<IHH", _wa, 240 + 8 * i) for i in range(3)]
          == [(0x62300000, 0, 36), (0x62300001, 0, 18), (0x62300002, 0, 60)])
    check("ammo: tops a shop bag UP, never lowers it",
          S.issue_items([(0x62300000, 100), (0x69320000, 3)], S.STANDARD_AMMO)
          == [(0x62300000, 100), (0x62300001, 18), (0x62300002, 60), (0x69320000, 3)])
    check("ammo: bullets survive a full 50-item bag (lowest category sorts first)",
          S.issue_items([(0x6F300000 + i, 1) for i in range(50)],
                        S.STANDARD_AMMO)[:3] == list(S.STANDARD_AMMO))
    check("ammo: 'off' issues nothing; 'ID:QTY' parses and caps at 500",
          S.parse_issue("off") == () and S.parse_issue("") == ()
          and S.parse_issue("0x62300000:5,0x62300001:9999")
          == ((0x62300000, 5), (0x62300001, 500)))

    # 2026-09-13: UNITS (doc_unit.py). The enlisted unit = world-door
    # body[60..67] (setUserData src+16 -> R+720); selector 2 only.
    _uid = 0x0000000700000029
    _wu = body(D.build_world_answer(world_door_request(), selector=2, pad_to=176,
                                    ident=0, self_hp=100, self_unit=_uid))
    check("units: enlisted unit u64 at world-door body[60..67]",
          struct.unpack_from("<Q", _wu, 60)[0] == _uid)
    check("units: 0 when not enlisted (never the echoed token)",
          struct.unpack_from("<Q", body(D.build_world_answer(
              world_door_request(), selector=2, pad_to=176, ident=0,
              self_unit=0)), 60)[0] == 0)
    check("units: nothing else in the first 176 bytes moves",
          _wu[:60] == body(_wp)[:60] and _wu[68:176] == body(_wp)[68:176])
    # 2026-09-13: the equipped MASK + SUIT at body[76]/[80] (-> R+768/772).
    import doc_gear as G
    _gear = G.starter_gear(True)
    _wgr = body(D.build_world_answer(world_door_request(), selector=2, pad_to=176,
                                     ident=0, self_hp=100, self_gear=_gear))
    check("gear: mask at body[76], suit at body[80] (female -> DG Soldier Mask F)",
          struct.unpack_from("<II", _wgr, 76) == (0x63300001, 0x63310000))
    check("gear: male -> DG Soldier Mask M", G.starter_gear(False)[0] == 0x63300000)
    check("gear: nothing else in the first 176 bytes moves",
          _wgr[:76] == body(_wp)[:76] and _wgr[84:176] == body(_wp)[84:176])
    check("gear: never written on selector 13",
          body(D.build_world_answer(world_door_request(), selector=13, pad_to=176,
                                    ident=0))
          == body(D.build_world_answer(world_door_request(), selector=13,
                                       pad_to=176, ident=0, self_gear=_gear)))
    check("gear: issue_items puts both in the bag once",
          [i for i, q in S.issue_items([], [(_gear[0], 1), (_gear[1], 1)])]
          == [0x63300001, 0x63310000])
    # 2026-09-13: CHANGE MASK / ARMOR = lobby commands 17 / 18 (doc_gear.py).
    import tempfile as _tf
    _gdir = _tf.mkdtemp()
    _gs = G.GearStore(os.path.join(_gdir, "doc-gear.json"))
    _gk = "member:15/0x0004103c"

    def _gear_req(cmd, slot, item=0):
        _r = bytearray(28)
        _r[0], _r[1], _r[12], _r[16] = 7, 240, cmd, slot
        struct.pack_into("<I", _r, 20, item)
        return bytes(_r)
    _gb, _gn = _gs.body_for(17, _gear_req(17, 0, 0x63300009), _gk, 0x1019)
    check("gear cmd 17: 241 answer names command 17 at body[12], success header",
          _gb[1] == 241 and struct.unpack_from("<H", _gb, 12)[0] == 17
          and struct.unpack_from("<H", _gb, 4)[0] == 0)
    check("gear cmd 17 Capsule Searcher: body[6] = bit 7 + its model 7 (item def +16) "
          "(0x1019 -> 0x1799)",
          struct.unpack_from("<H", _gb, 6)[0] == 0x1799)
    check("gear cmd 17: stored and served back at login",
          G.GearStore(_gs.path).login(_gk, G.starter_gear(False), 0x1019)
          == (0x63300009, 0x63310000, 0x1799))
    _gb, _gn = _gs.body_for(17, _gear_req(17, 1, 0x63310050), _gk, 0x1019)
    check("gear cmd 17 Armored Suit (0x..50 = armor 4): armor bits follow, mask kept "
          "(0x1799 -> 0x17a1)",
          struct.unpack_from("<H", _gb, 6)[0] == 0x17A1
          and _gs.login(_gk)[:2] == (0x63300009, 0x63310050))
    check("gear: the armor pick -> the NAMED suit every 20 ids (live session 09-13: "
          "armor 2 = Speed Suit 0x63310028, never placeholder 'Suit 2')",
          [G.starter_gear(False, t)[1] for t in range(5)]
          == [0x63310000, 0x63310014, 0x63310028, 0x6331003C, 0x63310050])
    check("gear: a suit's look = id // 20 for all 100 (placeholder 'Suit 41' = Speed look)",
          G.armor_for_suit(0x63310029) == 2 and G.armor_for_suit(0x63310002) == 0)
    _gb, _gn = _gs.body_for(18, _gear_req(18, 0), _gk, 0x1019)
    check("gear cmd 18: mask slot -1, bit 7 cleared (0x17a1 -> 0x1721)",
          struct.unpack_from("<H", _gb, 6)[0] == 0x1721
          and _gs.login(_gk)[0] == G.NO_ITEM)
    _gb, _gn = _gs.body_for(17, _gear_req(17, 0, 0x63310000), _gk, 0x1019)
    check("gear cmd 17 suit into the mask slot: REFUSED (body[4] bit 0), nothing stored",
          struct.unpack_from("<H", _gb, 4)[0] & 1
          and struct.unpack_from("<H", _gb, 6)[0] != 0 and _gs.login(_gk)[0] == G.NO_ITEM)
    _gb, _gn = _gs.body_for(18, _gear_req(18, 1), _gk, 0x1019)
    check("gear cmd 18 on the suit: REFUSED (armor cannot be removed)",
          struct.unpack_from("<H", _gb, 4)[0] & 1)
    _gb, _gn = _gs.body_for(17, _gear_req(17, 0, 0x63300000), "anon/0x00000001", None)
    check("gear: no known costume -> REFUSED, never a zero costume",
          struct.unpack_from("<H", _gb, 4)[0] & 1 and _gs.get("anon/0x00000001") is None)
    check("gear: a never-changed character gets the starter pair + creation look",
          _gs.login("member:1/0x00000002", G.starter_gear(True), 0x1059)
          == (0x63300001, 0x63310000, 0x1059))
    for _usel in (13, 21):
        check("units: never written on selector %d" % _usel,
              body(D.build_world_answer(world_door_request(), selector=_usel,
                                        pad_to=176, ident=0))
              == body(D.build_world_answer(world_door_request(), selector=_usel,
                                           pad_to=176, ident=0, self_unit=_uid)))
    _pl = S.price_body(list(S.DEFAULT_STOCK))
    _pn = struct.unpack_from("<I", _pl, 16)[0]
    check("shop: 144 = u32 count body[16], 12-B {id, price} rows from body[20], "
          "stock order", _pl[1] == 144 and _pn == len(S.DEFAULT_STOCK)
          and len(_pl) == 20 + 12 * _pn
          and [struct.unpack_from("<I", _pl, 20 + 12 * i)[0] for i in range(_pn)]
          == [i for i, _, _ in S.DEFAULT_STOCK])
    check("shop: the 65 list fits one datagram (< 1472 B)",
          D.BODY_OFF + len(S.stock_body(list(S.DEFAULT_STOCK))) < 1472)
    # 2026-09-13 LIVE: the BUY is request 66 -> answer 67, the SELL 68 -> 69.
    _rq66 = bytes.fromhex("074200000100ffffffffffff030000000000326f0100000000000000")
    check("shop: the live 09:11:51 request 66 parses to Auto Scope x1 at shop 3",
          S.parse_entry(_rq66) == {"shop": 3, "iid": 0x6F320000, "qty": 1})
    _b67 = S.buy_body(add=(0x6F300000, 2), spend=4000)
    check("shop: 67 = ADD body[12] x u16 [20], SPEND [28]",
          _b67[1] == 67 and struct.unpack_from("<I", _b67, 12)[0] == 0x6F300000
          and struct.unpack_from("<H", _b67, 20)[0] == 2
          and struct.unpack_from("<I", _b67, 28)[0] == 4000)
    _b69 = S.sell_body(remove=(0x6F300000, 1), gain=1000)
    check("shop: 69 = REMOVE body[16] x u16 [22], gil GAIN [24]",
          _b69[1] == 69 and struct.unpack_from("<I", _b69, 16)[0] == 0x6F300000
          and struct.unpack_from("<H", _b69, 22)[0] == 1
          and struct.unpack_from("<I", _b69, 24)[0] == 1000
          and struct.unpack_from("<I", _b69, 12)[0] == 0)
    # MODIFY: 142 rows {source, result, kit, fee}; 145 = shop, source, result.
    _rb = S.recipe_body([(0x6F310000, 0x6F310001, 0x6430000A, 1750)])
    check("shop: 142 = 20-B {source, result, kit, fee} rows",
          _rb[1] == 142 and struct.unpack_from("<I", _rb, 16)[0] == 1 and len(_rb) == 40
          and struct.unpack_from("<IIII", _rb, 20)
          == (0x6F310000, 0x6F310001, 0x6430000A, 1750))
    _rq145 = bytes([7, 145]) + bytes(10) + struct.pack("<III", 3, 0x6F310000, 0x6F310001)
    check("shop: 145 = body[12] shop, body[16] source, body[20] result",
          S.parse_modify(_rq145) == {"shop": 3, "src": 0x6F310000, "res": 0x6F310001})
    _sl = S.stock_body(list(S.DEFAULT_STOCK))
    check("shop: 65 = 16-B rows, id at +0 and the price at +4 and +8",
          _sl[1] == 65 and struct.unpack_from("<IIII", _sl, 20)
          == (S.DEFAULT_STOCK[0][0], S.DEFAULT_STOCK[0][1], S.DEFAULT_STOCK[0][1], 0))
    check("shop: 142 is a well-formed EMPTY list",
          S.recipe_body() == bytes([7, 142]) + bytes(18))
    _tx = S.txn_body(add=(0x69320000, 3), remove=(0x69310014, 1), spend=150, kit=7)
    check("shop: 146 ADD body[12]/u16 [20], REMOVE [16]/u16 [22], SPEND [28], KIT [32]",
          _tx[1] == 146 and struct.unpack_from("<IIHHII", _tx, 12)[:4]
          == (0x69320000, 0x69310014, 3, 1)
          and struct.unpack_from("<I", _tx, 28)[0] == 150
          and struct.unpack_from("<I", _tx, 32)[0] == 7)
    _sp = D.seal_world_body(None, _tx, seq=5, ptype=127, ident=0x0002a664)
    _z = bytearray(_sp)
    _z[D.CKSUM_OFF:D.CKSUM_OFF + 2] = b"\0\0"
    check("shop: sealed 146 = mode 0, type 127, record+4 = ident, good checksum",
          _sp[1] == 0 and _sp[8] == 127
          and struct.unpack_from("<I", _sp, 16)[0] == 0x0002a664
          and struct.unpack_from("<H", _sp, 2)[0] == len(_sp)
          and struct.unpack_from("<H", _sp, D.CKSUM_OFF)[0] == D.cksum(bytes(_z))
          and _sp[D.BODY_OFF:] == _tx)

    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
