"""The Dirge of Cerberus world responder (UDP 55040), one module per concern.

    deps.py          The imports every module shares, and the optional cipher (doc_kelcrypt).
    framing.py       The datagram: header offsets, the client's checksum, packet decoding for the log, the generic reply and the reliable ACK.
    handshake.py     The entrance: the subtype-3 server list and the type-129 reply that advances the lobby nest.
    charrecords.py   The character roster: character ids, the 96-byte wire record and the CHARAMAKE answer.
    worlddoor.py     The world-door answer (selector 1 -> 2 and the type-0x7f bodies built on it).
    worldchannel.py  The type-127 selector channel: selector names, request bodies, sealing an answer, the sender's ids.
    lobbycmd.py      Lobby commands (selector 240/241): command ids, the clock, and the table and quest command numbers.
    arenamaps.py     Maps and places: the lobby spawn descriptor and map-picker mask (selector 13), the lobby zone, and which arena zone, pieces and spawn each map uses.
    peerrecords.py   Other players as the client caches them: the 56-byte user record (selectors 19 and 37) and the cache-miss request.
    userlist.py      The lobby user list (selectors 10/11 and 18/19).
    worldpose.py     Positions in the lobby: the client's own uid and pose, the type-125 world update and the relayed position broadcast.
    tablerecords.py  The 120-byte battletable record: its offsets and flag bits, the browser list and the --battletable-list spec.
    tableverbs.py    The battletable store and the console's table verbs: create, config, join, reserve, cancel, dissolve, invite.
    questlist.py     The Solo quest list (selector 160), the mission list (selector 148) and the quest detail's map field.
    advertise.py     The address a client is handed, chosen per client (POL_ADVERTISE_PUBLIC / _LAN), and the table record stamped with it.
    gamemsg.py       The game-server channel (inner type 130): the request/answer ladder, the notify kinds and their builders.
    battleroom.py    One battle: the rules its table record asks for (BattleRules), the running room (BattleRoom), rank point and unit gates.
    teamdist.py      The player distribution (notify kind 20): when a table is ready, the automatic teams, rebalancing a one-sided table, the Solo briefing.
    briefingroom.py  The briefing room (selector 38's ready roster, a Solo quest as a mission) and the burst that starts a battle.
    arenadata.py     Arena data read from the user's own files: mission spawns, NPC controllers, team bases and starts, base reports and occupation.
    p2pbattle.py     The battle layer between consoles (P2P types): decoding shots, damage and pick-ups the server has to see.
    fielditems.py    Items on the battlefield: field item notices, capsules (pick-up, drop, hold, scoreboard) and dropped items.
    cli.py           The command line (--help): the tool's usage text and every flag.
    worldserver.py   main(): the socket, the per-session state and the event loop that answers every datagram, and the --sweep table.

docudp.py (one directory up) is the entry point and the compatibility
facade over these modules.
"""
