# CrystalDirge

A server for the online mode of Dirge of Cerberus: Final Fantasy VII, the
2006 PlayStation 2 release whose multiplayer ran through PlayOnline in Japan.
It plugs into [OpenLobby](https://github.com/PrettyOpenLobby/OpenLobby), the
PlayOnline core, and answers the game's own world channel: the lobby, the
character roster, the shop, the units, the rankings and the battles.

This is a clean-room reimplementation from protocol observation. It contains
no Square Enix code, art or data. You need your own copy of the game and your
own PlayOnline install on a PlayStation 2 hard disk; see below.

## What it does today

Tested on a private deployment with an emulated console. On this stack a
console can:

- log in through the core, resolve `kel-1001.pol.com` and enter the online
  lobby;
- create, name and delete characters (persistent, per PlayOnline member);
- see the user list and the other players' characters walking in the lobby;
- talk to the lobby NPCs (instructors, briefers, clerks, registrars);
- use the shop (a server-owned stock with placeholder prices, a per-character
  wallet and bag, a starter set of both guns), equip mask and armour;
- register and manage a unit (a PlayOnline friend-list group);
- reserve a battle table, sortie into the arena, fight, see the result screen
  and return to the lobby, with a career (rank, rank points, medals, play
  time) that the rankings and the PlayOnline profile read back.

What it does not do: the online story zones (the Kerberos event stages) are
not on the retail disc sets we have seen; the "online events" data the game
asks for is missing from the US build entirely and from the JP build past
what the lobby needs. Player trade is relayed but the client-side flow has
only been seen from one side. Several replies carry values that were found
to work on the private deployment before their meaning was decoded;
`docker-compose.yml` and the comments in `tools/docudp.py` say which.

## How it fits the core

The core (OpenLobby) does the login, the DNS and the member profile; this
repository is one UDP service, `docudp.py`, on port 55040. It joins the core's
data volume read-only, to learn which PlayOnline member is signed in at each
console's address, and the core's logs volume, where it keeps its stores
(characters, careers, shop, units, rankings) as JSON files. The core's lobby
reads two of those files to fill the game's content profile (character name,
rank, ranking points) in the PlayOnline Viewer.

## Prerequisites

- The core lobby stack (OpenLobby) running on the same Docker host
- Docker with Compose v2
- A Japanese Dirge of Cerberus disc with the online mode, and a PlayOnline
  install on a PlayStation 2 hard disk (real hardware, or an emulator that
  boots from a hard-disk image). OpenLobby's README, "PlayStation 2 clients",
  says what that install needs (the DNAS console-binding check defeated on
  your own copy, DNS pointed at the server). None of that is provided here.

## Bring-up

```
cp .env.example .env        # set POL_ADVERTISE to your server's LAN/VPN IP
docker compose up -d --build
```

`POL_ADVERTISE` must be the address the console reaches this host on; it is
handed to the game inside the protocol. The core's DNS answers
`kel-1001.pol.com` with the same address. Nothing needs to be configured on
the console beyond the DNS/hosts redirection already done for the core.

Every flag the service runs with is listed in `docker-compose.yml`, with a
comment where its value is a working guess; `python tools/docudp.py --help`
documents them all.

## The lobby NPCs

The lobby's non-player characters are placed by the server (the game skips
its own placement loop online). Their positions are the game's own level
data, so they do not ship: `--npc-spawn` stays off until you put a
`tools/doc_npc_table.json` beside the code, shaped
`{"npcs": [[number, record, type, x, y, z, dir_x, dir_z, "motion"], ...]}`,
one row per standing NPC of the lobby zone's character table. No tool to
read that table out of your own copy is provided yet.

## Selftests

```
python tools/doc_run_all.py
```

runs every suite: the cipher (the published Twofish known-answer test, then
packets of every mode and length round-tripped), every measured wire offset
the responder ships, the character store, careers, play time, NPCs, the
shop, rankings, units, gear and trade. Nothing opens a socket.

## What is not included, and why

- No game data. The NPC placement table (above) is the only game-data
  input the server reads, and it is not included.
- No carved client code. The game enciphers each datagram's inner header
  with Twofish under two compile-time keys; `tools/doc_kelcrypt.py` is a
  clean-room implementation of standard Twofish from the published
  specification, checked against the published test vector.
- No PlayStation 2 installer, image, patch or DNAS workaround (OpenLobby's
  README explains the console side).

## License

AGPL-3.0 (see LICENSE).

## Credits

- The PlayOnline preservation community.
- Bruce Schneier and the Twofish team, for publishing the cipher.
