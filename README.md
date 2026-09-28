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
  time) that the rankings and the PlayOnline profile read back;
- play the team modes on the server's rules (Team Battle, Team Base with
  base occupation, Team Capsule, Team Leader, Unit Battle), with one shared
  start per battle room, per-team start points, respawn, the kill ledger and
  the medals it names, and the rank point cost of leaving a running battle;
- take Mission Mode: a per-player mission ledger the promotion-exam
  instructors grant exams into, missions listed by rank class, each mission's
  arena, enemies, time limit and initial supplies, and the reward notice the
  lobby prints;
- cast magic against a server-owned MP ledger, use Potions and Ethers, pick up
  ammunition and items on the field, and drop them for teammates;
- see the new-player intro and the Beginner mark, and do the lobby item
  quests (Soar, Este-D, Hiren) and Argento's story chain;
- chat in the lobby: say, shout, tell, entry and team, each to the players in
  its scope.

The later items in that list were built from reading the client and are
covered by the end-to-end scripts below; not every one of them has been
played through on a console yet.

What it does not do: the online story zones (the Kerberos event stages) are
not on the retail disc sets we have seen; the "online events" data the game
asks for is missing from the US build entirely and from the JP build past
what the lobby needs. Player trade is relayed but the client-side flow has
only been seen from one side. Several replies carry values that were found
to work on the private deployment before their meaning was decoded;
`docker-compose.yml` and the comments in `tools/docworld/` say which.

## How it fits the core

The core (OpenLobby) does the login, the DNS and the member profile; this
repository is one UDP service, `docudp.py`, on port 55040. It joins the core's
data volume read-only, to learn which PlayOnline member is signed in at each
console's address, and the core's logs volume, where it keeps its stores
(characters, careers, shop, units, rankings) as JSON files. The title plugin
below reads two of those files to fill the game's content profile (character
name, rank, ranking points) in the PlayOnline Viewer.

## The title plugin (the Viewer's profile)

The core builds the profile the Viewer shows for a Dirge of Cerberus Content ID from
data only this title holds, so a small plugin runs inside the core's `login`
and `authsess` processes (OpenLobby's `services/titles.py`, `POL_TITLES`).
`Dockerfile.title` layers it on the core image and `docker-compose.title.yml`
swaps that image into those two services. From this directory, with the core
checked out beside it:

```
docker compose --project-directory ../openlobby     -f ../openlobby/docker-compose.yml -f docker-compose.title.yml     up -d --build login authsess
```

Without it the game plays the same; only the Viewer's profile screen for a Dirge Content ID stays empty. The plugin reads the character and stats files the responder keeps on the core's logs volume. To run several titles, build each title image on the previous
one (`OPENLOBBY_IMAGE`) and list them all in `POL_TITLES` in OpenLobby's
`.env`, for example `POL_TITLES=tmtitle,doctitle`.

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

Without building, from the image published to
`ghcr.io/prettyopenlobby/crystaldirge` on every push:

```
docker compose -f docker-compose.yml -f docker-compose.ghcr.yml up -d
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

## Arena data

Three more inputs are the arenas' own level data and do not ship either. Each
is optional; the server runs without it.

- `tools/doc_mission_spawns.json`: the mission controllers' enemy spawn
  nodes, `{zone: {controller: {"count": n, "spawn": [[x, y, z], ...], ...}}}`.
  Without it mission enemies have no spawn points.
- `tools/doc_item_generators.json`: the arenas' item generator nodes and item
  sets, `{zone: {"sets": {i: [[item, qty, weight], ...]}, "situations": {sit:
  [[x, y, z, set], ...]}}}`. Without it nothing appears on the field by itself
  (the players' own drops and the capsules still do), and the Fuzzy Seed of
  the church missions is not placed.
- `tools/doc_arena_table.json`: the team base and team start positions,
  `{"base_positions": {zone: [[x, y, z], [x, y, z]]}, "team_starts": {zone:
  [[x, y, z], [x, y, z]]}}`. Without it both teams use the arena spawn and
  Team Base occupation has no spots to stand on.

## Selftests

```
python tools/doc_run_all.py
```

runs every suite: the cipher (the published Twofish known-answer test, then
packets of every mode and length round-tripped), every measured wire offset
the responder ships, the character store, careers, play time, NPCs, the
shop, rankings, units, gear, trade, missions, the novice mark, the lobby item
quests, rewards, magic, items, the field and chat. Nothing opens a socket.

The `tools/doc_*_e2e.py` scripts and `tests/test_doc_session_nat.py` go one
step further: each starts a real `docudp.py` on a loopback port and drives it
with synthetic client datagrams (a battle from table to result screen, the
chat scopes, the mission supplies, two consoles behind one address, and so
on). Run any of them with `python <script>` from its own directory.

## What is not included, and why

- No game data. The NPC placement table and the arena data (above) are the
  only game-data inputs the server reads, and none of them is included.
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
