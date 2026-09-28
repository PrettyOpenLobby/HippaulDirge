-- Dirge of Cerberus durable player state, formerly JSON files the world
-- responder kept on the logs volume.
--
-- CrystalDirge's migrations are numbered 5001..5999 because they share
-- OpenLobby's schema_migrations table, which is keyed by version alone. Every
-- table here starts with doc_. None has a foreign key into the account
-- tables: the keys are the ones the game already used (a member, an address,
-- an entrance uid), and a row outliving a deleted member is what the files
-- did too.
--
-- Every table has the same shape, one row per key of the old file:
--
--     key         the file's key, unchanged
--     data        the value under that key, as JSON text
--     updated_at  when the responder last wrote the row
--
-- `data` is JSON, not JSONB, on purpose: JSON keeps the text it was given,
-- so an object comes back with its keys in the order they were written
-- (sorted, as the files wrote them). JSONB reorders object keys, and a bag or
-- a medal table is served to the client in iteration order.
--
-- The key column is compared with COLLATE "C" by the code that lists a
-- table, so rows come back in the byte order the files were sorted in.

-- doc-characters.json: each account's roster (a list of up to four
-- characters, each {slot, name, gender, app92, app93, voice}). The key is
-- member:<id>, addr:<ip>, a configured --account, or an entrance uid 0x....
CREATE TABLE doc_character (
    key        TEXT PRIMARY KEY,
    data       JSON NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- doc-ip-members.json: the member last resolved at a client address,
-- {key, at}, the resolver's fallback once POL has purged the session row.
CREATE TABLE doc_ip_member (
    key        TEXT PRIMARY KEY,
    data       JSON NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- doc-shop.json: each character's wallet {gil, bag, kit marks}. The key is
-- the wallet key member:<id>/0x<charid>, which the careers, the gear, the
-- play time and the units use too.
CREATE TABLE doc_wallet (
    key        TEXT PRIMARY KEY,
    data       JSON NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- doc-gear.json: each character's equipped mask and suit and its costume
-- code {mask, suit, costume}.
CREATE TABLE doc_gear (
    key        TEXT PRIMARY KEY,
    data       JSON NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- doc-playtime.json: whole seconds played per character (a JSON number).
CREATE TABLE doc_playtime (
    key        TEXT PRIMARY KEY,
    data       JSON NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- doc-stats.json, "chars": each character's career (rank, rank points,
-- W-L per mode, medals, the mission ledger, the novice marks).
CREATE TABLE doc_career (
    key        TEXT PRIMARY KEY,
    data       JSON NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- doc-stats.json, "weekly": each week's tallies for the weekly medals. The
-- key is the week's start in unix seconds.
CREATE TABLE doc_week (
    key        TEXT PRIMARY KEY,
    data       JSON NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- doc-stats.json, "weeks_closed": the verdict of each week already closed,
-- so a week pays its medals once.
CREATE TABLE doc_week_closed (
    key        TEXT PRIMARY KEY,
    data       JSON NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- doc-rankings.json, "chars": each character's ranking values {name, id,
-- ind: {category: value}}.
CREATE TABLE doc_rank_char (
    key        TEXT PRIMARY KEY,
    data       JSON NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- doc-rankings.json, "units": unit ranking values {name, unit: {category:
-- value}} set by hand; the registered units are ranked from doc_unit.
CREATE TABLE doc_rank_unit (
    key        TEXT PRIMARY KEY,
    data       JSON NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- doc-units.json, "units": each registered unit {name, emblem, cls, area,
-- pts, stats, registrant, members, created}. The key is the unit id in hex.
CREATE TABLE doc_unit (
    key        TEXT PRIMARY KEY,
    data       JSON NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- doc-units.json, "enlist": the unit each character is enlisted in (the
-- unit id in hex, as a JSON string).
CREATE TABLE doc_unit_enlist (
    key        TEXT PRIMARY KEY,
    data       JSON NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
