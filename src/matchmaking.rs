//! Session manager (port 7314): the client's own room protocol.
//!
//! The stream is fixed-size big-endian records, each starting with a u32
//! type whose size is fixed per type (the same record family as the sibling
//! uc3-server's matchmaking.rs). Records are reassembled from the TCP stream,
//! so coalesced or split reads are handled.
//!
//! Room behaviour, as the client requires it:
//!   * RoomCreate is answered with Member(solo, own player id) + HostFlagUpdated
//!     (1 for a game room, 0 for a party: a nonzero party flag hides "Join
//!     Party" from friends) + OwnerChanged, after a short delay; never with
//!     RoomJoined (0x132), which registers a phantom member.
//!   * Every room id is minted here (party 0x6…, public 0x5…, private 0x7…,
//!     low word = the client's room-object address): client-sent ids collide.
//!   * A room is public only if its +0x0c field is a known matchmaking
//!     playlist; a party is never public. Searches get the live public rooms
//!     of the same playlist and build, except for a live host (its search
//!     object is its room object).
//!   * A solo game-room owner gets its roster re-sent every 10 s (keeps the
//!     client's room id nonzero); multi-member and party rooms never do. The
//!     re-send is built from the live room, byte-identical to what the owner
//!     already holds (team, data blob): the client de-duplicates roster
//!     entries by comparing them, and a differing copy showed the owner's
//!     name twice on retail consoles.
//!   * Members are identified by the full 36-byte player id from their
//!     ClientHello (+8), not only the 16-byte online id: a searcher reaches
//!     the host through the player id in the search result.
//!   * Joins push the grown roster to existing members first, then admit the
//!     joiner, then replay each member's 32-byte data blob (harvested from
//!     RoomCreate/RoomJoin/0x13a) to the others.
//!   * Kicks and promotions come only from the room owner; an automatic kick
//!     (requester 0) is acted on only when late and the target is silent.
//!   * A member leaving a party gets a fresh solo party room id, because its
//!     own leave code zeroes the id and only the server can restore it.
//!   * An owner leaving or vanishing closes the room for everyone left.
//!     Ownership follows promotions, so a promoted party survives its old
//!     leader leaving.
//!   * Lifecycle: a connection silent for three ping periods is gone (a
//!     crashed console never closes TCP); a player connecting again ends its
//!     old session; a new game (party) room replaces the creator's previous
//!     one; a repeated join is answered without adding the player twice.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::log::hex;
use crate::presence::Presence;
use crate::{debug, info, warn};

const CLIENT_HELLO: u32 = 0x12d;
const SERVER_HELLO: u32 = 0x12e;
const ROOM_CREATE: u32 = 0x12f;
const ROOM_JOIN: u32 = 0x130;
const MEMBER: u32 = 0x131;
const ROOM_LEAVING: u32 = 0x133;
const ROOM_LEAVE: u32 = 0x134;
const FIND_MATCH: u32 = 0x135;
const ROOM_SEARCH: u32 = 0x136;
const KICKOUT: u32 = 0x137;
const KICKEDOUT: u32 = 0x138;
const ROOM_CLOSED: u32 = 0x139;
const SET_PARTY_DATA: u32 = 0x13a;
const MEMBER_BLOB: u32 = 0x13b;
const PROMOTE: u32 = 0x13c;
const OWNER_CHANGED: u32 = 0x13d;
const SET_HOST_FLAG: u32 = 0x13e;
const HOST_FLAG_UPDATED: u32 = 0x13f;
const SET_ROOM_FLAGS: u32 = 0x140;
const UPDATED_ROOM_FLAGS: u32 = 0x141;
const HOST_RANK: u32 = 0x142;
const SET_ROOM_DATA: u32 = 0x143;
const ROOM_DATA_UPDATED: u32 = 0x144;
const PING: u32 = 0x145;
const CLIENT_HELLO2: u32 = 0x146;

/// Player id: online id (16) + terminator/padding (4) + opt (8) + reserved (8).
const PLAYER_ID_LEN: usize = 36;
const OWNER: u16 = 1;
const FIRST_JOINER: u16 = 2;
/// Retail lobbies hold 8 players in every mode.
const RETAIL_MAX_PLAYERS: u16 = 8;
/// The client copies search results into a fixed array (24 slots in the
/// sibling UC3 client); never send more.
const MAX_SEARCH_RESULTS: usize = 24;
const LATE_KICKOUT: Duration = Duration::from_secs(5);
const DEAD_PEER_SILENCE: Duration = Duration::from_secs(75);
/// The client pings (0x145) every 30 s in every state, matches included
/// (retail console, 2026-10-22). Three missed pings mean the console is gone:
/// a crashed or unplugged console never closes its TCP connection, and its
/// rooms must not stay listed or keep their members waiting.
const IDLE: Duration = Duration::from_secs(95);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BUFFER: usize = 0x4000;

/// Client builds, recognised by their static game/party room objects (the
/// pointer the client sends at RoomCreate/RoomJoin +8, RoomSearch +8).
const BUILDS: [(&str, u32, u32); 2] = [
    ("01.00", 0x0138_3bd8, 0x0138_7f58),
    ("01.11", 0x013b_abd8, 0x013b_f068),
];
/// Matchmaking playlist ids (RoomCreate/RoomSearch +0x0c) of the menus'
/// three Find Match variants per mode: 01.00 has 2 and 3; 01.11 has 1-3,
/// 6-8 and 11-13. A room with one of these ids is public even without the
/// key below.
const PLAYLISTS: [u32; 9] = [1, 2, 3, 6, 7, 8, 11, 12, 13];

/// The `*playlists*` table of each build's network data (01.11: net10.bin
/// and the update's local copies, identical keys; 01.00: net1.bin): record
/// key by playlist id. Ids are the record's +0x3c index; 01.11 groups them
/// by mode (+0x04 hash): 1-5 Supply Raid, 6-10 Survivors, 11-15
/// Interrogation. In each group the 1st allows parties (party size +0x1c =
/// 4), the 2nd is solo (size 1), the 3rd is the DLC variant; the 4th and
/// 5th are not identified yet.
///
/// A public host's RoomCreate carries its playlist's key at +0xa0 (retail
/// 01.11: confirmed for ids 1, 2, 3, 6 and 7; party and private creates carry
/// none; +0x14 is then 0x10Nc5020 with N = id + 1). A private match picks its
/// +0x0c at random from a small pool (values such as 0x09 occur), so an id
/// outside PLAYLISTS counts as a playlist only when its key is present.
const PLAYLIST_KEYS: [(&str, u32, u32); 17] = [
    ("01.00", 2, 0xd3b8_6d60),
    ("01.00", 3, 0xae00_a01f),
    ("01.11", 1, 0xd3b8_6d60),
    ("01.11", 2, 0xb3ec_2405),
    ("01.11", 3, 0x0207_a1dd),
    ("01.11", 4, 0xd393_b090),
    ("01.11", 5, 0xd752_ad27),
    ("01.11", 6, 0xae00_a01f),
    ("01.11", 7, 0x36a4_9c9f),
    ("01.11", 8, 0x55d3_dce3),
    ("01.11", 9, 0x613e_7592),
    ("01.11", 10, 0x65ff_6825),
    ("01.11", 11, 0x5c49_4f79),
    ("01.11", 12, 0x644d_c357),
    ("01.11", 13, 0x123a_efa0),
    ("01.11", 14, 0xa2cc_16e0),
    ("01.11", 15, 0xa60d_0b57),
];
/// RoomCreate offset of the playlist key.
const CREATE_PLAYLIST_KEY: usize = 0xa0;

/// Whether a game-room create is a matchmaking (public) host.
fn is_matchmaking(build: Option<&str>, field_0c: u32, key: u32) -> bool {
    PLAYLISTS.contains(&field_0c)
        || PLAYLIST_KEYS
            .iter()
            .any(|(b, id, k)| *id == field_0c && *k == key && build.is_none_or(|x| x == *b))
}

/// Playlist name for logs (01.11 numbering).
fn playlist_name(build: Option<&str>, id: u32) -> String {
    if build == Some("01.00") {
        return match id {
            2 => "Supply Raid".into(),
            3 => "Survivors".into(),
            _ => format!("playlist {id}"),
        };
    }
    let mode = match id {
        1..=5 => "Supply Raid",
        6..=10 => "Survivors",
        11..=15 => "Interrogation",
        _ => return format!("playlist {id}"),
    };
    let variant = match (id - 1) % 5 {
        0 => "Parties Allowed",
        1 => "No Parties",
        2 => "DLC",
        v => return format!("{mode} / variant {} (id {id})", v + 1),
    };
    format!("{mode} / {variant} (id {id})")
}

fn build_of(ptr: u32) -> Option<&'static str> {
    BUILDS
        .iter()
        .find(|b| b.1 == ptr || b.2 == ptr)
        .map(|b| b.0)
}

fn is_party(ptr: u32) -> bool {
    BUILDS.iter().any(|b| b.2 == ptr)
}

/// Size of a client record by type; None for a type the client never sends.
fn request_len(kind: u32) -> Option<usize> {
    Some(match kind {
        CLIENT_HELLO => 0x30,
        ROOM_CREATE => 0xe8,
        ROOM_JOIN => 0x58,
        FIND_MATCH => 0x24,
        SET_PARTY_DATA => 0x50,
        SET_ROOM_DATA => 0x90,
        PING => 4,
        CLIENT_HELLO2 => 8,
        ROOM_LEAVING | KICKOUT | PROMOTE | SET_HOST_FLAG | SET_ROOM_FLAGS | HOST_RANK => 0x10,
        _ => return None,
    })
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}
fn id8(b: &[u8], at: usize) -> [u8; 8] {
    b[at..at + 8].try_into().unwrap()
}
fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|x| *x == 0).unwrap_or(b.len())]
}
/// The online id of a name or full player id, for logs.
fn show(player_id: &[u8]) -> String {
    String::from_utf8_lossy(cstr(&player_id[..player_id.len().min(16)])).into_owned()
}

fn clamp_players(v: u16) -> u16 {
    if v == 0 {
        RETAIL_MAX_PLAYERS
    } else {
        v.min(RETAIL_MAX_PLAYERS)
    }
}

fn record(kind: u32, len: usize) -> Vec<u8> {
    let mut r = vec![0u8; len];
    r[..4].copy_from_slice(&kind.to_be_bytes());
    r
}

/// Member (0x131): 0xa0 header + 0x68 per member. Header: room object +8,
/// owner ref +12, local ref +14, room id +16, capacity +24 (never 0: the
/// client traps), count +26. Entry: player id +0 (36 bytes), team +16 (over
/// the player id's always-zero terminator, as RoomCreate reported it), member id
/// +36, data length +39, data +40.
#[allow(clippy::too_many_arguments)]
fn build_member(
    members: &[(u16, Vec<u8>)],
    room_id: [u8; 8],
    max_players: u16,
    owner_ref: u16,
    local_ref: u16,
    teams: &HashMap<u16, u16>,
    room_ptr: u32,
    blobs: &HashMap<u16, Vec<u8>>,
) -> Vec<u8> {
    let mut r = record(MEMBER, 0xa0);
    r[8..12].copy_from_slice(&room_ptr.to_be_bytes());
    r[12..14].copy_from_slice(&owner_ref.to_be_bytes());
    r[14..16].copy_from_slice(&local_ref.to_be_bytes());
    r[16..24].copy_from_slice(&room_id);
    r[24..26].copy_from_slice(&max_players.to_be_bytes());
    r[26..28].copy_from_slice(&(members.len() as u16).to_be_bytes());
    for (mid, player_id) in members {
        let mut e = [0u8; 0x68];
        let n = player_id.len().min(PLAYER_ID_LEN);
        e[..n].copy_from_slice(&player_id[..n]);
        if let Some(team) = teams.get(mid) {
            e[16..18].copy_from_slice(&team.to_be_bytes());
        }
        e[36..38].copy_from_slice(&mid.to_be_bytes());
        if let Some(blob) = blobs.get(mid) {
            let blob = &blob[..blob.len().min(64)];
            e[39] = blob.len() as u8;
            e[40..40 + blob.len()].copy_from_slice(blob);
        }
        r.extend_from_slice(&e);
    }
    r
}

fn build_owner_changed(room_id: [u8; 8], owner: u16) -> Vec<u8> {
    let mut r = record(OWNER_CHANGED, 16);
    r[4..6].copy_from_slice(&owner.to_be_bytes());
    r[8..16].copy_from_slice(&room_id);
    r
}

fn build_host_flag(room_id: [u8; 8], flag: bool) -> Vec<u8> {
    let mut r = record(HOST_FLAG_UPDATED, 16);
    r[4] = u8::from(flag);
    r[8..16].copy_from_slice(&room_id);
    r
}

fn build_room_leave(room_id: [u8; 8], mid: u16) -> Vec<u8> {
    let mut r = record(ROOM_LEAVE, 24);
    r[8..16].copy_from_slice(&room_id);
    r[16..18].copy_from_slice(&mid.to_be_bytes());
    r
}

fn build_room_closed(room_id: [u8; 8]) -> Vec<u8> {
    let mut r = record(ROOM_CLOSED, 16);
    r[8..16].copy_from_slice(&room_id);
    r
}

fn build_kickedout(room_id: [u8; 8]) -> Vec<u8> {
    let mut r = record(KICKEDOUT, 16);
    r[8..16].copy_from_slice(&room_id);
    r
}

fn build_member_blob(mid: u16, room_id: [u8; 8], blob: &[u8]) -> Vec<u8> {
    let mut r = record(MEMBER_BLOB, 80);
    let blob = &blob[..blob.len().min(64)];
    r[4..6].copy_from_slice(&mid.to_be_bytes());
    r[6] = blob.len() as u8;
    r[8..16].copy_from_slice(&room_id);
    r[16..16 + blob.len()].copy_from_slice(blob);
    r
}

/// RoomSearch result (0x136): searcher's object +8, count +12, then 0x38 per
/// room: room id +0, members +0xc, capacity +0x10, host player id +0x14..0x38
/// (copied verbatim into the client's list entry +8; its pick check and the
/// connection to the host both use it, so it must be the host's own player id).
fn build_room_search(search_ptr: u32, rooms: &[&Room]) -> Vec<u8> {
    let mut r = record(ROOM_SEARCH, 16);
    r[8..12].copy_from_slice(&search_ptr.to_be_bytes());
    r[12..16].copy_from_slice(&(rooms.len() as u32).to_be_bytes());
    for room in rooms {
        let mut e = [0u8; 0x38];
        e[..8].copy_from_slice(&room.id);
        e[0xc..0xe].copy_from_slice(&(room.members.len().max(1) as u16).to_be_bytes());
        e[0x10..0x12].copy_from_slice(&room.max_players.to_be_bytes());
        let n = room.owner_id.len().min(PLAYER_ID_LEN);
        e[0x14..0x14 + n].copy_from_slice(&room.owner_id[..n]);
        r.extend_from_slice(&e);
    }
    r
}

/// The client's own 32-byte member data, embedded in RoomCreate (+0x26
/// length, +0xa8 data) and RoomJoin (+0x0c, +0x18).
fn extract_blob(rec: &[u8], len_at: usize, at: usize) -> Option<Vec<u8>> {
    let n = usize::from(*rec.get(len_at)?);
    (n > 0 && n <= 64 && rec.len() >= at + n).then(|| rec[at..at + n].to_vec())
}

type ConnId = u64;

struct Conn {
    tx: Sender<Vec<u8>>,
    last_inbound: Instant,
    online_id: Vec<u8>,
    /// For shutting the connection down when the same player connects
    /// again (a restarted game leaves its old connection behind).
    stream: TcpStream,
}

struct Room {
    id: [u8; 8],
    /// The owner's connection: the room closes when it leaves. Starts as
    /// the creator and follows promotions.
    anchor: ConnId,
    owner_id: Vec<u8>,
    room_ptr: u32,
    max_players: u16,
    members: Vec<(u16, Vec<u8>)>,
    conns: Vec<(ConnId, u16)>,
    owner: u16,
    last_join: Instant,
    next_mid: u16,
    room_ptrs: HashMap<u16, u32>,
    public: bool,
    mode: Option<u32>,
    build: Option<&'static str>,
    blobs: HashMap<u16, Vec<u8>>,
    /// Team as each member's RoomCreate reported it, echoed unchanged.
    teams: HashMap<u16, u16>,
}

impl Room {
    fn member_of(&self, c: ConnId) -> Option<u16> {
        self.conns.iter().find(|(cc, _)| *cc == c).map(|(_, m)| *m)
    }
    fn conn_of(&self, mid: u16) -> Option<ConnId> {
        self.conns.iter().find(|(_, m)| *m == mid).map(|(c, _)| *c)
    }
    /// The roster as one member sees it: its own entry first.
    fn roster_for(&self, mid: u16) -> Vec<(u16, Vec<u8>)> {
        let mut v: Vec<_> = self
            .members
            .iter()
            .filter(|m| m.0 == mid)
            .cloned()
            .collect();
        v.extend(self.members.iter().filter(|m| m.0 != mid).cloned());
        v
    }
}

/// A solo room's pending keepalive (one per room: a connection can own a
/// game room and a party at once).
struct Refresh {
    conn: ConnId,
    local_ref: u16,
    due: Instant,
}

#[derive(Default)]
struct State {
    conns: HashMap<ConnId, Conn>,
    rooms: Vec<Room>,
    refreshers: HashMap<[u8; 8], Refresh>,
    seq: u32,
    next_conn: ConnId,
}

impl State {
    fn send(&self, c: ConnId, msg: Vec<u8>) -> bool {
        self.conns
            .get(&c)
            .is_some_and(|conn| conn.tx.send(msg).is_ok())
    }

    fn mint(&mut self, tag: u32, room_ptr: u32) -> [u8; 8] {
        self.seq = self.seq.wrapping_add(1);
        let mut id = [0u8; 8];
        id[..4].copy_from_slice(&(tag | (self.seq & 0x0fff_ffff)).to_be_bytes());
        id[4..].copy_from_slice(&room_ptr.to_be_bytes());
        id
    }

    fn start_refresher(&mut self, c: ConnId, room: &Room, local_ref: u16, interval: Duration) {
        self.refreshers.remove(&room.id);
        if room.members.len() > 1 || is_party(room.room_ptr) {
            return;
        }
        self.refreshers.insert(
            room.id,
            Refresh {
                conn: c,
                local_ref,
                due: Instant::now() + interval,
            },
        );
    }

    fn stop_room_refreshers(&mut self, room_id: [u8; 8]) {
        self.refreshers.remove(&room_id);
    }

    /// The owner left: tell everyone else (RoomLeave for the owner, then
    /// RoomClosed; the owner itself, if it is a recipient, only RoomClosed;
    /// a member is never sent its own departure).
    fn close_room(&mut self, room: Room, exclude: ConnId, reason: &str) {
        let closed = build_room_closed(room.id);
        let mut told = 0;
        for (c, mid) in &room.conns {
            if *c == exclude {
                continue;
            }
            let msg = if *mid == room.owner {
                closed.clone()
            } else {
                [build_room_leave(room.id, room.owner), closed.clone()].concat()
            };
            told += usize::from(self.send(*c, msg));
        }
        info!(
            "matchmaking",
            "room {} closed ({reason}); told {told} member(s)",
            hex(&room.id)
        );
        self.stop_room_refreshers(room.id);
    }

    fn member_departed(
        &mut self,
        departing: ConnId,
        only: Option<[u8; 8]>,
        reseed: bool,
        interval: Duration,
    ) {
        let mut affected = Vec::new();
        let mut reseeds = Vec::new();
        for room in &mut self.rooms {
            if only.is_some_and(|id| id != room.id) {
                continue;
            }
            let Some(mid) = room.member_of(departing) else {
                continue;
            };
            room.conns.retain(|(c, _)| *c != departing);
            let player_id = room
                .members
                .iter()
                .find(|m| m.0 == mid)
                .map(|m| m.1.clone())
                .unwrap_or_default();
            room.members.retain(|m| m.0 != mid);
            room.blobs.remove(&mid);
            affected.push((room.id, mid));
            if reseed && is_party(room.room_ptr) {
                let ptr = room.room_ptrs.get(&mid).copied().unwrap_or(room.room_ptr);
                reseeds.push((player_id, ptr, room.max_players));
            }
        }
        for (room_id, mid) in affected {
            let Some(i) = self.rooms.iter().position(|r| r.id == room_id) else {
                continue;
            };
            for (c, _) in self.rooms[i].conns.clone() {
                self.send(c, build_room_leave(room_id, mid));
            }
            info!("matchmaking", "member {mid} left room {}", hex(&room_id));
            self.stop_room_refreshers(room_id);
            let room = &self.rooms[i];
            if let Some(anchor_mid) = room.member_of(room.anchor) {
                // Temporarily take the room out to satisfy the borrow checker.
                let room = self.rooms.remove(i);
                self.start_refresher(room.anchor, &room, anchor_mid, interval);
                self.rooms.insert(i, room);
            }
        }
        for (player_id, ptr, max) in reseeds {
            self.reseed_party(departing, player_id, ptr, max);
        }
    }

    /// Before connection `c` gets a new game (or party) room: close the game
    /// (party) rooms it owns, telling their members, and take it out of the
    /// ones it joined. Its client has already dropped them.
    fn retire_rooms_of_kind(&mut self, c: ConnId, party: bool, interval: Duration) {
        let (owned, kept): (Vec<Room>, Vec<Room>) = std::mem::take(&mut self.rooms)
            .into_iter()
            .partition(|r| r.anchor == c && is_party(r.room_ptr) == party);
        self.rooms = kept;
        for room in owned {
            self.close_room(room, c, "its owner created a new room");
        }
        let joined: Vec<[u8; 8]> = self
            .rooms
            .iter()
            .filter(|r| is_party(r.room_ptr) == party && r.member_of(c).is_some())
            .map(|r| r.id)
            .collect();
        for id in joined {
            self.member_departed(c, Some(id), false, interval);
        }
    }

    /// A leaver's own client zeroes its party room id and nothing client-side
    /// restores it; give it a fresh solo party room.
    fn reseed_party(&mut self, c: ConnId, player_id: Vec<u8>, room_ptr: u32, max_players: u16) {
        let id = self.mint(0x6000_0000, room_ptr);
        let members = vec![(OWNER, player_id.clone())];
        let msg = [
            build_member(
                &members,
                id,
                max_players,
                OWNER,
                OWNER,
                &HashMap::new(),
                room_ptr,
                &HashMap::new(),
            ),
            build_host_flag(id, false),
            build_owner_changed(id, OWNER),
        ]
        .concat();
        if !self.send(c, msg) {
            return;
        }
        let before = self.rooms.len();
        self.rooms
            .retain(|r| !(r.anchor == c && is_party(r.room_ptr)));
        let retired = before - self.rooms.len();
        self.rooms.push(Room {
            id,
            anchor: c,
            owner_id: player_id.clone(),
            room_ptr,
            max_players,
            members,
            conns: vec![(c, OWNER)],
            owner: OWNER,
            last_join: Instant::now(),
            next_mid: FIRST_JOINER,
            room_ptrs: HashMap::from([(OWNER, room_ptr)]),
            public: false,
            mode: None,
            build: build_of(room_ptr),
            blobs: HashMap::new(),
            teams: HashMap::new(),
        });
        info!(
            "matchmaking",
            "{} left a party: fresh party room {} (retired {retired} old party room(s))",
            show(&player_id),
            hex(&id)
        );
    }
}

/// Who is on a connection.
struct Session {
    online_id: Vec<u8>,
    /// The full player id from ClientHello +8.
    identity: Vec<u8>,
}

/// Admission of member `mid`: its roster view, host flag 0, the owner.
fn admit_message(room: &Room, mid: u16, room_ptr: u32) -> Vec<u8> {
    [
        build_member(
            &room.roster_for(mid),
            room.id,
            room.max_players,
            room.owner,
            mid,
            &room.teams,
            room_ptr,
            &room.blobs,
        ),
        build_host_flag(room.id, false),
        build_owner_changed(room.id, room.owner),
    ]
    .concat()
}

pub struct Matchmaking {
    state: Mutex<State>,
    presence: Arc<Presence>,
    refresh_interval: Duration,
    create_delay: Duration,
    idle: Duration,
}

impl Matchmaking {
    pub fn new(presence: Arc<Presence>) -> Arc<Self> {
        Self::with_timing(
            presence,
            Duration::from_secs(10),
            Duration::from_millis(250),
            IDLE,
        )
    }

    pub fn with_timing(
        presence: Arc<Presence>,
        refresh_interval: Duration,
        create_delay: Duration,
        idle: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::default(),
            presence,
            refresh_interval,
            create_delay,
            idle,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn serve(self: Arc<Self>, listener: TcpListener) {
        info!(
            "matchmaking",
            "listening on {}",
            listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_default()
        );
        let ticker = self.clone();
        std::thread::spawn(move || ticker.refresh_loop());
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let me = self.clone();
            std::thread::spawn(move || {
                let peer = stream.peer_addr().ok();
                if let Err(e) = me.connection(stream) {
                    debug!("matchmaking", "{peer:?}: {e}");
                }
            });
        }
    }

    fn refresh_loop(&self) {
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let mut st = self.lock();
            let now = Instant::now();
            let due: Vec<[u8; 8]> = st
                .refreshers
                .iter()
                .filter(|(_, r)| r.due <= now)
                .map(|(id, _)| *id)
                .collect();
            for room_id in due {
                let r = &st.refreshers[&room_id];
                let (c, local_ref) = (r.conn, r.local_ref);
                let Some(room) = st.rooms.iter().find(|room| room.id == room_id) else {
                    st.refreshers.remove(&room_id);
                    continue;
                };
                // Rebuilt from the live room: identical to what the owner holds.
                let msg = build_member(
                    &room.roster_for(local_ref),
                    room.id,
                    room.max_players,
                    room.owner,
                    local_ref,
                    &room.teams,
                    room.room_ptrs
                        .get(&local_ref)
                        .copied()
                        .unwrap_or(room.room_ptr),
                    &room.blobs,
                );
                if st.send(c, msg) {
                    debug!(
                        "matchmaking",
                        "keepalive Member for solo room {}",
                        hex(&room_id)
                    );
                    st.refreshers.get_mut(&room_id).unwrap().due = now + self.refresh_interval;
                } else {
                    st.refreshers.remove(&room_id);
                }
            }
        }
    }

    fn connection(&self, stream: TcpStream) -> std::io::Result<()> {
        let peer = stream.peer_addr()?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(self.idle))?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        let mut reader = stream.try_clone()?;
        let control = stream.try_clone()?;
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let mut writer = stream;
        std::thread::spawn(move || {
            for msg in rx {
                if writer.write_all(&msg).is_err() {
                    let _ = writer.shutdown(Shutdown::Both);
                    return;
                }
            }
        });

        let mut buf = Vec::new();
        let hello = loop {
            if let Some((rec, used)) = next_record(&buf) {
                let rec = rec.to_vec();
                buf.drain(..used);
                break rec;
            }
            if !fill(&mut reader, &mut buf)?
                || (buf.len() >= 4 && request_len(be32(&buf, 0)).is_none())
            {
                return Ok(());
            }
        };
        if be32(&hello, 0) != CLIENT_HELLO {
            warn!(
                "matchmaking",
                "{peer}: expected ClientHello, got {}",
                hex(&hello[..hello.len().min(16)])
            );
            return Ok(());
        }
        let online_id = cstr(&hello[8..24]).to_vec();
        let identity = hello[8..8 + PLAYER_ID_LEN].to_vec();
        let online = show(&online_id);
        self.presence.saw(peer.ip(), &online);
        // The client opens this connection once per game start. An older
        // connection of the same player is a leftover of a restarted game:
        // end it now (its rooms close and their members are told). Shutting
        // the socket down does not wake its blocked reader on every platform,
        // so the cleanup runs here; the reader's own later cleanup is a no-op.
        let stale: Vec<ConnId> = {
            let st = self.lock();
            st.conns
                .iter()
                .filter(|(_, c)| !online_id.is_empty() && c.online_id == online_id)
                .map(|(old, conn)| {
                    let _ = conn.stream.shutdown(Shutdown::Both);
                    *old
                })
                .collect()
        };
        for old in stale {
            warn!(
                "matchmaking",
                "{online} connected again; ending its old session {old}"
            );
            self.disconnect(old);
        }
        let id = {
            let mut st = self.lock();
            st.next_conn += 1;
            let id = st.next_conn;
            st.conns.insert(
                id,
                Conn {
                    tx: tx.clone(),
                    last_inbound: Instant::now(),
                    online_id: online_id.clone(),
                    stream: control,
                },
            );
            id
        };
        let _ = tx.send(record(SERVER_HELLO, 16));
        info!(
            "matchmaking",
            "{peer}: {online} connected (session {id}); hello {}",
            hex(&hello)
        );
        let sess = Session {
            online_id,
            identity,
        };

        let result = 'session: loop {
            while let Some((rec, used)) = next_record(&buf) {
                let rec = rec.to_vec();
                buf.drain(..used);
                match self.lock().conns.get_mut(&id) {
                    Some(conn) => conn.last_inbound = Instant::now(),
                    // Ended by a newer connection of the same player.
                    None => break 'session Ok(()),
                }
                self.handle(id, &sess, &rec, peer.ip());
            }
            if buf.len() >= 4 && request_len(be32(&buf, 0)).is_none() {
                warn!(
                    "matchmaking",
                    "{peer}: unknown record type, dropping {} buffered bytes: {}",
                    buf.len(),
                    hex(&buf[..buf.len().min(64)])
                );
                buf.clear();
            }
            match fill(&mut reader, &mut buf) {
                Ok(true) => {}
                Ok(false) => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        self.disconnect(id);
        info!(
            "matchmaking",
            "{peer}: {online} disconnected (session {id})"
        );
        result
    }

    fn disconnect(&self, c: ConnId) {
        let mut st = self.lock();
        st.refreshers.retain(|_, r| r.conn != c);
        let (owned, kept): (Vec<Room>, Vec<Room>) = std::mem::take(&mut st.rooms)
            .into_iter()
            .partition(|r| r.anchor == c);
        st.rooms = kept;
        for room in owned {
            st.close_room(room, c, "owner connection closed");
        }
        st.member_departed(c, None, false, self.refresh_interval);
        st.conns.remove(&c);
    }

    fn handle(&self, c: ConnId, sess: &Session, rec: &[u8], ip: IpAddr) {
        let kind = be32(rec, 0);
        debug!("matchmaking", "session {c} <- {kind:#x} {}", hex(rec));
        match kind {
            ROOM_CREATE => self.room_create(c, sess, rec),
            ROOM_JOIN => self.room_join(c, sess, rec),
            FIND_MATCH => self.find_match(c, rec),
            ROOM_LEAVING => self.room_leaving(c, rec),
            SET_PARTY_DATA => self.set_party_data(c, rec),
            KICKOUT => self.kickout(c, rec),
            PROMOTE => self.promote(c, rec),
            SET_ROOM_FLAGS => {
                let reply = [&UPDATED_ROOM_FLAGS.to_be_bytes()[..], &rec[4..16]].concat();
                self.lock().send(c, reply);
            }
            SET_ROOM_DATA => {
                let reply = [&ROOM_DATA_UPDATED.to_be_bytes()[..], &rec[4..0x90]].concat();
                self.lock().send(c, reply);
            }
            PING | CLIENT_HELLO2 | SET_HOST_FLAG | HOST_RANK => {}
            CLIENT_HELLO => warn!(
                "matchmaking",
                "session {c}: repeated ClientHello from {ip} ignored"
            ),
            _ => warn!("matchmaking", "session {c}: unhandled record {kind:#x}"),
        }
    }

    fn room_create(&self, c: ConnId, sess: &Session, rec: &[u8]) {
        let name = cstr(&rec[0x28..0xa8]);
        let named = name.split(|b| *b == b'.').next().unwrap_or(&[]);
        let named = &named[..named.len().min(16)];
        // The room name starts with the creator's online id; use the full
        // player id from its hello when it is the same player.
        let player_id = if named == sess.online_id.as_slice() {
            sess.identity.clone()
        } else {
            named.to_vec()
        };
        let max_players = clamp_players(be16(rec, 0x24));
        let room_ptr = be32(rec, 8);
        let field_0c = be32(rec, 0x0c);
        let team = be16(rec, 0xb0);
        let party = is_party(room_ptr);
        let build = build_of(room_ptr);
        let public = !party && is_matchmaking(build, field_0c, be32(rec, CREATE_PLAYLIST_KEY));
        if build.is_none() {
            warn!(
                "matchmaking",
                "session {c}: unknown room object {room_ptr:#010x}; party detection is off for this client build"
            );
        }
        let blob = extract_blob(rec, 0x26, 0xa8);
        // Answer after a short delay: the client's own pending-room
        // registration may not have run yet.
        std::thread::sleep(self.create_delay);
        let mut st = self.lock();
        // The client has one game and one party room object: a create on one
        // replaces whatever room it last had there.
        st.retire_rooms_of_kind(c, party, self.refresh_interval);
        let tag = if party {
            0x6000_0000
        } else if public {
            0x5000_0000
        } else {
            0x7000_0000
        };
        let id = st.mint(tag, room_ptr);
        let members = vec![(OWNER, player_id.clone())];
        let blobs: HashMap<u16, Vec<u8>> = blob.into_iter().map(|b| (OWNER, b)).collect();
        let teams = HashMap::from([(OWNER, team)]);
        let msg = [
            build_member(
                &members,
                id,
                max_players,
                OWNER,
                OWNER,
                &teams,
                room_ptr,
                &blobs,
            ),
            build_host_flag(id, !party),
            build_owner_changed(id, OWNER),
        ]
        .concat();
        st.send(c, msg);
        // The room's own playlist field, not the creator's last search.
        let mode = public.then_some(field_0c);
        let room = Room {
            id,
            anchor: c,
            owner_id: player_id.clone(),
            room_ptr,
            max_players,
            members,
            conns: vec![(c, OWNER)],
            owner: OWNER,
            last_join: Instant::now(),
            next_mid: FIRST_JOINER,
            room_ptrs: HashMap::from([(OWNER, room_ptr)]),
            public,
            mode,
            build,
            blobs,
            teams,
        };
        st.start_refresher(c, &room, OWNER, self.refresh_interval);
        st.rooms.push(room);
        info!(
            "matchmaking",
            "{} created {} room {} (build {}, {}, capacity {max_players}, team {team})",
            show(cstr(&player_id[..player_id.len().min(16)])),
            if party {
                "party"
            } else if public {
                "public"
            } else {
                "private"
            },
            hex(&id),
            build.unwrap_or("?"),
            if public {
                playlist_name(build, field_0c)
            } else {
                format!("field {field_0c:#x}")
            }
        );
    }

    fn room_join(&self, c: ConnId, sess: &Session, rec: &[u8]) {
        let join_ptr = be32(rec, 8);
        let target = id8(rec, 0x10);
        let mut st = self.lock();
        // A repeated join of a room it is already in: answer it again, never
        // add the player a second time (a second entry is a duplicate name).
        if let Some(room) = st.rooms.iter().find(|r| r.id == target)
            && let Some(mid) = room.member_of(c)
        {
            let msg = admit_message(room, mid, join_ptr);
            st.send(c, msg);
            info!(
                "matchmaking",
                "{} repeated its join of room {}; answered again",
                show(&sess.online_id),
                hex(&target)
            );
            return;
        }
        let Some(i) = st.rooms.iter().position(|r| r.id == target) else {
            info!(
                "matchmaking",
                "session {c}: join of unknown room {}; no reply",
                hex(&target)
            );
            return;
        };
        let room = &st.rooms[i];
        if room.members.len() >= usize::from(clamp_players(room.max_players)) {
            info!(
                "matchmaking",
                "{} refused: room {} is full",
                show(&sess.online_id),
                hex(&target)
            );
            return;
        }
        // Joining a game (party) room means the client left whatever game
        // (party) room it had.
        let party = is_party(room.room_ptr);
        st.retire_rooms_of_kind(c, party, self.refresh_interval);
        let Some(i) = st.rooms.iter().position(|r| r.id == target) else {
            return;
        };
        let room = &mut st.rooms[i];
        if let (Some(a), Some(b)) = (build_of(join_ptr), room.build)
            && a != b
        {
            warn!(
                "matchmaking",
                "cross-build join: {a} client into a {b} room {}",
                hex(&target)
            );
        }
        let mid = room.next_mid;
        room.next_mid += 1;
        room.room_ptrs.insert(mid, join_ptr);
        if let Some(blob) = extract_blob(rec, 0x0c, 0x18) {
            room.blobs.insert(mid, blob);
        }
        let joiner = (mid, sess.identity.clone());
        room.members.push(joiner);
        let room = &st.rooms[i];
        // Existing members first: the host must start dialling the joiner
        // before the joiner is admitted.
        let mut host_dead = false;
        let mut pushes = Vec::new();
        for (mc, mmid) in &room.conns {
            let rp = room.room_ptrs.get(mmid).copied().unwrap_or(room.room_ptr);
            pushes.push((
                *mc,
                build_member(
                    &room.roster_for(*mmid),
                    room.id,
                    room.max_players,
                    room.owner,
                    *mmid,
                    &room.teams,
                    rp,
                    &room.blobs,
                ),
            ));
        }
        let anchor = room.anchor;
        for (mc, msg) in pushes {
            if !st.send(mc, msg) && mc == anchor {
                host_dead = true;
            }
        }
        if host_dead {
            // The joiner is not admitted (its join times out client-side);
            // everyone else in the room is told it is gone.
            let mut room = st.rooms.remove(i);
            room.members.retain(|m| m.0 != mid);
            st.close_room(room, anchor, "host connection is gone");
            return;
        }
        let room = &st.rooms[i];
        let admit = admit_message(room, mid, join_ptr);
        // Data blobs: the joiner gets everyone's, everyone gets the joiner's.
        // (Members already hold each other's; re-sending them all on every
        // join is O(n^2) noise in a full lobby.)
        let mut replays = Vec::new();
        for (bmid, blob) in &room.blobs {
            let msg = build_member_blob(*bmid, room.id, blob);
            if *bmid == mid {
                for (mc, _) in &room.conns {
                    replays.push((*mc, msg.clone()));
                }
            } else {
                replays.push((c, msg));
            }
        }
        st.send(c, admit);
        for (mc, msg) in replays {
            st.send(mc, msg);
        }
        let room = &mut st.rooms[i];
        room.conns.push((c, mid));
        room.last_join = Instant::now();
        let (count, room_id, owner) = (room.members.len(), room.id, room.owner_id.clone());
        st.stop_room_refreshers(room_id);
        info!(
            "matchmaking",
            "{} joined {}'s room {} as member {mid} ({count} members)",
            show(&sess.online_id),
            show(cstr(&owner[..owner.len().min(16)])),
            hex(&room_id)
        );
    }

    fn find_match(&self, c: ConnId, rec: &[u8]) {
        let ptr = be32(rec, 8);
        let mode = be32(rec, 12);
        let build = build_of(ptr);
        let st = self.lock();
        if st.rooms.iter().any(|r| r.anchor == c && r.room_ptr == ptr) {
            debug!(
                "matchmaking",
                "session {c}: search from a live host; no result list"
            );
            return;
        }
        let rooms: Vec<&Room> = st
            .rooms
            .iter()
            .filter(|r| {
                r.public
                    && r.anchor != c
                    && r.members.len() < usize::from(r.max_players)
                    && r.mode == Some(mode)
                    && (build.is_none() || r.build.is_none() || r.build == build)
            })
            .take(MAX_SEARCH_RESULTS)
            .collect();
        let msg = build_room_search(ptr, &rooms);
        let n = rooms.len();
        st.send(c, msg);
        debug!(
            "matchmaking",
            "session {c}: search {} -> {n} room(s)",
            playlist_name(build, mode)
        );
    }

    fn room_leaving(&self, c: ConnId, rec: &[u8]) {
        let room_id = id8(rec, 8);
        let mut st = self.lock();
        let pos = st
            .rooms
            .iter()
            .position(|r| r.anchor == c && r.id == room_id)
            .or_else(|| st.rooms.iter().position(|r| r.anchor == c && r.public));
        if let Some(i) = pos {
            let room = st.rooms.remove(i);
            st.close_room(room, c, "owner left");
        }
        st.member_departed(c, Some(room_id), true, self.refresh_interval);
    }

    fn set_party_data(&self, c: ConnId, rec: &[u8]) {
        let room_id = id8(rec, 8);
        let mut st = self.lock();
        let Some(i) = st
            .rooms
            .iter()
            .position(|r| r.id == room_id && r.member_of(c).is_some())
            .or_else(|| st.rooms.iter().position(|r| r.member_of(c).is_some()))
        else {
            debug!("matchmaking", "session {c}: member data for no room");
            return;
        };
        let n = usize::from(rec[4]).min(64);
        let blob = rec[16..16 + n].to_vec();
        let room = &mut st.rooms[i];
        let mid = room.member_of(c).unwrap();
        room.blobs.insert(mid, blob.clone());
        let msg = build_member_blob(mid, room.id, &blob);
        let others: Vec<ConnId> = room
            .conns
            .iter()
            .filter(|(_, m)| *m != mid)
            .map(|(cc, _)| *cc)
            .collect();
        for o in others {
            st.send(o, msg.clone());
        }
    }

    fn kickout(&self, c: ConnId, rec: &[u8]) {
        let target = be16(rec, 4);
        let requester = be16(rec, 6);
        let room_id = id8(rec, 8);
        let mut st = self.lock();
        let Some(room) = st
            .rooms
            .iter()
            .find(|r| r.id == room_id && r.member_of(c).is_some())
        else {
            debug!("matchmaking", "session {c}: kick in a room it is not in");
            return;
        };
        let Some(tc) = room.conn_of(target) else {
            return;
        };
        if requester == 0 {
            // Automatic removal: seen right after joins (never act) and from a
            // host whose peer link died (act only if the target is silent).
            let silent = st
                .conns
                .get(&tc)
                .map_or(Duration::MAX, |x| x.last_inbound.elapsed());
            let why = if tc == c {
                Some("target is the sender")
            } else if target == room.owner {
                Some("target is the owner")
            } else if room.last_join.elapsed() < LATE_KICKOUT {
                Some("inside the join window")
            } else if silent < DEAD_PEER_SILENCE {
                Some("target is still pinging")
            } else {
                None
            };
            if let Some(why) = why {
                debug!(
                    "matchmaking",
                    "automatic kick of member {target} ignored: {why}"
                );
                return;
            }
            info!(
                "matchmaking",
                "removing silent member {target} from room {}",
                hex(&room_id)
            );
            st.send(tc, build_kickedout(room_id));
            st.member_departed(tc, Some(room_id), false, self.refresh_interval);
            return;
        }
        if room.member_of(c) != Some(room.owner) {
            warn!(
                "matchmaking",
                "session {c}: kick refused, not the room owner"
            );
            return;
        }
        st.send(tc, build_kickedout(room_id));
        info!(
            "matchmaking",
            "member {target} kicked from room {}",
            hex(&room_id)
        );
        st.member_departed(tc, Some(room_id), true, self.refresh_interval);
    }

    fn promote(&self, c: ConnId, rec: &[u8]) {
        let new_owner = be16(rec, 4);
        let room_id = id8(rec, 8);
        let mut st = self.lock();
        let Some(room) = st
            .rooms
            .iter_mut()
            .find(|r| r.id == room_id && r.member_of(c).is_some())
        else {
            return;
        };
        if room.member_of(c) != Some(room.owner) || room.conn_of(new_owner).is_none() {
            warn!(
                "matchmaking",
                "session {c}: promote refused (not owner, or unknown member)"
            );
            return;
        }
        room.owner = new_owner;
        // Ownership moves with the lead: the room now closes when the new
        // owner leaves (not the creator), and searches name the new host.
        if let Some(oc) = room.conn_of(new_owner) {
            room.anchor = oc;
        }
        if let Some(m) = room.members.iter().find(|m| m.0 == new_owner) {
            room.owner_id = m.1.clone();
        }
        let party = is_party(room.room_ptr);
        let msgs: Vec<(ConnId, Vec<u8>)> = room
            .conns
            .iter()
            .map(|(mc, mid)| {
                (
                    *mc,
                    [
                        build_owner_changed(room_id, new_owner),
                        build_host_flag(room_id, !party && *mid == new_owner),
                    ]
                    .concat(),
                )
            })
            .collect();
        for (mc, m) in msgs {
            st.send(mc, m);
        }
        info!(
            "matchmaking",
            "member {new_owner} now leads room {}",
            hex(&room_id)
        );
    }

    pub fn room_count(&self) -> usize {
        self.lock().rooms.len()
    }
}

/// The next whole record at the start of `buf`, with its length.
fn next_record(buf: &[u8]) -> Option<(&[u8], usize)> {
    if buf.len() < 4 {
        return None;
    }
    let kind = be32(buf, 0);
    let mut len = request_len(kind)?;
    if kind == HOST_RANK {
        if buf.len() < 0x10 {
            return None;
        }
        len += 2 * usize::from(be16(buf, 4));
    }
    (buf.len() >= len).then(|| (&buf[..len], len))
}

/// Read more bytes; false on a clean close.
fn fill(r: &mut TcpStream, buf: &mut Vec<u8>) -> std::io::Result<bool> {
    let mut chunk = [0u8; 4096];
    let n = r.read(&mut chunk)?;
    if n == 0 {
        return Ok(false);
    }
    if buf.len() + n > MAX_BUFFER {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "record buffer overflow",
        ));
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(true)
}

#[cfg(test)]
mod tests;
