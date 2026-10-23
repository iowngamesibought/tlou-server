use super::*;
use std::net::SocketAddr;

const GAME: u32 = 0x013b_abd8;
const PARTY: u32 = 0x013b_f068;

fn start(refresh: Duration) -> (Arc<Matchmaking>, SocketAddr) {
    start_idle(refresh, Duration::from_secs(60))
}

fn start_idle(refresh: Duration, idle: Duration) -> (Arc<Matchmaking>, SocketAddr) {
    let mm = Matchmaking::with_timing(Arc::default(), refresh, Duration::from_millis(10), idle);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let m = mm.clone();
    std::thread::spawn(move || m.serve(l));
    (mm, a)
}

struct Client(TcpStream);

impl Client {
    fn connect(addr: SocketAddr, name: &str) -> Self {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut c = Client(s);
        let mut hello = record(CLIENT_HELLO, 0x30);
        hello[8..8 + PLAYER_ID_LEN].copy_from_slice(&identity(name));
        c.send(&hello);
        let r = c.recv();
        assert_eq!((be32(&r, 0), r.len()), (SERVER_HELLO, 16));
        c
    }

    fn send(&mut self, rec: &[u8]) {
        self.0.write_all(rec).unwrap();
    }

    /// One server record, sized by its type.
    fn recv(&mut self) -> Vec<u8> {
        let mut head = vec![0u8; 16];
        self.0.read_exact(&mut head).unwrap();
        let len = match be32(&head, 0) {
            MEMBER => {
                let mut more = vec![0u8; 0xa0 - 16];
                self.0.read_exact(&mut more).unwrap();
                head.extend(more);
                0xa0 + 0x68 * usize::from(be16(&head, 26))
            }
            ROOM_SEARCH => 16 + 0x38 * be32(&head, 12) as usize,
            ROOM_LEAVE => 24,
            MEMBER_BLOB => 80,
            ROOM_DATA_UPDATED => 0x90,
            _ => 16,
        };
        let have = head.len();
        head.resize(len, 0);
        self.0.read_exact(&mut head[have..]).unwrap();
        head
    }

    /// Read everything pending.
    fn drain(&mut self) {
        while !self.quiet(150) {
            let _ = self.recv();
        }
    }

    /// Records until one of `kind` arrives (at most 30), returned last.
    fn until(&mut self, kind: u32) -> Vec<u8> {
        for _ in 0..30 {
            let r = self.recv();
            if be32(&r, 0) == kind {
                return r;
            }
        }
        panic!("no record {kind:#x}");
    }

    fn quiet(&mut self, ms: u64) -> bool {
        self.0
            .set_read_timeout(Some(Duration::from_millis(ms)))
            .unwrap();
        let mut b = [0u8; 1];
        let quiet = matches!(self.0.peek(&mut b), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut);
        self.0
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        quiet
    }
}

fn create(ptr: u32, playlist: u32, name: &str, blob_tag: u8) -> Vec<u8> {
    let mut r = record(ROOM_CREATE, 0xe8);
    r[8..12].copy_from_slice(&ptr.to_be_bytes());
    r[0x0c..0x10].copy_from_slice(&playlist.to_be_bytes());
    r[0x24..0x26].copy_from_slice(&8u16.to_be_bytes());
    r[0x26] = 0x20;
    let n = format!("{name}.1787116698");
    r[0x28..0x28 + n.len()].copy_from_slice(n.as_bytes());
    r[0xa8..0xc8].fill(blob_tag);
    r[0xb0..0xb2].copy_from_slice(&1u16.to_be_bytes());
    r
}

fn join(ptr: u32, room: [u8; 8], blob_tag: u8) -> Vec<u8> {
    let mut r = record(ROOM_JOIN, 0x58);
    r[8..12].copy_from_slice(&ptr.to_be_bytes());
    r[0x0c] = 0x20;
    r[0x10..0x18].copy_from_slice(&room);
    r[0x18..0x38].fill(blob_tag);
    r
}

fn short(kind: u32, a: u16, b: u16, room: [u8; 8]) -> Vec<u8> {
    let mut r = record(kind, 0x10);
    r[4..6].copy_from_slice(&a.to_be_bytes());
    r[6..8].copy_from_slice(&b.to_be_bytes());
    r[8..16].copy_from_slice(&room);
    r
}

fn search(ptr: u32, playlist: u32) -> Vec<u8> {
    let mut r = record(FIND_MATCH, 0x24);
    r[8..12].copy_from_slice(&ptr.to_be_bytes());
    r[12..16].copy_from_slice(&playlist.to_be_bytes());
    r
}

/// A full player id as a retail client sends it: online id, then nonzero
/// opt/reserved bytes that must be echoed verbatim.
fn identity(name: &str) -> [u8; PLAYER_ID_LEN] {
    let mut id = [0u8; PLAYER_ID_LEN];
    id[..name.len()].copy_from_slice(name.as_bytes());
    id[20..].copy_from_slice(b"opt-bytereserved");
    id
}

fn entry_player_id(member: &[u8], i: usize) -> String {
    show(cstr(&member[0xa0 + 0x68 * i..0xa0 + 0x68 * i + 16]))
}

#[test]
fn create_search_join_relay_leave() {
    let (mm, addr) = start(Duration::from_secs(60));
    let mut alice = Client::connect(addr, "alice");
    alice.send(&create(GAME, 2, "alice", 0xaa));
    let m = alice.recv();
    assert_eq!(be32(&m, 0), MEMBER);
    assert_eq!(
        (be16(&m, 12), be16(&m, 14), be16(&m, 24), be16(&m, 26)),
        (1, 1, 8, 1)
    );
    assert_eq!(be32(&m, 8), GAME);
    assert_eq!(
        entry_player_id(&m, 0),
        "alice",
        "own player id is populated"
    );
    assert_eq!(be16(&m, 0xa0 + 16), 1, "team echoed");
    assert_eq!(m[0xa0 + 39], 0x20, "own data blob seeded");
    let room = id8(&m, 16);
    assert_eq!(room[0] >> 4, 5, "public-tag id (playlist field)");
    assert_eq!(&room[4..], &GAME.to_be_bytes());
    let flag = alice.recv();
    assert_eq!(
        (be32(&flag, 0), flag[4], id8(&flag, 8)),
        (HOST_FLAG_UPDATED, 1, room)
    );
    let owner = alice.recv();
    assert_eq!((be32(&owner, 0), be16(&owner, 4)), (OWNER_CHANGED, 1));

    // Another playlist sees nothing; the same playlist sees alice's room.
    let mut bob = Client::connect(addr, "bob");
    bob.send(&search(GAME, 3));
    assert_eq!(be32(&bob.recv(), 12), 0);
    bob.send(&search(GAME, 2));
    let list = bob.recv();
    assert_eq!(
        (be32(&list, 0), be32(&list, 8), be32(&list, 12)),
        (ROOM_SEARCH, GAME, 1)
    );
    assert_eq!(id8(&list, 16), room);
    assert_eq!(
        &list[16 + 0x14..16 + 0x38],
        &identity("alice"),
        "the host's whole player id"
    );
    // A live host's own search is not answered.
    alice.send(&search(GAME, 2));
    assert!(alice.quiet(200));

    bob.send(&join(GAME, room, 0xbb));
    let pushed = alice.recv();
    assert_eq!((be16(&pushed, 26), be16(&pushed, 14)), (2, 1));
    assert_eq!(
        (entry_player_id(&pushed, 0), entry_player_id(&pushed, 1)),
        ("alice".into(), "bob".into())
    );
    let bob_entry = 0xa0 + 0x68;
    assert_eq!(
        &pushed[bob_entry..bob_entry + PLAYER_ID_LEN],
        &identity("bob")
    );
    assert_eq!(
        be16(&pushed, 0xa0 + 16),
        1,
        "owner's team kept on later pushes"
    );
    let admitted = bob.recv();
    assert_eq!(
        (be16(&admitted, 14), entry_player_id(&admitted, 0)),
        (2, "bob".into())
    );
    assert_eq!(be32(&admitted, 8), GAME);
    let f = bob.recv();
    assert_eq!((be32(&f, 0), f[4]), (HOST_FLAG_UPDATED, 0));
    assert_eq!(be32(&bob.recv(), 0), OWNER_CHANGED);
    let b1 = bob.recv();
    assert_eq!((be32(&b1, 0), be16(&b1, 4), b1[16]), (MEMBER_BLOB, 1, 0xaa));
    let b2 = alice.recv();
    assert_eq!((be32(&b2, 0), be16(&b2, 4), b2[16]), (MEMBER_BLOB, 2, 0xbb));

    // Full rooms are no longer listed; data updates are relayed.
    let mut data = record(SET_PARTY_DATA, 0x50);
    data[4] = 0x20;
    data[8..16].copy_from_slice(&room);
    data[16..48].fill(0xcc);
    bob.send(&data);
    let b = alice.recv();
    assert_eq!(
        (be32(&b, 0), be16(&b, 4), b[6], b[16]),
        (MEMBER_BLOB, 2, 0x20, 0xcc)
    );

    // Two records in one write, and one split across writes.
    let mut flags = record(SET_ROOM_FLAGS, 0x10);
    flags[4..8].copy_from_slice(&[0, 1, 0x2f, 0x78]);
    flags[8..16].copy_from_slice(&room);
    let both = [record(PING, 4), flags.clone()].concat();
    bob.send(&both[..7]);
    std::thread::sleep(Duration::from_millis(50));
    bob.send(&both[7..]);
    let r = bob.recv();
    assert_eq!(
        (be32(&r, 0), &r[4..16]),
        (UPDATED_ROOM_FLAGS, &flags[4..16])
    );

    // A guest leaving: the host hears RoomLeave for member 2.
    bob.send(&short(ROOM_LEAVING, 0, 0, room));
    let l = alice.recv();
    assert_eq!(
        (be32(&l, 0), id8(&l, 8), be16(&l, 16)),
        (ROOM_LEAVE, room, 2)
    );
    assert_eq!(mm.room_count(), 1);

    // The owner vanishing closes the room for whoever is left.
    let mut carol = Client::connect(addr, "carol");
    carol.send(&join(GAME, room, 0xdd));
    let _ = alice.recv(); // roster push
    for _ in 0..3 {
        let _ = carol.recv(); // Member, host flag, owner
    }
    let _ = carol.recv(); // alice's blob
    let _ = alice.recv(); // carol's blob
    drop(alice);
    let l = carol.recv();
    assert_eq!((be32(&l, 0), be16(&l, 16)), (ROOM_LEAVE, 1));
    assert_eq!(be32(&carol.recv(), 0), ROOM_CLOSED);
}

#[test]
fn party_flag_kick_and_reseed() {
    let (_mm, addr) = start(Duration::from_secs(60));
    let mut host = Client::connect(addr, "host");
    host.send(&create(PARTY, 2, "host", 1));
    let m = host.recv();
    let room = id8(&m, 16);
    assert_eq!(
        room[0] >> 4,
        6,
        "party id, never public even with a playlist value"
    );
    let f = host.recv();
    assert_eq!(f[4], 0, "a party host advertises flag 0");
    let _ = host.recv();

    let mut guest = Client::connect(addr, "guest");
    guest.send(&search(GAME, 2));
    assert_eq!(be32(&guest.recv(), 12), 0, "parties are not listed");
    guest.send(&join(PARTY, room, 2));
    let _ = host.recv();
    for _ in 0..4 {
        let _ = guest.recv();
    }
    let _ = host.recv();

    // Only the owner may kick; the guest's attempt changes nothing.
    guest.send(&short(KICKOUT, 1, 2, room));
    assert!(host.quiet(200));
    host.send(&short(KICKOUT, 2, 1, room));
    let k = guest.recv();
    assert_eq!((be32(&k, 0), id8(&k, 8)), (KICKEDOUT, room));
    // The kicked guest gets a fresh solo party room of its own.
    let fresh = guest.recv();
    assert_eq!((be32(&fresh, 0), be16(&fresh, 26)), (MEMBER, 1));
    let fresh_id = id8(&fresh, 16);
    assert!(fresh_id != room && fresh_id[0] >> 4 == 6);
    assert_eq!(guest.recv()[4], 0);
    assert_eq!(be32(&guest.recv(), 0), OWNER_CHANGED);
    let l = host.recv();
    assert_eq!((be32(&l, 0), be16(&l, 16)), (ROOM_LEAVE, 2));
    // An immediate automatic kick (requester 0) is ignored.
    host.send(&short(KICKOUT, 2, 0, room));
    assert!(guest.quiet(200));
}

#[test]
fn solo_game_room_keepalive_only() {
    let (_mm, addr) = start(Duration::from_millis(300));
    let mut solo = Client::connect(addr, "solo");
    solo.send(&create(GAME, 0x58, "solo", 1));
    let first = solo.recv();
    let _ = solo.recv();
    let _ = solo.recv();
    let again = solo.recv();
    assert_eq!(again, first, "re-send identical to what the owner holds");
    // A later data update is part of the next re-send.
    let mut data = record(SET_PARTY_DATA, 0x50);
    data[4] = 0x20;
    data[8..16].copy_from_slice(&id8(&first, 16));
    data[16..48].fill(0xcc);
    solo.send(&data);
    let updated = solo.recv();
    assert_eq!((be32(&updated, 0), updated[0xa0 + 40]), (MEMBER, 0xcc));
    let mut party = Client::connect(addr, "party");
    party.send(&create(PARTY, 0x58, "party", 1));
    for _ in 0..3 {
        let _ = party.recv();
    }
    assert!(party.quiet(800), "party rooms are never re-sent");
    // Leaving stops the keepalive.
    solo.send(&short(ROOM_LEAVING, 0, 0, id8(&first, 16)));
    std::thread::sleep(Duration::from_millis(100));
    while !solo.quiet(50) {
        let _ = solo.recv();
    }
    assert!(solo.quiet(800));
}

/// A host with a public game room and one joined guest, both drained.
fn hosted(addr: SocketAddr, host: &str, guest: &str) -> (Client, Client, [u8; 8]) {
    let mut h = Client::connect(addr, host);
    h.send(&create(GAME, 2, host, 1));
    let room = id8(&h.recv(), 16);
    h.drain();
    let mut g = Client::connect(addr, guest);
    g.send(&join(GAME, room, 2));
    g.drain();
    h.drain();
    (h, g, room)
}

fn listed(addr: SocketAddr, playlist: u32) -> Vec<[u8; 8]> {
    let mut s = Client::connect(addr, "searcher");
    s.send(&search(GAME, playlist));
    let list = s.recv();
    (0..be32(&list, 12) as usize)
        .map(|i| id8(&list, 16 + 0x38 * i))
        .collect()
}

#[test]
fn repeated_join_is_answered_not_duplicated() {
    let (_mm, addr) = start(Duration::from_secs(60));
    let (mut host, mut guest, room) = hosted(addr, "host", "guest");
    guest.send(&join(GAME, room, 2));
    let again = guest.recv();
    assert_eq!(
        (be32(&again, 0), be16(&again, 26), be16(&again, 14)),
        (MEMBER, 2, 2),
        "same roster, same member id"
    );
    guest.drain();
    assert!(host.quiet(200), "the host sees no second joiner");
}

#[test]
fn promotion_moves_ownership() {
    let (mm, addr) = start(Duration::from_secs(60));
    let mut lead = Client::connect(addr, "lead");
    lead.send(&create(PARTY, 0x58, "lead", 1));
    let party = id8(&lead.recv(), 16);
    lead.drain();
    let mut next = Client::connect(addr, "next");
    next.send(&join(PARTY, party, 2));
    next.drain();
    lead.drain();

    lead.send(&short(PROMOTE, 2, 0, party));
    let o = next.recv();
    assert_eq!((be32(&o, 0), be16(&o, 4)), (OWNER_CHANGED, 2));
    next.drain();
    lead.drain();
    // The old leader leaving no longer closes the party.
    lead.send(&short(ROOM_LEAVING, 0, 0, party));
    let l = next.recv();
    assert_eq!((be32(&l, 0), be16(&l, 16)), (ROOM_LEAVE, 1));
    assert!(next.quiet(200), "no RoomClosed: the party lives on");
    let fresh = lead.until(MEMBER);
    assert_eq!(be16(&fresh, 26), 1, "the leaver gets its own party back");
    assert_eq!(mm.room_count(), 2);
    // The new leader leaving now closes it.
    drop(next);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(mm.room_count(), 1);
}

#[test]
fn reconnect_ends_the_old_session() {
    let (_mm, addr) = start(Duration::from_secs(60));
    let (_old, mut guest, room) = hosted(addr, "host", "guest");
    let _new = Client::connect(addr, "host");
    let l = guest.recv();
    assert_eq!(
        (be32(&l, 0), id8(&l, 8), be16(&l, 16)),
        (ROOM_LEAVE, room, 1)
    );
    assert_eq!(be32(&guest.recv(), 0), ROOM_CLOSED);
    assert!(
        listed(addr, 2).is_empty(),
        "the old room is no longer offered"
    );
}

#[test]
fn new_room_replaces_the_previous_one() {
    let (_mm, addr) = start(Duration::from_secs(60));
    let (mut host, mut guest, old) = hosted(addr, "host", "guest");
    host.send(&create(GAME, 2, "host", 1));
    let new = id8(&host.until(MEMBER), 16);
    assert_ne!(new, old);
    let l = guest.recv();
    assert_eq!((be32(&l, 0), id8(&l, 8)), (ROOM_LEAVE, old));
    assert_eq!(be32(&guest.recv(), 0), ROOM_CLOSED);
    assert_eq!(listed(addr, 2), [new]);
}

#[test]
fn keepalives_are_per_room() {
    let (_mm, addr) = start(Duration::from_millis(300));
    let mut host = Client::connect(addr, "host");
    host.send(&create(GAME, 0x5a, "host", 1));
    let game = id8(&host.recv(), 16);
    host.send(&create(PARTY, 0x58, "host", 1));
    let party = id8(&host.until(MEMBER), 16);
    let mut friend = Client::connect(addr, "friend");
    friend.send(&join(PARTY, party, 2));
    friend.drain();
    friend.send(&short(ROOM_LEAVING, 0, 0, party));
    // The party member leaving does not stop the game room's keepalive.
    let mut seen = false;
    for _ in 0..20 {
        let r = host.recv();
        if be32(&r, 0) == MEMBER && id8(&r, 16) == game {
            seen = true;
            break;
        }
    }
    assert!(seen, "solo game room still kept alive");
}

#[test]
fn silent_console_is_dropped() {
    // Longer than the setup below takes, far shorter than the real 95 s.
    let (_mm, addr) = start_idle(Duration::from_secs(60), Duration::from_millis(1500));
    let (_host, mut guest, room) = hosted(addr, "host", "guest");
    guest.send(&record(PING, 4));
    // The host stops pinging (a crashed console): its room closes.
    let l = guest.recv();
    assert_eq!((be32(&l, 0), id8(&l, 8)), (ROOM_LEAVE, room));
    assert_eq!(be32(&guest.recv(), 0), ROOM_CLOSED);
}

#[test]
fn full_eight_player_lobby() {
    let (_mm, addr) = start(Duration::from_secs(60));
    let mut players = vec![Client::connect(addr, "p1")];
    players[0].send(&create(GAME, 2, "p1", 0x01));
    let room = id8(&players[0].recv(), 16);
    players[0].drain();
    for k in 2..=8u16 {
        let name = format!("p{k}");
        let mut c = Client::connect(addr, &name);
        c.send(&join(GAME, room, k as u8));
        // The joiner: whole roster with itself as the local member, then
        // exactly one data blob from each member already there.
        let admit = c.recv();
        assert_eq!(
            (be32(&admit, 0), be16(&admit, 26), be16(&admit, 14)),
            (MEMBER, k, k)
        );
        let ids: std::collections::BTreeSet<u16> = (0..usize::from(k))
            .map(|i| be16(&admit, 0xa0 + 0x68 * i + 36))
            .collect();
        assert_eq!(ids, (1..=k).collect(), "unique member ids");
        assert_eq!(be32(&c.recv(), 0), HOST_FLAG_UPDATED);
        assert_eq!(be32(&c.recv(), 0), OWNER_CHANGED);
        let mut from: Vec<u16> = (1..k)
            .map(|_| {
                let b = c.recv();
                assert_eq!(be32(&b, 0), MEMBER_BLOB);
                be16(&b, 4)
            })
            .collect();
        from.sort();
        assert_eq!(from, (1..k).collect::<Vec<_>>());
        assert!(c.quiet(100), "nothing duplicated to the joiner");
        // Everyone already there: the grown roster, then only the joiner's blob.
        for p in players.iter_mut() {
            let m = p.recv();
            assert_eq!((be32(&m, 0), be16(&m, 26)), (MEMBER, k));
            let b = p.recv();
            assert_eq!((be32(&b, 0), be16(&b, 4)), (MEMBER_BLOB, k));
            assert!(p.quiet(50), "no blob replays to existing members");
        }
        players.push(c);
    }
    assert!(listed(addr, 2).is_empty(), "a full lobby is not offered");
    let mut ninth = Client::connect(addr, "p9");
    ninth.send(&join(GAME, room, 9));
    assert!(ninth.quiet(200), "a ninth player is refused");
    assert!(players[0].quiet(100));

    // Member 5 leaves: the other seven hear it, and the lobby is listed again.
    players[4].send(&short(ROOM_LEAVING, 0, 0, room));
    players.remove(4);
    for p in players.iter_mut() {
        let l = p.recv();
        assert_eq!((be32(&l, 0), be16(&l, 16)), (ROOM_LEAVE, 5));
    }
    assert_eq!(listed(addr, 2), [room]);

    // The host leaves: the remaining six are told the owner left and the
    // room closed.
    players[0].send(&short(ROOM_LEAVING, 0, 0, room));
    for p in players.iter_mut().skip(1) {
        let l = p.recv();
        assert_eq!((be32(&l, 0), be16(&l, 16)), (ROOM_LEAVE, 1));
        assert_eq!(be32(&p.recv(), 0), ROOM_CLOSED);
    }
    assert!(listed(addr, 2).is_empty());
}

#[test]
fn playlists_are_matched_separately() {
    let (_mm, addr) = start(Duration::from_secs(60));
    let mut hosts = Vec::new();
    let mut host = |name: &str, ptr: u32, field: u32, key: u32| {
        let mut c = Client::connect(addr, name);
        let mut r = create(ptr, field, name, 1);
        r[CREATE_PLAYLIST_KEY..CREATE_PLAYLIST_KEY + 4].copy_from_slice(&key.to_be_bytes());
        c.send(&r);
        let id = id8(&c.recv(), 16);
        hosts.push(c);
        id
    };
    // Supply Raid parties / solo / DLC, Survivors solo, Interrogation parties.
    let sr_party = host("a", GAME, 1, 0xd3b8_6d60);
    let sr_solo = host("b", GAME, 2, 0xb3ec_2405);
    let sr_dlc = host("c", GAME, 3, 0x0207_a1dd);
    let sv_solo = host("d", GAME, 7, 0x36a4_9c9f);
    let in_party = host("e", GAME, 11, 0x5c49_4f79);
    // An unidentified variant: public only with its own playlist key.
    let sv_v4 = host("f", GAME, 9, 0x613e_7592);
    host("g", GAME, 9, 0);
    // Private matches (random field, no key) and a party: never listed.
    host("h", GAME, 0x5a, 0);
    host("i", GAME, 0x13, 0);
    host("j", PARTY, 6, 0xae00_a01f);

    assert_eq!(listed(addr, 1), [sr_party]);
    assert_eq!(listed(addr, 2), [sr_solo]);
    assert_eq!(listed(addr, 3), [sr_dlc]);
    assert_eq!(listed(addr, 7), [sv_solo]);
    assert_eq!(listed(addr, 11), [in_party]);
    assert_eq!(listed(addr, 9), [sv_v4], "keyed variant only");
    assert!(listed(addr, 6).is_empty(), "the party is not a lobby");
    for private in [0x5a, 0x13] {
        assert!(listed(addr, private).is_empty());
    }
}

#[test]
fn playlist_names() {
    let b = Some("01.11");
    assert_eq!(playlist_name(b, 1), "Supply Raid / Parties Allowed (id 1)");
    assert_eq!(playlist_name(b, 7), "Survivors / No Parties (id 7)");
    assert_eq!(playlist_name(b, 13), "Interrogation / DLC (id 13)");
    assert_eq!(playlist_name(b, 10), "Survivors / variant 5 (id 10)");
    assert_eq!(playlist_name(Some("01.00"), 3), "Survivors");
    assert_eq!(playlist_name(b, 0x5a), "playlist 90");
}

#[test]
fn unknown_records_are_dropped_not_fatal() {
    let (_mm, addr) = start(Duration::from_secs(60));
    let mut c = Client::connect(addr, "odd");
    c.send(&[0, 0, 0x99, 0x99, 1, 2, 3]);
    std::thread::sleep(Duration::from_millis(100));
    let mut data = record(SET_ROOM_DATA, 0x90);
    data[16] = 7;
    c.send(&data);
    let r = c.recv();
    assert_eq!((be32(&r, 0), r.len(), r[16]), (ROOM_DATA_UPDATED, 0x90, 7));
}
