use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use tlou_server::content_set::{Content, MAX_ASSET, MAX_HEADERS, REQUEST_TIMEOUT};

static NEXT: AtomicU64 = AtomicU64::new(0);
const BODY: &[u8] = b"synthetic-bootstrap\0\xff";

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        // Test files stay in this crate's target directory, never OS temp.
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("asset.bin"), BODY).unwrap();
        let fixture = Self { root };
        fixture.manifest(&fixture.row("asset.bin", BODY));
        fixture
    }
    fn row(&self, file: &str, body: &[u8]) -> String {
        format!(
            "content.example.test\t/net1.bin.psarc.crypt\t{file}\t{:x}\tprepared\tsynthetic-test-only\n",
            Sha256::digest(body)
        )
    }
    fn manifest(&self, rows: &str) {
        fs::write(
            self.root.join("manifest.tsv"),
            format!("tlou-bootstrap-v1\n{rows}"),
        )
        .unwrap();
    }
    fn load(&self) -> std::io::Result<Content> {
        Content::load(&self.root, &self.root.join("manifest.tsv"))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let allowed =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target")).unwrap();
        let resolved = fs::canonicalize(&self.root).unwrap();
        assert!(resolved.starts_with(&allowed) && resolved != allowed);
        fs::remove_dir_all(resolved).unwrap();
    }
}

fn exchange(content: Content, chunks: &[&[u8]]) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        content.serve(&mut stream).unwrap();
    });
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(6)))
        .unwrap();
    for chunk in chunks {
        client.write_all(chunk).unwrap();
    }
    client.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    task.join().unwrap();
    response
}
fn split_response(response: &[u8]) -> (&str, &[u8]) {
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    (
        std::str::from_utf8(&response[..split]).unwrap(),
        &response[split..],
    )
}

#[test]
fn exact_body_query_case_and_port() {
    let fixture = Fixture::new();
    let response = exchange(
        fixture.load().unwrap(),
        &[b"GET /net1.bin.psarc.crypt?cache=%2f HTTP/1.1\r\nHost: CONTENT.EXAMPLE.TEST:18080\r\n\r\n"],
    );
    let (headers, body) = split_response(&response);
    assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(headers.contains(&format!("Content-Length: {}\r\n", BODY.len())));
    assert!(headers.contains("Connection: close\r\n"));
    assert_eq!(body, BODY);
}

#[test]
fn head_advertises_same_size_without_body() {
    let fixture = Fixture::new();
    let response = exchange(
        fixture.load().unwrap(),
        &[b"HEAD /net1.bin.psarc.crypt HTTP/1.0\r\nHost: content.example.test\r\n\r\n"],
    );
    let (headers, body) = split_response(&response);
    assert!(headers.contains(&format!("Content-Length: {}\r\n", BODY.len())));
    assert!(body.is_empty());
}

#[test]
fn every_split_of_request_has_same_result() {
    let fixture = Fixture::new();
    let request = b"GET /net1.bin.psarc.crypt HTTP/1.1\r\nHost: content.example.test\r\n\r\n";
    for split in 0..=request.len() {
        let response = exchange(
            fixture.load().unwrap(),
            &[&request[..split], &request[split..]],
        );
        assert_eq!(split_response(&response).1, BODY);
    }
}

#[test]
fn unknown_host_or_path_never_returns_empty_success() {
    let fixture = Fixture::new();
    for request in [
        "GET /missing HTTP/1.1\r\nHost: content.example.test\r\n\r\n",
        "GET /net1.bin.psarc.crypt HTTP/1.1\r\nHost: elsewhere.test\r\n\r\n",
    ] {
        let response = exchange(fixture.load().unwrap(), &[request.as_bytes()]);
        assert!(response.starts_with(b"HTTP/1.1 404 "));
        assert!(!split_response(&response).1.is_empty());
    }
}

#[test]
fn unsafe_targets_and_framing_rejected() {
    let fixture = Fixture::new();
    for target in [
        "/../asset.bin",
        "/./asset.bin",
        "/%2e%2e/asset.bin",
        "/a\\b",
        "//asset.bin",
        "/a//b",
        "/a#frag",
        "http://content.example.test/net1.bin.psarc.crypt",
    ] {
        let request = format!("GET {target} HTTP/1.1\r\nHost: content.example.test\r\n\r\n");
        let response = exchange(fixture.load().unwrap(), &[request.as_bytes()]);
        assert!(response.starts_with(b"HTTP/1.1 400 "), "{target}");
    }
    for headers in [
        "",
        "Host: content.example.test\r\nHost: content.example.test\r\n",
        "Host: content.example.test\r\nContent-Length: 1\r\n",
        "Host: content.example.test\r\nContent-Length: 0\r\nContent-Length: 0\r\n",
        "Host: content.example.test\r\nTransfer-Encoding: chunked\r\n",
        "Host: content.example.test\r\nExpect: 100-continue\r\n",
        " Host: content.example.test\r\n",
        "Host: content.example.test:65536\r\n",
    ] {
        let request = format!("GET /net1.bin.psarc.crypt HTTP/1.1\r\n{headers}\r\n");
        let response = exchange(fixture.load().unwrap(), &[request.as_bytes()]);
        assert!(response.starts_with(b"HTTP/1.1 400 "), "{headers}");
    }
}

#[test]
fn method_uri_header_and_eof_limits_are_explicit() {
    let fixture = Fixture::new();
    let response = exchange(
        fixture.load().unwrap(),
        &[b"PUT /asset HTTP/1.1\r\nHost: content.example.test\r\n\r\n"],
    );
    assert!(response.starts_with(b"HTTP/1.1 405 "));
    assert!(split_response(&response).0.contains("Allow: GET, HEAD\r\n"));
    let long_uri = format!(
        "GET /{} HTTP/1.1\r\nHost: content.example.test\r\n\r\n",
        "a".repeat(2048)
    );
    assert!(
        exchange(fixture.load().unwrap(), &[long_uri.as_bytes()]).starts_with(b"HTTP/1.1 414 ")
    );
    let long_headers = vec![b'a'; MAX_HEADERS];
    assert!(exchange(fixture.load().unwrap(), &[&long_headers]).starts_with(b"HTTP/1.1 431 "));
    assert!(
        exchange(fixture.load().unwrap(), &[b"GET /asset HTTP/1.1\r\nHost:"])
            .starts_with(b"HTTP/1.1 400 ")
    );
}

#[test]
fn one_request_per_connection_even_when_coalesced() {
    let fixture = Fixture::new();
    let request = b"GET /net1.bin.psarc.crypt HTTP/1.1\r\nHost: content.example.test\r\n\r\nGET /missing HTTP/1.1\r\nHost: content.example.test\r\n\r\n";
    let response = exchange(fixture.load().unwrap(), &[request]);
    assert_eq!(split_response(&response).1, BODY);
}

#[test]
fn snapshots_survive_file_changes_but_restart_rejects_changes() {
    let fixture = Fixture::new();
    let loaded = fixture.load().unwrap();
    fs::write(fixture.root.join("asset.bin"), b"changed after startup").unwrap();
    assert!(fixture.load().is_err());
    let response = exchange(
        loaded,
        &[b"GET /net1.bin.psarc.crypt HTTP/1.1\r\nHost: content.example.test\r\n\r\n"],
    );
    assert_eq!(split_response(&response).1, BODY);
}

#[test]
fn manifest_errors_missing_wrong_hash_duplicates_and_empty() {
    let fixture = Fixture::new();
    for rows in [
        fixture.row("missing.bin", BODY),
        fixture.row("asset.bin", b"wrong bytes"),
        format!(
            "{}{}",
            fixture.row("asset.bin", BODY),
            fixture.row("asset.bin", BODY)
        ),
        String::new(),
        fixture.row("../outside.bin", BODY),
        fixture.row("C:/outside.bin", BODY),
        fixture.row("a/../asset.bin", BODY),
        fixture
            .row("asset.bin", BODY)
            .replace("\tprepared\t", "\tverified\t"),
    ] {
        fixture.manifest(&rows);
        assert!(fixture.load().is_err(), "{rows}");
    }
}

#[test]
fn any_host_routes_and_path_lookup() {
    let fixture = Fixture::new();
    fixture.manifest(
        &fixture
            .row("asset.bin", BODY)
            .replacen("content.example.test", "*", 1),
    );
    let content = fixture.load().unwrap();
    assert_eq!(
        content.get("other.example.test", "/net1.bin.psarc.crypt"),
        Some(BODY)
    );
    assert_eq!(content.get_path("/net1.bin.psarc.crypt"), Some(BODY));
    assert_eq!(content.get_path("/missing"), None);
    let response = exchange(
        content,
        &[b"GET /net1.bin.psarc.crypt HTTP/1.1\r\nHost: any.example.test\r\n\r\n"],
    );
    assert_eq!(split_response(&response).1, BODY);

    // The same path under two hosts is ambiguous for a path-only lookup.
    fixture.manifest(&format!(
        "{}{}",
        fixture.row("asset.bin", BODY),
        fixture
            .row("asset.bin", BODY)
            .replacen("content.example.test", "second.example.test", 1)
    ));
    assert_eq!(
        fixture.load().unwrap().get_path("/net1.bin.psarc.crypt"),
        None
    );
}

#[test]
fn oversized_disk_asset_is_bounded() {
    let fixture = Fixture::new();
    let file = fs::OpenOptions::new()
        .write(true)
        .open(fixture.root.join("asset.bin"))
        .unwrap();
    file.set_len((MAX_ASSET + 1) as u64).unwrap();
    assert!(
        fixture
            .load()
            .unwrap_err()
            .to_string()
            .contains("byte limit")
    );
}

#[test]
fn incomplete_live_request_has_deadline() {
    let fixture = Fixture::new();
    let content = fixture.load().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        content.serve(&mut stream).unwrap();
    });
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let start = Instant::now();
    client.write_all(b"GET /asset HTTP/1.1\r\n").unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    task.join().unwrap();
    assert!(response.starts_with(b"HTTP/1.1 408 "));
    assert!(start.elapsed() >= REQUEST_TIMEOUT - Duration::from_millis(100));
    assert!(start.elapsed() < Duration::from_secs(8));
}

#[test]
fn manifest_and_route_counts_are_bounded() {
    let fixture = Fixture::new();
    fixture.manifest(&"#".repeat(tlou_server::content_set::MAX_MANIFEST));
    assert!(
        fixture
            .load()
            .unwrap_err()
            .to_string()
            .contains("byte limit")
    );
    let rows: String = (0..=tlou_server::content_set::MAX_ROUTES)
        .map(|index| {
            fixture
                .row("asset.bin", BODY)
                .replace("/net1.bin.psarc.crypt", &format!("/asset-{index}"))
        })
        .collect();
    fixture.manifest(&rows);
    assert!(
        fixture
            .load()
            .unwrap_err()
            .to_string()
            .contains("route limit")
    );
}

#[test]
fn fixed_sha256_vector_and_zero_length_request_body() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("asset.bin"), b"abc").unwrap();
    fixture.manifest("content.example.test\t/net1.bin.psarc.crypt\tasset.bin\tba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\tprepared\tfixed-sha256-abc\n");
    let response = exchange(fixture.load().unwrap(), &[b"GET /net1.bin.psarc.crypt HTTP/1.1\r\nHost: content.example.test\r\nContent-Length: 0\r\n\r\n"]);
    assert_eq!(split_response(&response).1, b"abc");
}
