//! Builds the served content set: the objects the client downloads before
//! and while going online, pointed at this server.
//!
//! Sources (one of):
//! * `--update <archive>`: the operator's installed update archive. The
//!   network data file `dc1/net-10.bin` becomes the 01.11 client's
//!   `net10.bin`, and the per-language networking string tables
//!   `text1/<n>.networking` are wrapped for download. With `--base <archive>`
//!   (the base game's data archive), its `dc1/net.bin` becomes the 01.00
//!   client's `net1.bin`.
//! * `--originals <dir>`: the wrapped objects as the client downloads them
//!   (`net1.bin.psarc.crypt`, `net10.bin.psarc.crypt`, optionally
//!   `campaign3.config.txt.crypt` and, with `--ancillary <dir>`, further
//!   objects under their own paths), for comparison with the above.
//!
//! In both, every IPv4 address stored in a network data file is replaced by
//! the server's address (the client connects to these directly, without a
//! DNS lookup); an address that does not fit in place is an error unless
//! `--keep-unfitting` is given. The campaign configuration names this server
//! as its queue server. Every object is read back and checked before it is
//! written.
//!
//! Output: one file per URL path plus `manifest.tsv` (tlou-bootstrap-v1,
//! SHA-256 pinned, any host) and `prepare-report.txt`. An existing output is
//! refused.

use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::keys::Keys;
use crate::log::hex;

/// Objects copied unchanged in `--originals` mode when present.
const ANCILLARY: [&str; 4] = [
    "t1/upgrades/upgrades.txt.crypt",
    "t1/upgrades/extras.txt.crypt",
    "t1/upgrades/upgrades7.txt.crypt",
    "build/main/pak23/level-1.psarc.crypt",
];
/// Language indices of the networking string tables.
const TEXT_LANGUAGES: u32 = 32;
/// The update archive's network data (a suffix: its entries carry full game
/// paths) and the base archive's (an exact name).
const UPDATE_NET: &str = "dc1/net-10.bin";
const BASE_NET: &str = "dc1/net.bin";
/// Campaign configuration values other than the queue server (those of the
/// retail configuration).
const CAMPAIGN_DEFAULTS: [(&str, &str); 4] = [
    ("interval", "30"),
    ("enable", "0"),
    ("enable-dlc-facebook", "1"),
    ("enable-dlc-facebook-text", "0"),
];

pub enum Source {
    /// Installed update archive, optional base game data archive.
    Install {
        update: PathBuf,
        base: Option<PathBuf>,
    },
    /// Directory of downloaded originals, optional directory of further
    /// objects.
    Originals {
        dir: PathBuf,
        ancillary: Option<PathBuf>,
    },
}

pub struct Inputs {
    pub source: Source,
    pub public_ip: Ipv4Addr,
    pub ticket_port: u16,
    /// Leave a network-file address in place when the server's address is
    /// longer than it (otherwise an error).
    pub keep_unfitting: bool,
    pub out: PathBuf,
}

struct Output {
    dir: PathBuf,
    manifest: String,
    report: String,
}

impl Output {
    fn add(&mut self, key: &str, data: &[u8], kind: &str, label: &str) -> Result<(), String> {
        let path = self.dir.join(key);
        std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&path, data).map_err(|e| format!("{}: {e}", path.display()))?;
        let digest = hex(&Sha256::digest(data));
        writeln!(self.manifest, "*\t/{key}\t{key}\t{digest}\t{kind}\t{label}").unwrap();
        writeln!(
            self.report,
            "output /{key} {} bytes sha256 {digest} ({kind})",
            data.len()
        )
        .unwrap();
        Ok(())
    }

    fn note(&mut self, line: impl AsRef<str>) {
        writeln!(self.report, "{}", line.as_ref()).unwrap();
    }
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Replace every IPv4 address in one network data file; returns the report
/// lines.
pub fn patch_net_blob(
    data: &mut [u8],
    ip: &str,
    keep_unfitting: bool,
) -> Result<Vec<String>, String> {
    let found = crate::archive::ipv4_literals(data);
    if found.is_empty() {
        return Err("no IPv4 address found; is this a network data file?".into());
    }
    if !keep_unfitting && let Some(short) = found.iter().find(|old| old.len() < ip.len()) {
        return Err(format!(
            "{ip} ({} characters) does not fit in place of a {}-character address; \
             use an address of at most {} characters, or --keep-unfitting to leave \
             such addresses unchanged",
            ip.len(),
            short.len(),
            found.iter().map(String::len).min().unwrap()
        ));
    }
    let mut lines = Vec::new();
    for old in &found {
        match crate::archive::replace_ipv4(data, &[old.as_str()], ip) {
            Ok(edits) => lines.extend(
                edits
                    .iter()
                    .map(|e| format!("replaced {} at {:#x}", e.old, e.offset)),
            ),
            Err(why) => lines.push(format!("kept {old}: {why}")),
        }
    }
    Ok(lines)
}

/// Wrap one network data file as the client downloads it: a one-entry
/// archive named `<name>.bin`, inside the content wrapper.
fn serve_net(
    keys: &Keys,
    inputs: &Inputs,
    name: &str,
    mut data: Vec<u8>,
    out: &mut Output,
) -> Result<(), String> {
    let wrapper = keys.wrapper()?;
    let ip = inputs.public_ip.to_string();
    for line in patch_net_blob(&mut data, &ip, inputs.keep_unfitting)
        .map_err(|why| format!("{name}.bin: {why}"))?
    {
        out.note(format!("  {name}.bin: {line}"));
    }
    let entries = [crate::archive::Entry {
        name: format!("{name}.bin"),
        data,
    }];
    let wrapped = wrapper
        .encode(&crate::archive::write(&entries).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{name}: encode failed ({e:?})"))?;
    // Independent read-back of exactly what will be served.
    let check = crate::archive::read(
        &wrapper
            .decode(&wrapped)
            .map_err(|e| format!("{name}: read-back ({e:?})"))?,
    )
    .map_err(|e| format!("{name}: read-back {e}"))?;
    if check != entries {
        return Err(format!("{name}: read-back differs from the edited content"));
    }
    out.add(
        &format!("{name}.bin.psarc.crypt"),
        &wrapped,
        "prepared",
        "ip-redirect",
    )
}

/// The network data file inside a downloaded original.
fn net_from_original(keys: &Keys, path: &Path) -> Result<Vec<u8>, String> {
    let name = path.display();
    let archive = keys
        .wrapper()?
        .decode(&read(path)?)
        .map_err(|e| format!("{name}: wrapper rejected ({e:?})"))?;
    let mut entries = crate::archive::read(&archive).map_err(|e| format!("{name}: {e}"))?;
    let i = entries
        .iter()
        .position(|e| e.name.ends_with(".bin"))
        .ok_or_else(|| format!("{name}: no network data file inside"))?;
    Ok(entries.swap_remove(i).data)
}

/// The entries of an installed data archive that `want` selects.
fn from_archive(
    path: &Path,
    want: impl Fn(&str) -> bool,
) -> Result<Vec<crate::archive::Entry>, String> {
    let data = read(path)?;
    crate::archive::read_selected(&data, want).map_err(|e| archive_error(path, e))
}

fn archive_error(path: &Path, e: crate::archive::Error) -> String {
    match e {
        crate::archive::Error::Magic => format!("{}: not a game archive", path.display()),
        e => format!("{}: not a readable data archive ({e})", path.display()),
    }
}

fn is_text_table(name: &str) -> bool {
    name.contains("text1/") && name.ends_with(".networking")
}

/// An archive's entry names, for `list-archive`.
pub fn archive_names(path: &Path) -> Result<Vec<String>, String> {
    crate::archive::names(&read(path)?).map_err(|e| archive_error(path, e))
}

/// Which `prepare` input an archive with these entries fits: the verdict
/// line of `list-archive`, by the same tests `prepare` applies.
pub fn archive_role(names: &[String]) -> String {
    let texts = names.iter().filter(|n| is_text_table(n)).count();
    if names.iter().any(|n| n.ends_with(UPDATE_NET)) {
        format!("fits --update (holds {UPDATE_NET} and {texts} networking text tables)")
    } else if names.iter().any(|n| n == BASE_NET) {
        format!("fits --base (holds {BASE_NET}; only for consoles still on 01.00)")
    } else {
        "fits neither --update nor --base (no network data)".into()
    }
}

fn campaign(
    keys: &Keys,
    inputs: &Inputs,
    original: Option<&str>,
    out: &mut Output,
) -> Result<(), String> {
    let port = inputs.ticket_port.to_string();
    let ip = inputs.public_ip.to_string();
    let queue = [
        ("queue-server-addr", ip.as_str()),
        ("queue-server-port", port.as_str()),
    ];
    let text = match original {
        Some(text) => crate::archive::set_config_values(text, &queue),
        None => queue
            .iter()
            .chain(CAMPAIGN_DEFAULTS.iter())
            .map(|(k, v)| format!("{k} {v}\n"))
            .collect(),
    };
    let wrapper = keys.wrapper()?;
    let enc = wrapper
        .encode(text.as_bytes())
        .map_err(|e| format!("campaign configuration: encode ({e:?})"))?;
    out.note(format!(
        "campaign configuration ({}): queue server {ip}:{port}",
        if original.is_some() {
            "edited"
        } else {
            "generated"
        }
    ));
    // Both names the client builds use.
    out.add(
        "campaign3.config.txt.crypt",
        &enc,
        "prepared",
        "queue-redirect",
    )?;
    out.add(
        "campaign.config.txt.crypt",
        &enc,
        "prepared",
        "queue-redirect",
    )
}

fn from_install(
    keys: &Keys,
    inputs: &Inputs,
    update: &Path,
    base: Option<&Path>,
    out: &mut Output,
) -> Result<(), String> {
    let wrapper = keys.wrapper()?;
    let entries = from_archive(update, |n| n.ends_with(UPDATE_NET) || is_text_table(n))?;
    out.note(format!(
        "update archive {}: {} entries used",
        update.display(),
        entries.len()
    ));
    let net = entries
        .iter()
        .find(|e| e.name.ends_with(UPDATE_NET))
        .ok_or("the update archive has no dc1/net-10.bin; is it the update's archive?")?;
    serve_net(keys, inputs, "net10", net.data.clone(), out)?;
    match base {
        Some(base) => {
            let net = from_archive(base, |n| n == BASE_NET)?.pop().ok_or(
                "the base archive has no dc1/net.bin; is it the base game's data archive?",
            )?;
            serve_net(keys, inputs, "net1", net.data, out)?;
        }
        None => out.note("no --base archive: net1.bin (01.00 clients) not served"),
    }
    campaign(keys, inputs, None, out)?;
    let mut tables = 0;
    for lang in 0..TEXT_LANGUAGES {
        let suffix = format!("text1/{lang}.networking");
        if let Some(e) = entries.iter().find(|e| e.name.ends_with(&suffix)) {
            let enc = wrapper
                .encode(&e.data)
                .map_err(|err| format!("{suffix}: encode ({err:?})"))?;
            if wrapper.decode(&enc).ok().as_deref() != Some(&e.data[..]) {
                return Err(format!("{suffix}: read-back differs"));
            }
            out.add(
                &format!("build/main/{suffix}.crypt"),
                &enc,
                "prepared",
                "networking-text",
            )?;
            tables += 1;
        }
    }
    if tables == 0 {
        out.note("no networking string tables in the update archive; online labels will read UNKNOWN STRING");
    }
    Ok(())
}

fn from_originals(
    keys: &Keys,
    inputs: &Inputs,
    dir: &Path,
    ancillary: Option<&Path>,
    out: &mut Output,
) -> Result<(), String> {
    for name in ["net1", "net10"] {
        let path = dir.join(format!("{name}.bin.psarc.crypt"));
        if path.exists() {
            out.note(format!(
                "input {} sha256 {}",
                path.display(),
                hex(&Sha256::digest(read(&path)?))
            ));
            let data = net_from_original(keys, &path)?;
            serve_net(keys, inputs, name, data, out)?;
        } else {
            out.note(format!("absent (not served): {name}.bin.psarc.crypt"));
        }
    }
    let path = dir.join("campaign3.config.txt.crypt");
    let original = if path.exists() {
        let plain = keys
            .wrapper()?
            .decode(&read(&path)?)
            .map_err(|e| format!("{}: wrapper rejected ({e:?})", path.display()))?;
        Some(String::from_utf8(plain).map_err(|_| format!("{}: not text", path.display()))?)
    } else {
        None
    };
    campaign(keys, inputs, original.as_deref(), out)?;
    let Some(dir) = ancillary else {
        return Ok(());
    };
    let wrapper = keys.wrapper()?;
    let tables = (0..TEXT_LANGUAGES).map(|n| format!("build/main/text1/{n}.networking.crypt"));
    for key in ANCILLARY.iter().map(|k| k.to_string()).chain(tables) {
        let path = dir.join(&key);
        if !path.exists() {
            continue;
        }
        let data = read(&path)?;
        wrapper
            .decode(&data)
            .map_err(|e| format!("{key}: wrapper rejected ({e:?})"))?;
        out.add(&key, &data, "original", "unchanged")?;
    }
    Ok(())
}

pub fn run(keys: &Keys, inputs: &Inputs) -> Result<String, String> {
    if inputs.out.exists() {
        return Err(format!(
            "{} already exists; choose a new output folder",
            inputs.out.display()
        ));
    }
    std::fs::create_dir_all(&inputs.out).map_err(|e| e.to_string())?;
    let mut out = Output {
        dir: inputs.out.clone(),
        manifest: "tlou-bootstrap-v1\n".into(),
        report: format!(
            "tlou-server prepare {}\npublic address {}\nkeys of build {}\n",
            crate::log::timestamp(),
            inputs.public_ip,
            keys.build
        ),
    };
    let result = match &inputs.source {
        Source::Install { update, base } => {
            from_install(keys, inputs, update, base.as_deref(), &mut out)
        }
        Source::Originals { dir, ancillary } => {
            from_originals(keys, inputs, dir, ancillary.as_deref(), &mut out)
        }
    };
    if let Err(e) = result {
        let _ = std::fs::remove_dir_all(&inputs.out);
        return Err(e);
    }
    std::fs::write(inputs.out.join("manifest.tsv"), &out.manifest).map_err(|e| e.to_string())?;
    std::fs::write(inputs.out.join("prepare-report.txt"), &out.report)
        .map_err(|e| e.to_string())?;
    Ok(out.report)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Addresses below are from the documentation ranges (RFC 5737).
    const BLOB: &[u8] = b"head\x00203.0.113.200\x00198.51.100.17\x00mid\x00192.0.2.10\x00tail";

    fn synthetic_keys() -> Keys {
        Keys {
            build: "test".into(),
            frame: [0; 16],
            content_cipher: b"synthetic-key".to_vec(),
            content_mac: b"synthetic-mac-key".to_vec(),
        }
    }

    fn inputs(source: Source, out: PathBuf) -> Inputs {
        Inputs {
            source,
            public_ip: Ipv4Addr::new(10, 0, 0, 5),
            ticket_port: 7320,
            keep_unfitting: false,
            out,
        }
    }

    fn served_blob(w: &crate::content::Wrapper, out: &Path, name: &str) -> Vec<u8> {
        let served = std::fs::read(out.join(format!("{name}.bin.psarc.crypt"))).unwrap();
        let entries = crate::archive::read(&w.decode(&served).unwrap()).unwrap();
        assert_eq!(entries[0].name, format!("{name}.bin"));
        entries[0].data.clone()
    }

    /// Each slot keeps its length: the rest of the old string and its NUL
    /// become NULs.
    fn redirected() -> Vec<u8> {
        let ip = &b"10.0.0.5"[..];
        [
            &b"head\0"[..],
            ip,
            &[0; 6],
            ip,
            &[0; 6],
            b"mid\0",
            ip,
            &[0; 3],
            b"tail",
        ]
        .concat()
    }

    #[test]
    fn from_install_archives() {
        let dir = std::env::temp_dir().join(format!("tlou-prep-inst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let keys = synthetic_keys();
        let w = keys.wrapper().unwrap();
        let entry = |name: &str, data: &[u8]| crate::archive::Entry {
            name: name.into(),
            data: data.to_vec(),
        };
        let update = crate::archive::write(&[
            entry("build/main/bin/dc1/net-10.bin", BLOB),
            entry("build/main/bin/dc1/net-9.bin", b"\x00192.0.2.99\x00"),
            entry("build/main/bin/dc1/net.bin", b"\x00192.0.2.98\x00"),
            entry("build/main/text1/2.networking", b"\x00\x00\x0a\xb1strings"),
            entry("build/main/other.pak", b"unrelated"),
        ])
        .unwrap();
        std::fs::write(dir.join("update.archive"), update).unwrap();
        let base = crate::archive::write(&[entry("dc1/net.bin", BLOB)]).unwrap();
        std::fs::write(dir.join("base.archive"), base).unwrap();

        let out = dir.join("out");
        let report = run(
            &keys,
            &inputs(
                Source::Install {
                    update: dir.join("update.archive"),
                    base: Some(dir.join("base.archive")),
                },
                out.clone(),
            ),
        )
        .unwrap();
        assert!(report.contains("replaced 198.51.100.17"));
        assert_eq!(served_blob(&w, &out, "net10"), redirected());
        assert_eq!(served_blob(&w, &out, "net1"), redirected());
        let table = std::fs::read(out.join("build/main/text1/2.networking.crypt")).unwrap();
        assert_eq!(w.decode(&table).unwrap(), b"\x00\x00\x0a\xb1strings");
        let c = std::fs::read(out.join("campaign.config.txt.crypt")).unwrap();
        assert_eq!(
            String::from_utf8(w.decode(&c).unwrap()).unwrap(),
            "queue-server-addr 10.0.0.5\nqueue-server-port 7320\ninterval 30\nenable 0\n\
             enable-dlc-facebook 1\nenable-dlc-facebook-text 0\n"
        );
        let content = crate::content_set::Content::load(&out, &out.join("manifest.tsv")).unwrap();
        assert_eq!(content.route_count(), 5);
        assert!(content.get_path("/net10.bin.psarc.crypt").is_some());
        let again = run(
            &keys,
            &inputs(
                Source::Install {
                    update: dir.join("update.archive"),
                    base: None,
                },
                out.clone(),
            ),
        );
        assert!(again.is_err(), "never overwrites");
        // The base game's archive is not an update archive.
        let wrong = run(
            &keys,
            &inputs(
                Source::Install {
                    update: dir.join("base.archive"),
                    base: None,
                },
                dir.join("out2"),
            ),
        );
        assert!(wrong.unwrap_err().contains("net-10.bin"));
        assert!(!dir.join("out2").exists(), "no partial output");
        // Nor is the update's archive the base game's (its own net.bin is the
        // update's data, not the 01.00 one).
        let wrong = run(
            &keys,
            &inputs(
                Source::Install {
                    update: dir.join("update.archive"),
                    base: Some(dir.join("update.archive")),
                },
                dir.join("out3"),
            ),
        );
        assert!(wrong.unwrap_err().contains("dc1/net.bin"));
        // list-archive tells the three apart by the same tests.
        let role = |name: &str| archive_role(&archive_names(&dir.join(name)).unwrap());
        assert_eq!(
            role("update.archive"),
            "fits --update (holds dc1/net-10.bin and 1 networking text tables)"
        );
        assert!(role("base.archive").starts_with("fits --base"));
        let other = crate::archive::write(&[entry("build/main/other.pak", b"x")]).unwrap();
        std::fs::write(dir.join("other.archive"), other).unwrap();
        assert!(role("other.archive").starts_with("fits neither"));
        let elf = [b"\x7fELF\x02\x02".as_slice(), &[0; 64]].concat();
        std::fs::write(dir.join("plain.bin"), elf).unwrap();
        let err = archive_names(&dir.join("plain.bin")).unwrap_err();
        assert!(err.contains("not a game archive"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn from_downloaded_originals() {
        let dir = std::env::temp_dir().join(format!("tlou-prep-orig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let orig = dir.join("orig");
        let anc = dir.join("anc");
        std::fs::create_dir_all(orig.clone()).unwrap();
        std::fs::create_dir_all(anc.join("build/main/text1")).unwrap();
        let keys = synthetic_keys();
        let w = keys.wrapper().unwrap();
        for name in ["net1", "net10"] {
            let archive = crate::archive::write(&[crate::archive::Entry {
                name: format!("{name}.bin"),
                data: BLOB.to_vec(),
            }])
            .unwrap();
            std::fs::write(
                orig.join(format!("{name}.bin.psarc.crypt")),
                w.encode(&archive).unwrap(),
            )
            .unwrap();
        }
        let cfg = "queue-server-addr 192.0.2.10\nqueue-server-port 7320\ninterval 10\nenable 1\n";
        std::fs::write(
            orig.join("campaign3.config.txt.crypt"),
            w.encode(cfg.as_bytes()).unwrap(),
        )
        .unwrap();
        let table = w.encode(b"\x00\x00\x0a\xb2strings").unwrap();
        std::fs::write(anc.join("build/main/text1/2.networking.crypt"), &table).unwrap();
        let mut inp = inputs(
            Source::Originals {
                dir: orig.clone(),
                ancillary: Some(anc.clone()),
            },
            dir.join("out"),
        );
        run(&keys, &inp).unwrap();
        let out = dir.join("out");
        assert_eq!(served_blob(&w, &out, "net10"), redirected());
        let c = std::fs::read(out.join("campaign.config.txt.crypt")).unwrap();
        assert_eq!(
            String::from_utf8(w.decode(&c).unwrap()).unwrap(),
            "queue-server-addr 10.0.0.5\nqueue-server-port 7320\ninterval 10\nenable 1\n",
            "an original configuration keeps its other values"
        );
        assert_eq!(
            std::fs::read(out.join("build/main/text1/2.networking.crypt")).unwrap(),
            table,
            "served unchanged"
        );
        // A damaged ancillary object is refused.
        let mut bad = table.clone();
        *bad.last_mut().unwrap() ^= 1;
        std::fs::write(anc.join("build/main/text1/3.networking.crypt"), bad).unwrap();
        inp.out = dir.join("out2");
        assert!(run(&keys, &inp).unwrap_err().contains("3.networking"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unfitting_address_is_an_error_unless_kept() {
        let mut d = b"\x00198.51.100.17\x00192.0.2.10\x00".to_vec();
        let before = d.clone();
        // 13 characters: fits the first address, not the second.
        assert!(patch_net_blob(&mut d, "192.168.10.20", false).is_err());
        assert_eq!(d, before, "nothing changed on error");
        let lines = patch_net_blob(&mut d, "192.168.10.20", true).unwrap();
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("replaced 198.51.100.17"))
        );
        assert!(lines.iter().any(|l| l.starts_with("kept 192.0.2.10")));
        assert!(patch_net_blob(&mut b"\x00no address\x00".to_vec(), "10.0.0.1", false).is_err());
    }
}
