use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tlou_server::config::{Config, TicketTrust};
use tlou_server::http::Http;
use tlou_server::keys::Keys;
use tlou_server::leaderboard::Leaderboard;
use tlou_server::matchmaking::Matchmaking;
use tlou_server::presence::Presence;
use tlou_server::services::Services;
use tlou_server::{info, minor, prepare, warn};

const USAGE: &str = "\
tlou-server: private server for tlou's online multiplayer mode

  tlou-server extract-keys --elf <decrypted executable> --out <keys file>
      Read the title keys from your own executable (01.00 or 01.11).
  tlou-server hosts --elf <decrypted executable>
      List the host names to point at this server in your DNS.
  tlou-server list-archive <archive> [--all]
      List a data archive's entries and say which prepare input it fits.
  tlou-server prepare --keys <keys file> --update <update archive>
                      [--base <base game data archive>]
                      --public-ip <IPv4> [--ticket-port <port>]
                      [--keep-unfitting] --out <new dir>
      Build the served content set from your installed game.
  tlou-server prepare --keys <keys file> --originals <dir> [--ancillary <dir>]
                      --public-ip <IPv4> ... --out <new dir>
      The same from already downloaded originals (for comparison).
  tlou-server check --config <file>
      Load configuration, keys and content without opening ports.
  tlou-server run --config <file> [--verbose]
      Start every service.
";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn need(args: &[String], name: &str) -> Result<String, String> {
    arg(args, name).ok_or_else(|| format!("missing {name}\n\n{USAGE}"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("extract-keys") => extract_keys(&args),
        Some("hosts") => hosts(&args),
        Some("list-archive") => list_archive(&args),
        Some("prepare") => prepare_cmd(&args),
        Some("check") => load(&args).map(|_| println!("configuration, keys and content OK")),
        Some("run") => load(&args).and_then(run),
        _ => Err(USAGE.to_string()),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn extract_keys(args: &[String]) -> Result<(), String> {
    let elf = need(args, "--elf")?;
    let out = PathBuf::from(need(args, "--out")?);
    if out.exists() {
        return Err(format!("{} already exists", out.display()));
    }
    let keys = Keys::from_elf(&std::fs::read(&elf).map_err(|e| format!("{elf}: {e}"))?)?;
    std::fs::write(&out, keys.to_text()).map_err(|e| e.to_string())?;
    println!(
        "keys of build {} written to {} (keep this file private)",
        keys.build,
        out.display()
    );
    Ok(())
}

fn hosts(args: &[String]) -> Result<(), String> {
    let elf = need(args, "--elf")?;
    let hosts = tlou_server::hosts::from_executable(
        &std::fs::read(&elf).map_err(|e| format!("{elf}: {e}"))?,
    )?;
    println!("Point these names at this server's address in your DNS:");
    for name in &hosts.served {
        println!("  {name}");
    }
    if !hosts.other.is_empty() {
        println!("Other HTTP hosts the game uses, not answered by this server (leave them alone):");
        for name in &hosts.other {
            println!("  {name}");
        }
    }
    Ok(())
}

fn list_archive(args: &[String]) -> Result<(), String> {
    let file = args
        .get(1)
        .filter(|a| !a.starts_with("--"))
        .ok_or_else(|| format!("missing <archive>\n\n{USAGE}"))?;
    let names = prepare::archive_names(&PathBuf::from(file))?;
    println!("{file}: {} entries", names.len());
    let shown = if args.iter().any(|a| a == "--all") {
        names.len()
    } else {
        names.len().min(20)
    };
    for name in &names[..shown] {
        println!("  {name}");
    }
    if shown < names.len() {
        println!("  ... {} more (use --all)", names.len() - shown);
    }
    println!("=> {}", prepare::archive_role(&names));
    Ok(())
}

fn prepare_cmd(args: &[String]) -> Result<(), String> {
    let keys = Keys::load(&PathBuf::from(need(args, "--keys")?))?;
    let source = match (arg(args, "--update"), arg(args, "--originals")) {
        (Some(update), None) => prepare::Source::Install {
            update: update.into(),
            base: arg(args, "--base").map(PathBuf::from),
        },
        (None, Some(dir)) => prepare::Source::Originals {
            dir: dir.into(),
            ancillary: arg(args, "--ancillary").map(PathBuf::from),
        },
        _ => {
            return Err(format!(
                "give one of --update or --originals

{USAGE}"
            ));
        }
    };
    let inputs = prepare::Inputs {
        source,
        keep_unfitting: args.iter().any(|a| a == "--keep-unfitting"),
        public_ip: need(args, "--public-ip")?
            .parse()
            .map_err(|_| "--public-ip: not an IPv4 address")?,
        ticket_port: arg(args, "--ticket-port")
            .map_or(Ok(7320), |p| p.parse().map_err(|_| "--ticket-port"))?,
        out: need(args, "--out")?.into(),
    };
    print!("{}", prepare::run(&keys, &inputs)?);
    Ok(())
}

struct Loaded {
    config: Config,
    keys: Keys,
    content: tlou_server::content_set::Content,
    verbose: bool,
}

fn load(args: &[String]) -> Result<Loaded, String> {
    let config = Config::load(&PathBuf::from(need(args, "--config")?))?;
    let keys = Keys::load(&config.keys_file)?;
    let manifest = config.content_dir.join("manifest.tsv");
    let content = tlou_server::content_set::Content::load(&config.content_dir, &manifest)
        .map_err(|e| format!("content {}: {e}", manifest.display()))?;
    Ok(Loaded {
        config,
        keys,
        content,
        verbose: args.iter().any(|a| a == "--verbose"),
    })
}

fn bind(c: &Config, port: u16) -> Result<TcpListener, String> {
    let addr = SocketAddr::new(c.bind_ip, port);
    TcpListener::bind(addr).map_err(|e| format!("binding {addr}: {e}"))
}

fn run(l: Loaded) -> Result<(), String> {
    let c = l.config;
    tlou_server::log::set_verbose(l.verbose);
    std::fs::create_dir_all(&c.storage_dir)
        .map_err(|e| format!("{}: {e}", c.storage_dir.display()))?;
    if let Some(p) = &c.log_file {
        tlou_server::log::open_file(p).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    // Bind everything first so a busy port fails before anything starts.
    let http_l = bind(&c, c.http_port)?;
    let ticket_l = bind(&c, c.ticket_port)?;
    let session_l = bind(&c, c.session_port)?;
    let location_l = bind(&c, c.location_port)?;
    let voice_l = bind(&c, c.voice_port)?;

    let presence = Arc::new(Presence::default());
    let leaderboard = Arc::new(Leaderboard::open(&c.storage_dir.join("leaderboard.tsv"))?);
    if c.ticket_trust == TicketTrust::Deny {
        warn!(
            "main",
            "ticket_trust = deny: every sign-in is refused (set \"transport\" for a private LAN)"
        );
    }
    info!(
        "main",
        "keys of build {}; {} content routes ({} bytes); public address {}",
        l.keys.build,
        l.content.route_count(),
        l.content.total_bytes(),
        c.public_ip
    );
    let services = Arc::new(Services {
        key: l.keys.frame,
        trust: c.ticket_trust,
        leaderboard,
        presence: presence.clone(),
        games: Mutex::default(),
        stats_path: Some(c.storage_dir.join("stat_events.jsonl")),
    });
    let http = Arc::new(Http {
        content: l.content,
        storage: c.storage_dir.clone(),
        presence: presence.clone(),
        uploads: c.profile_uploads,
        missing: c.missing_content,
    });
    let mm = Matchmaking::new(presence);
    let (lat, lon) = c.location;
    let threads = vec![
        std::thread::spawn(move || http.serve(http_l)),
        std::thread::spawn(move || services.serve(ticket_l)),
        std::thread::spawn(move || mm.serve(session_l)),
        std::thread::spawn(move || minor::serve_location(location_l, lat, lon)),
        std::thread::spawn(move || minor::serve_voice(voice_l)),
    ];
    info!("main", "all services started; Ctrl+C stops the server");
    for t in threads {
        let _ = t.join();
    }
    Ok(())
}
