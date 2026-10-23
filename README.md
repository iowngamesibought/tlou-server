# tlou-server

A community server for the online multiplayer mode of **tlou** on a certain game console: the US release with its last update, 01.11.

This project is not affiliated with or endorsed by the game's developer or publisher. It ships no game files: you build what the server serves from **your own copy** of the game and its update, on your own machine, and keep it there.

Status: tested with two retail consoles on one LAN. Sign-in, the online menus, Find Match (each mode and variant matched separately, parties included) and private matches with full rounds work. A public match needs six players, as on the original servers; that and the leaderboards are not tested yet. Building the served content from the update (`prepare --update`) is checked file by file, but not yet on a console.

## What it serves

| Port | Service |
|---|---|
| TCP 80 | Downloads the client makes before and while going online (network data with every server address pointed here, campaign settings, per-language online texts), and player profile and game-record uploads |
| TCP 7320 | The client's framed services: sign-in ticket, ban check, heartbeat, leaderboards, game list, statistics |
| TCP 7314 | Matchmaking rooms (the game's own lobby protocol) |
| TCP 7312, 7313 | Location and voice-chat sign-in |

Platform services (sign-in to the platform itself, and the direct connections between consoles) stay with the platform. Matches are hosted by one of the consoles, as before.

## What you need from your copy of the game

| File | Used for |
|---|---|
| The **update's** main executable, **decrypted** | Its keys (`extract-keys`) and the host names to redirect (`hosts`). Read once; nothing is copied into this repository. |
| The **update's** data archive | The network data and online texts the server serves (`prepare --update`). |
| The disc's data archive (optional) | Only for consoles still on version 01.00 (`prepare --base`). |

Both update files sit together in the update's data folder, whether the update is installed on a console, installed in the console's emulator, or still a package file. A disc copy alone is not enough: the update is required.

This README deliberately doesn't name the files or the host names. To locate the files, and to set up the redirect, **ask an AI agent to follow [AGENTS.md](AGENTS.md)**: it describes how to recognise each file, and the server checks each choice. Never download these files from the internet; use only your own copy. Copying files off a console, unpacking packages and decrypting the executable are up to you.

Put them in a `game/` folder next to your config (`game/`, your config, `content*/`, `storage/` and logs are in `.gitignore`).

## Build and run

Building needs a Rust toolchain (https://rustup.rs).

```
cargo build --release
cp tlou-server.example.conf tlou-server.conf      # set public_ip

target/release/tlou-server extract-keys --elf game/<executable> --out game/keys.txt
target/release/tlou-server hosts --elf game/<executable>
target/release/tlou-server list-archive game/<archive>
target/release/tlou-server prepare --keys game/keys.txt --update game/<update archive> \
    --public-ip <this machine's IPv4> --out content
target/release/tlou-server check --config tlou-server.conf
target/release/tlou-server run --config tlou-server.conf
```

- `extract-keys` accepts only the executables it knows (checked by SHA-256) and writes a small private key file.
- `hosts` prints the host names to redirect, read from your executable, and lists separately other HTTP hosts the game uses, which this server doesn't answer.
- `list-archive` lists a data archive's entries and says whether it fits `prepare --update`, `--base` or neither. It only reads the file.
- `prepare` builds the served set into a new folder and checks every object it writes. Your address replaces the game's own server addresses in place, so it can't be longer than them: up to 12 characters (for example `192.168.1.10`) replaces every one; for a longer address add `--keep-unfitting`, which leaves the addresses it can't replace unchanged.
- `run --verbose` logs every matchmaking record.

## Network setup

- **DNS (consoles):** a console can't use a hosts file, so the names `hosts` prints must resolve to this machine through a DNS server the console uses, while every other name resolves normally (platform sign-in must keep working). One of the names is a large storage provider's bare domain that many other services use: **override it for the consoles only**, with a small DNS forwarder (dnsmasq or similar) that only the consoles use, rather than on your router for the whole network. [AGENTS.md](AGENTS.md) has the details and a check.
- **Emulator:** put the names in the emulator's IP/Hosts switch setting instead; no DNS server is needed.
- **Firewall:** allow inbound TCP 80, 7312, 7313, 7314 and 7320 from your local network only, and don't forward these ports on your router.
- **Consoles:** start the game after the server is running; the client opens its matchmaking connection once per game start. Restarting the server means restarting the game on every console.

## Security

- The sign-in ticket's platform signature is **not verified** (`ticket_trust = "transport"` trusts any well-formed ticket). Run the server on a private LAN only.
- Profile and game-record uploads are kept only from an address that recently used the services under that player's id, only for the key shapes the client uses, and with bounded size.
- Every served object is pinned by SHA-256 in the prepared manifest; nothing is fetched from the internet.

## Development

`cargo test` covers the content wrapper and archive formats, the framed-service transport, address replacement, both `prepare` sources and the `list-archive` verdict, host-name discovery, HTTP routing and uploads, the leaderboard, and the matchmaking room lifecycle (create, search per playlist, join, data relay, leave, kick, promote, reconnects, silent consoles, full eight-player lobbies).

Modules: `codec` and `transport` hold the framed-service wire format and transport, `content` the download wrapper, `archive` the archive format, `content_set` the hash-pinned served set; `services`, `matchmaking`, `http` and `minor` are the services, `ticket` reads the sign-in ticket; `keys`, `hosts` and `prepare` the setup commands.

## License

MIT (see [LICENSE](LICENSE)). The ticket reader is adapted from uc3-server (MIT). Dependencies are fetched from crates.io and keep their own licenses.
