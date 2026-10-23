# Instructions for agents helping a user set up tlou-server

You are helping someone run this server for their own copy of the game. Work through the steps below in order, and check each one before moving on. Read `README.md` first for what the server does.

<!-- Shared ground rules: copied verbatim from the game-server agent-docs template. Edit them there, then copy to every project. -->
## Ground rules

- **Use only the user's own copy of the game.** Never download game files, decrypted executables, keys or license files from the internet, and never suggest where to get them. If the user doesn't have the files, stop and tell them what's missing.
- **Decrypting the executable is the user's job.** Where the server needs the executable decrypted, the user provides that form from their own copy; it is their responsibility. Don't explain how to decrypt it, and never obtain a decrypted copy elsewhere.
- **Never put game-derived files in this repository**: executables, archives, generated output, decompiler projects or exports, server logs, stored uploads. Keep them in a folder outside it, or in the git-ignored folders this guide names.
- **The host names you find go into the user's DNS setup only.** Don't write them into this repository (code, docs, config examples, commits or issues), and don't copy anything else out of the executable: no keys, code or text. The server reads what it needs from the user's files at runtime.
- **Change the user's system only with their agreement**: firewall rules, DNS, router settings.
<!-- End of shared ground rules. -->

In this project the git-ignored folders for game-derived files are `game/`, `content*/`, `storage/` and `logs/`. The key file that `extract-keys` writes counts as game-derived: keep it private in `game/`. The rule about the executable covers the archives too: copy nothing out of them.

## 1. Supply the required files

The server needs two files from the user's own copy of the game, plus one optional file. This guide deliberately doesn't name them: identify them from the descriptions below. They are not config keys but the inputs of the setup commands (`--elf`, `--update`, `--base`), which turn them into a key file and a folder of served content. `tlou-server.conf` (copy it from `tlou-server.example.conf`) then names those two under `keys_file` and `content_dir`. Relative paths resolve from the config file's folder.

### Where to look

Follow the [pick-game-files](.claude/skills/pick-game-files/SKILL.md) skill: it finds the base game and the latest update in the user's copy, disc or download, and takes the update's copy of each file over the base game's. For this game:

- Only the game's **US release** is supported. Other regions are not.
- Both required files come from its **update 01.11**, the last one: the update's executable and its data archive. A copy without the update won't work. If the user has only the disc or a copy of it, stop and tell them that update 01.11 is needed.
- The update's **data folder** holds both files directly in it. An installation may hold other content beside them, such as downloadable content in subfolders. On a console or in the console's emulator, it is inside the game's folder (named after the title id) in the game data. In a package file, it is inside the package.
- The metadata file next to the data folder records the title id, the version and whether the folder holds an update or a disc's game data. Expect version `01.11` and an update. The disc's own metadata file says version `01.00` and disc game data.
- The update's network data has a new name, `dc1/net-10.bin`, which is what 01.11 consoles use, and it is the one the server needs. The base game's older `dc1/net.bin` is needed only for consoles still on 01.00, and only through the optional `--base` archive. That is normally no consoles at all: a console installs the update before playing online.
- `extract-keys` knows the executables by SHA-256: the update's (01.11) and the disc's (01.00). The disc's executable also works for keys and host names, but use the update's. If the update's executable isn't known, see the check below.

Copying files off a console, unpacking packages and decrypting the executable are the user's job. Ask for the files once they are on this machine. Copy them into a `game/` folder in this repository (git-ignored), keeping their original names, and pass them to the commands as `game/<file name>`. Absolute paths elsewhere work too. Never place them anywhere that gets committed.

### What each file is

| Used as | How to recognise it |
|---|---|
| `--elf` | The **update's main boot executable**: the one file with a `.BIN` extension directly in the update's data folder, about 20.3 MB. As installed or packaged it is **encrypted** (it does not start with `\x7fELF`). The server needs it **decrypted** to an ELF: starts with `\x7fELF`, then bytes `02 02` (64-bit, big-endian). See the ground rules. The disc's executable is about 20.1 MB (version 01.00). |
| `--update` | The update's **data archive**: the other file directly in the update's data folder, about 250 MB, in the game's own archive format. It holds the update's network data (an entry ending in `dc1/net-10.bin`) and the per-language online texts (`text1/<n>.networking`). |
| `--base` (optional) | The disc's **data archive** in its `build/main/` folder, about 9 MB: the one that holds the game's data files, including the original network data (entry `dc1/net.bin`). Only for consoles still on 01.00. |

The disc's `build/main/` folder also holds much larger archives with map and character data. None of them is right.

### Check each candidate with the server itself

Build the server first (`cargo build --release`, item 2 of the check below).

- `tlou-server list-archive <file>` lists an archive's entries and ends with a verdict: `fits --update`, `fits --base` or `fits neither --update nor --base`. It applies the same tests as `prepare`, and only reads the file. `not a game archive` means the file isn't an archive at all. `--all` lists every entry instead of the first 20. Go through the candidates as the skill describes until you have the update's archive, plus the base game's if it is needed.
- For the executable, `extract-keys` (below) accepts only an executable it knows.

**Check:**
1. Ask the user for this machine's IPv4 address on the LAN: the address the consoles reach it at (not `0.0.0.0`, not a placeholder).
2. Run `cargo build --release` from this repository. There is no prebuilt binary: if `cargo` is missing, install the Rust toolchain first (rustup, https://rustup.rs). The commands below call `target/release/tlou-server` by the short name `tlou-server`.
3. Extract the keys:
   ```
   tlou-server extract-keys --elf game/<executable> --out game/keys.txt
   ```
   Expected: `keys of build 01.11 written to game/keys.txt`. **"is not a supported build"** means the file's SHA-256 is not one the server knows. Check that the file starts with `\x7fELF 02 02` (decrypted), that it comes from the update's data folder, and that the metadata file next to it says version 01.11 and an update. If all of that holds, stop and report it: the server only knows the executables it was tested with, and supporting another one (another region, or a decryption that produced different bytes) needs a code change.
4. Build the served content:
   ```
   tlou-server prepare --keys game/keys.txt --update game/<update archive> \
       --public-ip <address> --out content
   ```
   Add `--base game/<base archive>` only for consoles still on 01.00. The report must show three `replaced <address>` lines for `net10.bin` (and three for `net1.bin` with `--base`), `campaign configuration (generated)`, and one `output /build/main/text1/<n>.networking.crypt` per language. Errors:
   - **"the update archive has no dc1/net-10.bin"**: `--update` is not the update's data archive.
   - **"the base archive has no dc1/net.bin"**: `--base` is not the disc's data archive.
   - **"does not fit in place of a ...-character address"**: the address is longer than the game's own server addresses. A shorter address is best, up to 12 characters (for example a static `192.168.1.10`). `--keep-unfitting` leaves the addresses that don't fit unchanged.
   - **"already exists"**: `prepare` never overwrites. Pick a new `--out` folder, and set `content_dir` to match.
5. Copy `tlou-server.example.conf` to `tlou-server.conf` and set `public_ip` (the same address), `keys_file` and `content_dir`. Then run `tlou-server check --config tlou-server.conf`. Expected: `configuration, keys and content OK`.

## 2. Find the host names in the user's executable

This guide deliberately doesn't name the hosts. The server reads them from the user's own decrypted executable:

```
tlou-server hosts --elf game/<executable>
```

It prints:
- **The names to point at this server:** the storage provider's hosts the game downloads its network data, campaign settings and online texts from (plain HTTP, port 80), and the provider's **bare domain**, which the game uploads profiles and game records to. Every other address the client uses (the service ports) comes from the network data that `prepare` rewrote, so no other names are needed.
- **Other HTTP hosts the game uses**, which this server does not answer. Leave those alone.

**"no download host template found"** means the file is not the game's main executable. Write the names down only for the DNS setup in step 3.

## 3. Set up the DNS override

Follow the [dns-override](.claude/skills/dns-override/SKILL.md) skill to point the names from step 2 at `public_ip`. For this game:

- Override every name `hosts` lists under "point at this server". Every other name must resolve normally, because the platform's own sign-in has to keep working.
- The **bare domain** belongs to the storage provider, which many other devices and services rely on: override it **for the console only**. Its `address=` line also catches every other name under it. On a DNS server only the console uses, that one line already covers the provider's other names, which is fine.
- **In the console's emulator** no DNS server is needed: put the names in its IP/Hosts switch setting (network settings), as `<name>=<this machine's address>` entries joined by `&&`. Platform sign-in there goes through the emulator's own network service.

**Check:**
1. `nslookup <name> <console's DNS server>` must return `public_ip`, for every name from step 2, and a name not in the list must still resolve normally. Query the console's DNS server explicitly: the machine you run the check on may use a different resolver.
2. Allow inbound TCP 80, 7312, 7313, 7314 and 7320 on the server machine, from the local network only. On Windows, a network marked "Public" blocks them. Don't forward these ports on the router: everything the server serves is derived from the user's game files.
3. Run `tlou-server run --config tlou-server.conf --verbose`. Start the game on the console after the server, and go online. The server log should show, in order:
   - `GET <host>/net10.bin.psarc.crypt: <n> bytes` from the console's address: this confirms the download host;
   - `ticket accepted for <online id>`;
   - `<online id> connected (session <n>)`;
   - `GET <host>/build/main/text1/<n>.networking.crypt`, then the profile (`not available, empty 200` the first time is normal), `get-location`, `heartbeat`, `is-banned [...]: not banned` and the voice `hello`;
   - `PUT /profiles/<id>/profile.21: stored ...`: this confirms the bare-domain override.

   Then Find Match logs `search <mode> / <variant> (id <n>) -> <k> room(s)`, and a console that hosts logs `created public room`.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| No request reaches the server | Follow "No request reaches the server" in the [dns-override](.claude/skills/dns-override/SKILL.md) skill, with the host the console downloads `net10.bin.psarc.crypt` from, and port 80 |
| `net10` downloaded, but no `ticket accepted` | `public_ip`/`--public-ip` is not reachable from the console, or TCP 7320 is blocked |
| `ticket accepted`, but no `connected (session ...)` | TCP 7314 is blocked |
| Online menus show "UNKNOWN STRING" everywhere | The text for the console's language wasn't served: check the `text1/<n>.networking.crypt` request and the `output` lines of `prepare` |
| One single label shows "UNKNOWN STRING" | Expected: the update's texts have one string fewer than the original servers' downloadable ones (most likely the Facebook-link prompt; Facebook is not supported) |
| No `PUT` lines; progress isn't kept between sessions | The bare domain isn't overridden for the console |
| `has no recent session from this address; acknowledged, not kept` | The server was restarted while the console was online: restart the game |
| A public lobby closes after a while and everyone searches again | Expected with fewer than six players: a match needs six, as on the original servers |
| Two consoles searching at the same moment each host their own lobby | Both searched before either lobby existed; one finds the other on its next search |
| Nothing works after restarting the server | The console opens its matchmaking connection once per game start: restart the game on every console |
