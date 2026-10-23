---
name: pick-game-files
description: Decides which copy of each game file to use when the user's copy of the game may have an update installed. The update's copy of a file replaces the base game's, so it is the one the console uses. Use before setting the game-file paths in the server's config or setup commands (see AGENTS.md).
---

# Pick the game files: the update's copy over the base game's

The console runs the game with its latest update applied. Wherever the update has its own copy of a file, the game loads that copy and never the base game's. The server's files have to be the ones the console uses, so take the update's copy whenever there is one, and the base game's copy only when the update has none. This holds for a disc copy and a downloaded copy alike.

AGENTS.md says which files the server needs and how to recognise each one. This guide says where to look and which copy to take; it is the same in every project that uses it, and AGENTS.md has the project's specifics. Its ground rules apply here too: use only the user's own copy, never download game files or updates, never commit them.

## 1. Find the base game and the update

Ask the user where their copy of the game is, whether it is a disc or a downloaded copy, whether it runs on a console or in an emulator, and whether the game's latest update is installed. The game is no longer developed, so its latest update is final. If it isn't installed, the user has to install it first; don't continue without it.

Copying the files off the console (or the disc), and unpacking or installing a package file, are the user's job; ask them for the folders once they are on this machine. There are two places:

- **Base game:** a data folder with the game's original main executable and a tree of data archives (for example `build/main/`). For a disc copy, it is on the disc.
- **Update:** a data folder with the update's own main executable and the archives the update added, directly in the folder.

How they are laid out depends on the copy:

| Copy | Layout |
|---|---|
| Disc | Two folders: the base game's on the disc, the update's on the console's storage. |
| Downloaded | One folder: the update installs into the game's own folder, replacing the main executable and adding its archives next to it. |
| Downloaded edition with the updates built in | One folder that already holds the newest copies; there is no separate update. |
| Installed in an emulator | The same layout as on the console's storage, in the emulator's own game-data folder. |
| Update as a package file | The update's data folder is inside the package. The user unpacks it, or installs it, and gives you the folder. |

If the user gives you a single folder, work out which case it is before going on.

**Confirm it is the latest update** with the metadata file that sits next to the update's data folder (in an edition with the updates built in, next to its one data folder). It records the game's title id, the version, and whether the folder holds an update or a disc's game data. If AGENTS.md lists the values to expect, compare them: a lower version means the latest update isn't installed, so stop as above. If it lists none, tell the user the title id and version you found, and go on.

## 2. List what each candidate holds

Don't judge an archive by its name or size alone. List its entries with the command AGENTS.md names for this (it only reads the file); AGENTS.md also says how to read its verdict.

- Skip the very large archives (about 1 GB and more): they hold map, sound or character data, which a server doesn't need, and listing one can take a lot of memory.
- The main executable is the one file with a `.BIN` extension directly in a data folder. AGENTS.md says which form of it the server needs.

## 3. Match the copies by game path

Two copies are the same file when they have the same **game path**: the path the game loads it by, relative to the data folder.

- **Loose files** have their path in the data folder as their game path. The update's main executable is the same file as the base game's.
- **Base game archives:** an archive `<folder>/<name>.<ext>` stands for the folder `<folder>/<name>/`. Its entry `<entry>` has the game path `<folder>/<name>/<entry>`.
- **Update archives** store each entry under its full game path.

For example, entry `a/b.bin` in the base game's `build/main/<name>.psarc` and entry `build/main/<name>/a/b.bin` in an update archive are the same file, and the update's copy wins. An update archive also adds files the base game doesn't have. Confirm the mapping on the user's copy: an update archive's entries under `<folder>/<name>/` should match entry names of the base game's `<name>` archive.

An update can also ship a newer version of a file under a **new name** (for example `a/b-2.bin` beside the base game's `a/b.bin`). That is a different game path, so the base game's copy is not replaced. AGENTS.md says which name the server needs, and whether it still needs the base game's older one (for consoles without the update).

## 4. Take the newest copy of each file

For each file the server needs:

1. **The update has a copy:** take the update's. If several of the update's archives have one, the archive with the highest number in its name is the latest patch and wins.
2. **The update has none:** take the base game's. Some editions ship a patch archive of their own with the base game. It is newer than the base game's archives but older than any archive of the update.

The server's config keys or command options usually point at archive files, not entries: set each one to the archive that holds the winning copy of the entries it needs. AGENTS.md says when one takes the base game's archive instead, or as a fallback for entries the update's archive lacks.

## 5. Confirm with the server

- Run the checks AGENTS.md lists: the server's startup log, or the setup commands that read the files. The server can refuse a file from an older build. Then you picked an older copy: go back to step 4.
- If the server doesn't know the build of the update's executable, follow AGENTS.md. Don't substitute a file from another edition, region or source.
- Tell the user which file you picked for each config key or command option and why (update or base game), and copy the files where AGENTS.md says (a git-ignored folder).

Files from different editions or regions don't mix: everything comes from the user's one copy and its own update.
