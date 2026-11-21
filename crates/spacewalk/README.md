# spacewalk

## Introducing AgentSpaces by Bad Monkey AI

**A peer-to-peer coordination fabric for agents, services, and the people who work with them.**

AgentSpaces is a P2P framework to quickly discover and join P2P networks, where agents, software services, and people share assets, queries, results, and coordinate. Agents post work, claim tasks, publish results, vote on decisions, and recover from each other's failures. There is no broker, no registry, no scheduler, and no server to keep alive.

## What spacewalk does

spacewalk is a terminal UI that shares files from a local directory into an agent space, and pulls files other members shared back out. It is one static Rust binary with no JVM beside it.

It writes and reads exactly what the AgentSpaces Groovy console's **Add to space…** writes, so a console user and a spacewalk user see each other's files:

- **The bytes** become a chunked blob that the sharing member serves over the content swarm.
- **The index** is the group's `file-share` map, which stores each file under `<space>/<relative path>`.
- **The notice** is a `SharedFile` record in the space, so readers of the space see the file arrive.

A shared file stays fetchable while some member that holds it runs. spacewalk holds what it shares for as long as it runs.

## Build

From the root of `agentspaces-rust` (Rust 1.99):

```bash
cargo build --release -p spacewalk
# the binary: target/release/spacewalk
```

## Quick start: two terminals, no console

Start a seed for a group, then share from one directory and fetch into another.

```bash
# terminal 1: a seed for the group "team-files"
aspace seed --listen tcp://127.0.0.1:7880 --group team-files --profile dev-local

# terminal 2: share the data directory of ~/alice, and keep holding it
spacewalk --seeds tcp://127.0.0.1:7880 --group team-files --space shared -C ~/alice put data

# terminal 3: list and fetch into ~/bob
spacewalk --seeds tcp://127.0.0.1:7880 --group team-files --space shared -C ~/bob ls
spacewalk --seeds tcp://127.0.0.1:7880 --group team-files --space shared -C ~/bob get data/notes.txt
```

Open the terminal UI on the same group with:

```bash
spacewalk --seeds tcp://127.0.0.1:7880 --group team-files --space shared -C ~/bob
```

## Quick start: with the Groovy console

1. Open a notebook in the console and run it, so its peer starts. The tutorial notebook has **File sharing** on. For any other notebook, turn on **Configure peer → File sharing → Enable content and persistent trees**, then **Save & restart peer**.
2. Read the peer's bind address from the notebook's banner (for example `127.0.0.1:7760`) and its configuration YAML from **Configure peer**.
3. Start spacewalk on that YAML and address:

```bash
spacewalk --config /path/to/notebook.yaml --seeds tcp://127.0.0.1:7760 -C ~/proj
```

A share the console hosts (**Share → New share → Copy beacon URL**) joins by its URL alone:

```bash
spacewalk --beacon http://127.0.0.1:63554/.well-known/agentspaces/beacon.json -C ~/proj
```

spacewalk reads the beacon document, checks its signature, and joins the group it names by id through the seeds it lists. A console's share group is its collaboration group, which may not run file sharing; the header says so when no member serves files.

The YAML names the group and its spaces; spacewalk opens the first space it lists, or the one `--space` names. The tutorial notebook's group is founded from the text `groovy-console-orders-v1`, so this works too:

```bash
spacewalk --seeds tcp://127.0.0.1:7760 --group groovy-console-orders-v1 --space catalogue -C ~/proj
```

A file you share is an entry of the console's `file-share` map, which a cell reads with `fleet.context('shop').requiredPdt().treeRef('file-share').deref()`, and its `SharedFile` record is in the space under the console's own type, `ai.badmonkey.agentspaces.groovy.console.files.SharedFile`. A file the console shares shows in spacewalk's space pane, and `d` downloads it.

## The terminal UI

```
 spacewalk  shop / catalogue  peer z7f3a…  members 2  tcp 127.0.0.1:7760  development share: unencrypted
┌ /Users/you/proj ───────────────────────┐┌ catalogue (file-share, 3 file(s)) ────────────────────┐
│ v     data/                            ││= [ ] data/report.csv      12.4 KiB      you    2m     │
│   [x] data/report.csv         12.4 KiB ││  [ ] model.json            1.1 MiB z9egem…    9s      │
│   [ ] data/raw.parquet        48.0 MiB ││  [ ] notes/plan.md          3.0 KiB z9egem…    1h     │
│ >     notes/                           ││                                                       │
│   [ ] README.md                2.1 KiB ││                                                       │
└────────────────────────────────────────┘└───────────────────────────────────────────────────────┘
 tab pane  space mark  s share  d download  x withdraw  r refresh  / filter  ? help  q quit
```

The left pane is the local directory, the right pane the files shared into the space, with size, sharer, and age. In the right pane `=` marks a local copy of the same size and `~` a local copy of another size.

| Key | Does |
|---|---|
| `tab` | Switch between the local pane and the space pane |
| `↑` `↓`, `j` `k` | Move; `PgUp` `PgDn`, `g` `G` jump |
| `enter`, `l` | Open or close a directory (local pane) |
| `space` | Mark or unmark the row |
| `s` | Share the marked files, or the selected file or directory |
| `d` | Download the marked or selected shared files into the directory |
| `x` | Withdraw the marked or selected shared files from the space |
| `r` | Read the space and the directory again |
| `c` | Choose another space (also opens by itself when no space is named) |
| `/` | Filter both panes by path; `enter` keeps the filter, `esc` clears it |
| `.` | Show or hide dot files |
| `esc` | Clear marks and the filter |
| `?` | Help |
| `q`, `ctrl-c` | Quit (asks again while an action runs) |

Every share, download, and withdraw asks first and names each file. A download keeps existing files unless you answer `o` (overwrite).

## Commands for scripts

With a command, spacewalk does that one thing and exits.

| Command | Does |
|---|---|
| `spacewalk ls [--json]` | List the files shared into the space; `--json` prints one object per file |
| `spacewalk put <path>... [--exit]` | Share files or directories (inside `-C`), then hold them for other members until `ctrl-c`; `--exit` leaves at once |
| `spacewalk get <key>... [--overwrite]` | Download into `-C` at each file's relative path |
| `spacewalk rm <key>...` | Remove files from the space's file share |

A key may be given with or without its `<space>/` prefix. Exit codes: 0 done, 1 failed, 2 usage.

## Options

| Option | Meaning |
|---|---|
| `-C, --dir <DIR>` | The local directory: what the UI shows and shares, and where downloads land (default `.`) |
| `-s, --space <NAME>` | The space to share into (default: the first space the fleet file lists for the group; with none, the UI opens a picker of the group's spaces) |
| `--config <FILE>` | The fleet YAML: the `agentspaces:` subtree of the Java starter's file, which a console notebook's YAML is |
| `--seeds <SEEDS>` | Comma-separated seeds, `scheme://host:port` or `host:port` |
| `--group <NAME>` | A group of the fleet file by name, or else a founding text |
| `--join <URI>` | Join a group by id, `aspace://<group-id>` |
| `--beacon <URL>` | Join the group a beacon serves; `--group` names one when the document lists several |
| `--store <DIR>` | Keep shared and fetched files (tree nodes and artifact pieces) in this directory, and hold again on start what this store shared (default: memory) |
| `--log <FILE>` | Write a log; `SPACEWALK_LOG` sets the level (default `info`) |
| `--keystore <DIR>` | A lasting identity (default: a fresh identity each run) |
| `--profile <PROFILE>` | `mtls` (the default) or `dev-local` |
| `--join-timeout <SECONDS>` | How long joining may take (default 10) |
| `--max-file <BYTES>` | The size limit of a shared file (default 64 MiB, the console's) |
| `--show-hidden` | Show dot files in the local pane |
| `--no-color` | No colour (also `NO_COLOR`) |

The configuration layers are those of `aspace`: these flags, then the `ASPACE_*` variables, then the fleet YAML (`--config`, `ASPACE_CONFIG`, `~/.config/agentspaces/fleet.yaml`).

## What spacewalk refuses

- **Sharing:** a symbolic link, anything but a regular file, a path outside `-C`, dot files when sharing a directory, more than 1,000 files in one share, and a file over the size limit (counted while reading, so a file that grows during the share fails).
- **Downloading:** a key whose path could leave `-C` (`..`, an absolute path, a backslash, a control character, a name Windows reserves), a symbolic-link entry, a path through a linked directory, and a size over the limit. It never sets the executable bit.
- **Displaying:** remote names and keys are drawn with control characters and bidirectional overrides replaced by `?`, so a hostile file name cannot rewrite the screen.

## Good to know

- **Development shares are not encrypted.** A `tcp://` seed under `dev-local`, the console tutorial's profile, signs every frame but encrypts nothing; the header says so. Use `tls://` seeds and the `mtls` profile for anything private.
- **Files live as long as a holder.** Without `--store`, spacewalk keeps what it shares in memory while it runs. With `--store`, the nodes stay on disk and the next run over the same store holds and serves those files again from the start. When the last member holding a file stops, the map still lists it but nobody can fetch it until a holder returns.
- **`rm` and records.** `rm` removes the file from the map at once. The `SharedFile` record a different process or member wrote lapses within 30 minutes, since only its writer can withdraw it.
- **`mine` and identity.** Each run has a fresh identity unless `--keystore` names one; use a keystore if you want later runs to recognise files as yours.
- **Merges.** Two members that share at the same moment both keep their files. When both change the same key at once, every member settles on the later one.

## Licence

Apache License 2.0. See the repository's `LICENSE`.
