# cron

**What it gives you:** a fleet call on a schedule. cron runs a small script every 30 minutes, and the script does three things:

- calls a fleet offering;
- appends the result to a JSON Lines file;
- logs one line per run that says what happened, sorted by `aspace`'s exit code.

`flock` makes sure a run never starts while the previous one still runs.

Before you start, do the steps in [the recipes README](README.md#before-any-recipe): `aspace` installed, the fleet file, and `aspace doctor` all `ok`.

## The configuration

The script, `~/bin/fleet-research.sh`:

```sh
#!/bin/sh
# One fleet call from cron: the result appended to a JSON Lines file, one log line per run.
set -u
umask 077
ASPACE=${ASPACE:-$HOME/.cargo/bin/aspace}
# cron sets no XDG_RUNTIME_DIR: name the socket of a running `aspace daemon` (its hello prints it).
export ASPACE_SOCKET="${ASPACE_SOCKET:-/run/user/$(id -u)/aspace/daemon.sock}"
out="$HOME/.local/state/fleet/findings.jsonl"
mkdir -p "$(dirname "$out")"
status=0
result=$("$ASPACE" -q call research --json '{"topic":"nightly","priority":1}' --timeout 2m) || status=$?
stamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case $status in
  0) printf '%s\n' "$result" >> "$out"; echo "$stamp ok" ;;
  2) echo "$stamp exit 2: no offering named research, or refused (aspace cards lists the offerings)" ;;
  3) echo "$stamp exit 3: no result within 2m; the request stays leased for a late worker" ;;
  4) echo "$stamp exit 4: the fleet refused this identity, or its key file is readable by others" ;;
  *) echo "$stamp exit $status: error (see the lines above)" ;;
esac
exit "$status"
```

The crontab line, on Linux (`crontab -e`). It must stay on one line:

```crontab
*/30 * * * * flock -n -E 75 "$HOME/.cache/fleet-research.lock" "$HOME/bin/fleet-research.sh" >> "$HOME/.cache/fleet-research.log" 2>&1 || echo "fleet-research exited $?" >> "$HOME/.cache/fleet-research.log"
```

On macOS, which has no `flock`, `lockf` does the same. `-t 0` means don't wait, and a held lock exits 75 too:

```crontab
*/30 * * * * /usr/bin/lockf -k -t 0 "$HOME/.cache/fleet-research.lock" "$HOME/bin/fleet-research.sh" >> "$HOME/.cache/fleet-research.log" 2>&1 || echo "fleet-research exited $?" >> "$HOME/.cache/fleet-research.log"
```

Set it up:

```sh
mkdir -p ~/bin ~/.cache
install -m 0700 fleet-research.sh ~/bin/fleet-research.sh
touch ~/.cache/fleet-research.log && chmod 600 ~/.cache/fleet-research.log
crontab -e      # add the line
```

### What each part does

- **`flock -n -E 75`:** takes the lock without waiting. When the previous run still holds it, `flock` exits 75 at once and the script doesn't start.
- **`>> ... 2>&1`:** keeps the script's log line and `aspace`'s errors in one file, so cron mails nothing.
- **`|| echo "fleet-research exited $?"`:** records every run that didn't exit 0, with its code:

  | Code | Meaning |
  |---|---|
  | 2 | No offering by that name, or refused |
  | 3 | No result in time |
  | 4 | Authentication failed |
  | 1 | An error |
  | 75 | Skipped: the previous run was still going |

- **Inside the script:**
  - `aspace -q` keeps standard error to errors only.
  - `|| status=$?` keeps a failing call from ending the script before it logs.
  - `umask 077` makes the results file owner-only.
- **cron's environment:** cron runs with a minimal `PATH` and no `XDG_RUNTIME_DIR`. So the script names `aspace` by its absolute path, and names the daemon's socket in `ASPACE_SOCKET` (when no daemon answers there, `aspace` joins the group itself). The fleet file comes from `$HOME/.config/agentspaces/fleet.yaml`, since cron sets `HOME`.

### The daemon and the keystore

A cron job that joins by itself takes about 0.3 s, which is fine for a schedule. Through `aspace daemon` the same call takes milliseconds. Whichever you use, mind one rule: a visitor that runs from the keystore of a running gateway or worker, without going through it, sees no offerings and exits 2 ([why](../mcp.md#identity-one-gateway-per-keystore)). A visitor that runs from the keystore of a running daemon of its group and can't use it refuses to join at all: exit 2 naming the socket the daemon listens on when it looked at another one, exit 1 when the daemon didn't answer. So:

- **If you run `aspace daemon` on the default keystore:** the script must reach it, so `ASPACE_SOCKET` must be the socket the daemon printed (the refusal names it). The script's default is the Linux one, `/run/user/<uid>/aspace/daemon.sock`, for a daemon started in your login session or as a systemd user service.
- **Otherwise:** give the cron job a keystore of its own (`"$ASPACE" -q --keystore "$HOME/.config/agentspaces/cron-keys" call ...`), and let the fleet admit that PeerID.

## Check that it works

Run the crontab line's command by hand, in an environment as bare as cron's:

```sh
env -i HOME="$HOME" LOGNAME="$LOGNAME" PATH=/usr/bin:/bin SHELL=/bin/sh \
  sh -c 'flock -n -E 75 "$HOME/.cache/fleet-research.lock" "$HOME/bin/fleet-research.sh" >> "$HOME/.cache/fleet-research.log" 2>&1 || echo "fleet-research exited $?" >> "$HOME/.cache/fleet-research.log"'
tail -n 2 ~/.cache/fleet-research.log                     # 2026-11-08T23:30:00Z ok
tail -n 1 ~/.local/state/fleet/findings.jsonl | jq .entry
```

On macOS, put the `lockf` line's command in the `sh -c '...'` instead.

To see the overlap guard, hold the lock and run the same command again. The log gains `fleet-research exited 75`:

```sh
flock "$HOME/.cache/fleet-research.lock" sleep 20 &      # macOS: /usr/bin/lockf -k "$HOME/.cache/fleet-research.lock" sleep 20 &
```

Once the line is in your crontab, `grep fleet-research /var/log/syslog` (or `journalctl -t CRON`) on Linux shows cron starting it.

## Security notes

- **Tokens and secrets:** the job needs none beyond the keystore. Keep `~/.config/agentspaces/keys` owner-only (`aspace` refuses a readable `peer.key`, exit 4). Put nothing secret in the crontab line or in `--json` arguments: other users can read command lines (`ps`). Pass sensitive input as `--json @file` with an owner-only file.
- **Loopback and transport:** a cron job is a visitor, not a server: it listens on nothing. With the default `mtls` profile, its `tls://` seeds attest their PeerID. Plaintext `tcp://` is refused outside loopback.
- **`--only` and scopes:** these belong to `aspace mcp`. A cron job calls exactly the offering it names, as its own identity. The group's authorizer decides what that identity may do, so give a dedicated cron identity only what the job needs.
- **Files:** the log and the results file are owner-only (`chmod 600` and `umask 077`). Results come from fleet members: treat them as data, and never `eval` them.
- **The lock file** sits in your own `~/.cache`. A world-writable directory such as `/tmp` would let another user hold the lock and stop your job.

## How this recipe was checked (2026-11-08)

- **The run:** on macOS, against a live fleet (the Java seed of `interop/java-seed` with a Java agent offering `research`). The script and the `lockf` line ran by hand under `env -i` with only `HOME`, `LOGNAME`, `PATH=/usr/bin:/bin`, and `SHELL`, as cron runs them. Observed:
  - a result appended and `ok` logged;
  - exit 2 logged for an offering that doesn't exist;
  - `fleet-research exited 75` while another process held the lock.
- **The daemon rule:** run as well. A cron-like visitor without `XDG_RUNTIME_DIR` missed a daemon on the default keystore, saw no offerings, and exited 2. With `ASPACE_SOCKET` naming the daemon's socket, the call was answered. `aspace` has changed since that run: such a visitor no longer joins with the daemon's PeerID, and exits 2 naming the daemon's socket. That refusal is checked by the `daemon_e2e` tests (a visitor looking at another socket, a stopped daemon, a weaker profile); the cron run itself was not repeated.
- **The Linux line:** the `flock` line wasn't run, since macOS has no `flock`. It ran with `flock -n -E 75` replaced by `lockf -k -t 0`, which gives the same exit 75 on a held lock. Its options were checked against flock(1), <https://man7.org/linux/man-pages/man1/flock.1.html>: `-n` fails rather than waits, `-E` sets the conflict exit code, and otherwise the exit status is the command's.
