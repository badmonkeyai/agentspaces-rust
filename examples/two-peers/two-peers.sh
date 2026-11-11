#!/bin/sh
# Copyright 2026 Bad Monkey, Inc.
# Author: Al Baker
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Two peers in a shell, with nothing but the aspace binary:
#
#   1. Peer 1 is `aspace seed --found demo`: it founds the group demo and listens.
#   2. Peer 2, with a keystore of its own, writes a note and reads it back.
#   3. A worker serves the action "shout" (`aspace work -- ./handler.sh`), and a third peer
#      calls it (`aspace call shout`).
#   4. A late visitor reads the note peer 2 wrote, long after peer 2 left: the seed holds it.
#   5. The worker and the seed stop.
#
#   ./two-peers.sh
#
# Every command is printed before it runs, as you would type it in the scratch directory the
# script works in (keystores under keys/, logs beside them). It needs `aspace` on PATH (or
# ASPACE=/path/to/aspace) and port 7700 free on 127.0.0.1 (PORT=7711 picks another; PORT=0
# lets the system choose). Everything runs under the dev-local profile on loopback: plaintext
# tcp, every frame signed. Every process it starts is stopped before it exits, also on a failure
# or Ctrl-C, and the scratch directory is removed unless KEEP=1.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
port=${PORT:-7700}
if [ -n "${ASPACE:-}" ]; then
    PATH=$(cd "$(dirname "$ASPACE")" && pwd):$PATH
    [ "$(basename "$ASPACE")" = aspace ] || { echo "two-peers.sh: ASPACE must name a file called aspace" >&2; exit 1; }
fi
command -v aspace >/dev/null 2>&1 || {
    echo "two-peers.sh: aspace not found; install it (cargo install --locked --path crates/aspace) or set ASPACE" >&2
    exit 1
}

work=$(mktemp -d "${TMPDIR:-/tmp}/two-peers.XXXXXX")
# Nothing of yours applies: HOME, the configuration directory, and every keystore are the
# scratch directory's.
for variable in ASPACE_CONFIG ASPACE_SEEDS ASPACE_GROUP ASPACE_JOIN ASPACE_INVITE ASPACE_KEYSTORE \
    ASPACE_PROFILE ASPACE_SPACES ASPACE_SOCKET ASPACE_LISTEN ASPACE_ADVERTISE ASPACE_NO_DAEMON; do
    unset "$variable"
done
export HOME="$work/home" XDG_CONFIG_HOME="$work/config" XDG_RUNTIME_DIR="$work/run"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_RUNTIME_DIR" "$work/keys"
chmod 700 "$XDG_RUNTIME_DIR"
cp "$here/handler.sh" "$work/handler.sh"
chmod 755 "$work/handler.sh"
cd "$work"

seed_pid=
worker_pid=

# stop <pid> <name>: SIGTERM, then up to 15 s for it to end (SIGKILL past that); sets `status`.
stop() {
    pid=$1
    status=0
    kill -TERM "$pid" 2>/dev/null || true
    rounds=0
    while kill -0 "$pid" 2>/dev/null; do
        rounds=$((rounds + 1))
        if [ "$rounds" -gt 75 ]; then
            echo "two-peers.sh: $2 did not stop within 15s; killing it" >&2
            kill -KILL "$pid" 2>/dev/null || true
            break
        fi
        sleep 0.2
    done
    wait "$pid" 2>/dev/null || status=$?
}

finish() {
    code=$?
    trap - EXIT INT TERM
    if [ -n "$worker_pid" ]; then stop "$worker_pid" worker; fi
    if [ -n "$seed_pid" ]; then stop "$seed_pid" seed; fi
    cd /
    if [ "${KEEP:-0}" = 1 ]; then
        echo "two-peers.sh: kept $work"
    else
        rm -rf "$work"
    fi
    exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    echo "two-peers.sh: $*" >&2
    for log in seed.log worker.log; do
        if [ -s "$log" ]; then
            echo "--- $log" >&2
            tail -n 20 "$log" >&2
        fi
    done
    exit 1
}

step() { printf '\n==> %s\n' "$*"; }

# run <command>: prints the command, then runs it here.
run() {
    printf '$ %s\n' "$1"
    eval "$1" || fail "exited with $?: $1"
}

# wait_for <file> <text> <seconds> <pid> <name>: waits until the file holds the text.
wait_for() {
    rounds=0
    while ! grep -q -F -- "$2" "$1" 2>/dev/null; do
        kill -0 "$4" 2>/dev/null || grep -q -F -- "$2" "$1" 2>/dev/null ||
            fail "$5 ended before it printed \"$2\""
        rounds=$((rounds + 1))
        [ "$rounds" -le $(($3 * 5)) ] || fail "$5 printed no \"$2\" within $3s"
        sleep 0.2
    done
}

readonly SEED="aspace --profile dev-local --keystore keys/seed seed --found demo --listen tcp://127.0.0.1:$port >seed.json 2>seed.log &"
readonly WRITE="aspace --keystore keys/peer2 write 'demo.Note#v1' --space notes --json '{\"text\":\"hello from peer 2\"}'"
readonly READ="aspace --keystore keys/peer2 read 'demo.Note#v1' --space notes"
readonly WORKER="aspace --keystore keys/worker work --space desk --take 'demo.Shout#v1' --produces 'demo.Shouted#v1' --action shout -- ./handler.sh 2>worker.log &"
readonly CARDS="aspace --keystore keys/caller cards"
readonly CALL="aspace --keystore keys/caller call shout --json '{\"text\":\"hello, fleet\"}' --timeout 30s"
readonly LATE="aspace --keystore keys/late read 'demo.Note#v1' --space notes"
readonly STATUS="aspace --keystore keys/late status"

step "peer 1, the seed: it founds the group demo and listens on 127.0.0.1:$port"
run "$SEED"
seed_pid=$!
wait_for seed.json '"event":"listening"' 30 "$seed_pid" "the seed"
cat seed.json
echo "(the seed runs as pid $seed_pid)"
seeds=$(sed -n -E 's/.*"listen":\["([^"]+)".*/\1/p' seed.json)
join=$(sed -n -E 's/.*"join":"(aspace:[^"]+)".*/\1/p' seed.json)
[ -n "$seeds" ] && [ -n "$join" ] || fail "the seed's listening line names no address or group"
step "every other peer joins through it: the same group, a keystore of its own"
run "export ASPACE_PROFILE=dev-local ASPACE_SEEDS=$seeds ASPACE_JOIN=$join ASPACE_NO_DAEMON=1"

step "peer 2 writes a note, reads it back, and leaves"
run "$WRITE"
run "$READ"

step "a worker serves the action shout: aspace work runs ./handler.sh once per task"
run "$WORKER"
worker_pid=$!
wait_for worker.log "working as" 30 "$worker_pid" "the worker"
grep -m 1 -o 'working as [^ ]*' worker.log
echo "(the worker runs as pid $worker_pid)"

step "a third peer finds the action and calls it"
# The worker's card reaches the seed a moment after it starts: look again at 0.5, 1, 2, 2, ... s.
pause=0.5
waited=0
until aspace --keystore keys/caller cards 2>/dev/null | grep -q '^shout '; do
    [ "$waited" -lt 30 ] || fail "no peer sees the shout action within 30s"
    sleep "$pause"
    waited=$((waited + 1))
    case $pause in 0.5) pause=1 ;; 1) pause=2 ;; esac
done
run "$CARDS"
run "$CALL"

step "a late visitor, joining long after peer 2 left, reads its note from the seed"
run "$LATE"
run "$STATUS"

step "stopping the worker and the seed (SIGTERM, as Ctrl-C)"
stop "$worker_pid" worker
worker_pid=
[ "$status" = 0 ] || fail "the worker exited with $status"
echo "the worker stopped with status 0"
stop "$seed_pid" seed
seed_pid=
[ "$status" = 0 ] || fail "the seed exited with $status"
echo "the seed stopped with status 0; what it said:"
cat seed.log
echo
echo "two peers: done"
