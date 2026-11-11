#!/usr/bin/env bash
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

# Runs the README's quick start end to end in a scratch copy of this repository, and exits
# non-zero on any mismatch:
#
#   0. Each README snippet marked <!-- quickstart/FILE --> equals FILE, licence header aside,
#      and every command below appears in the README as written there.
#   1. aspace installs (into the scratch directory), the Fulfiller builds, and ./seed.sh starts
#      `aspace seed` (no Java).
#   2. Two workers serve, and the desk's kite comes back shipped by one of them.
#   3. Kill one: with SHIP_SECONDS=10, the worker that takes the desk's order is killed with
#      kill -9 in the middle of it. The other worker ships it (attempt 2) once the 30 s take
#      lapses.
#   4. No Rust code: aspace work runs fulfil.sh; aspace cards lists ship; aspace write and
#      aspace read, aspace call, and the Rust desk each get a shipment by fulfil.sh.
#
#   ./verify.sh
#
# Needs Rust (through rustup: the repository pins its toolchain) and port 7700 free (PORT=7711
# picks another); no Java. About two minutes once built; the first build takes a few more.
# Optional: CARGO_TARGET_DIR (reuse a build directory between runs), KEEP=1 (keep the scratch
# directory and its logs).
#
# Every process it starts is stopped before it exits, also on a failure or Ctrl-C. The README's
# commands run with HOME in the scratch directory, so the keystore aspace makes is not yours.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
port=${PORT:-7700}

# The commands the README gives, run as written.
readonly WORKER='cargo run -q'
readonly DESK='cargo run -q -- kite'
readonly SLOW_WORKER='SHIP_SECONDS=10 cargo run -q'
readonly INSTALL='cargo install --locked --path ../crates/aspace'
readonly SCRIPT_WORKER="aspace --config fleet.yaml --keystore keys/script work --space orders --take 'shop.Order#v1' --produces 'shop.Shipment#v1' --name fulfiller --action ship -- ./fulfil.sh"
readonly CARDS='aspace --config fleet.yaml cards'
readonly WRITE="aspace --config fleet.yaml write 'shop.Order#v1' --space orders --json '{\"orderId\":\"o-2\",\"item\":\"ball\"}'"
readonly READ="aspace --config fleet.yaml read 'shop.Shipment#v1' --space orders --where 'orderId=o-2' --timeout 30s"
readonly CALL="aspace --config fleet.yaml call ship --json '{\"orderId\":\"o-3\",\"item\":\"yo-yo\"}'"
readonly SCRIPT_DESK='cargo run -q -- top'

say() { printf '==> %s\n' "$*"; }
ok() { printf 'ok   %s\n' "$*"; }

for tool in cargo; do
    command -v "$tool" >/dev/null 2>&1 || { echo "verify.sh: $tool not found" >&2; exit 1; }
done

# No configuration of yours applies: the fleet file is the quick start's, and the keystores are
# the scratch directory's.
unset ASPACE_CONFIG ASPACE_SEEDS ASPACE_GROUP ASPACE_JOIN ASPACE_KEYSTORE ASPACE_PROFILE \
    ASPACE_SPACES ASPACE_SOCKET ASPACE_NO_DAEMON ASPACE_INVITE ASPACE_LISTEN ASPACE_ADVERTISE \
    XDG_CONFIG_HOME SHIP_SECONDS SEED
export CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}
export RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}

tmp=${TMPDIR:-/tmp}
scratch=$(mktemp -d "${tmp%/}/aspace-quickstart.XXXXXX")
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$scratch/target}
logs=$scratch/logs
qs=$scratch/repo/quickstart
mkdir -p "$logs" "$scratch/home"
pids=()
seed=

# ---------------------------------------------------------------------------------- plumbing

stop_all() {
    local pid round alive
    for pid in ${pids[@]+"${pids[@]}"}; do kill -TERM "$pid" 2>/dev/null || true; done
    for round in 1 2 3 4 5 6 7 8 9 10; do
        alive=0
        for pid in ${pids[@]+"${pids[@]}"}; do kill -0 "$pid" 2>/dev/null && alive=1; done
        [ "$alive" = 0 ] && break
        sleep 0.5
    done
    for pid in ${pids[@]+"${pids[@]}"}; do kill -KILL "$pid" 2>/dev/null || true; done
    pids=()
}

finish() {
    local code=$?
    stop_all
    if [ "${KEEP:-0}" = 1 ]; then
        echo "verify.sh: kept $scratch"
    else
        rm -rf "$scratch"
    fi
    exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    local log
    printf 'FAIL %s\n' "$*"
    for log in "$logs"/*.log; do
        [ -s "$log" ] || continue
        echo "--- ${log##*/}"
        tail -n 25 "$log"
    done
    echo "quick start: FAILED"
    exit 1
}

# wait_for <log> <text> <seconds> <pid> <name>: waits until the log holds the text.
wait_for() {
    local log=$1 text=$2 limit=$3 pid=$4 name=$5
    local deadline=$((SECONDS + limit))
    while ! grep -q -F -- "$text" "$log" 2>/dev/null; do
        if ! kill -0 "$pid" 2>/dev/null; then
            grep -q -F -- "$text" "$log" 2>/dev/null && return 0
            fail "$name ended before it printed \"$text\""
        fi
        [ "$SECONDS" -lt "$deadline" ] || fail "$name printed no \"$text\" within ${limit}s"
        sleep 0.2
    done
}

# wait_exit <pid> <seconds> <name>: waits for the process to end; sets `status` to its status.
wait_exit() {
    local pid=$1 limit=$2 name=$3
    local deadline=$((SECONDS + limit))
    while kill -0 "$pid" 2>/dev/null; do
        [ "$SECONDS" -lt "$deadline" ] || fail "$name did not end within ${limit}s"
        sleep 0.2
    done
    status=0
    wait "$pid" 2>/dev/null || status=$?
}

# The README's shell lines: continuation lines joined, runs of blanks made one space.
readme_lines() {
    awk '
        /^```/ { fence = !fence; line = ""; next }
        fence {
            line = line $0
            if (line ~ /\\$/) { sub(/\\$/, "", line); next }
            gsub(/[[:space:]]+/, " ", line)
            sub(/^ /, "", line)
            sub(/ $/, "", line)
            print line
            line = ""
        }
    ' "$scratch/repo/README.md"
}

# in_readme <command>: fails unless the README gives the command as written.
in_readme() {
    readme_lines | grep -q -F -- "$1" || fail "the README does not give the command: $1"
}

# run <log> <command>: runs a README command in the quick start's directory.
run() {
    local log=$1 command=$2
    in_readme "$command"
    (cd "$qs" && export HOME="$scratch/home" && eval "$command") >"$logs/$log.log" 2>&1
}

# start <name> <command>: starts a README command in the background as process `last`.
start() {
    local name=$1 command=$2
    in_readme "$command"
    (cd "$qs" && export HOME="$scratch/home" && eval "exec env $command") \
        >"$logs/$name.log" 2>&1 &
    last=$!
    pids+=("$last")
}

# serving <name>: waits for a Rust worker's banner; sets `agent` and `pid` from it.
serving() {
    local name=$1 process=$2 banner
    wait_for "$logs/$name.log" "serving as " 120 "$process" "$name"
    banner=$(grep -m 1 '^serving as ' "$logs/$name.log")
    agent=$(printf '%s\n' "$banner" | sed -E 's/^serving as ([^ ]+) \(pid ([0-9]+)\)$/\1/')
    pid=$(printf '%s\n' "$banner" | sed -E 's/^serving as ([^ ]+) \(pid ([0-9]+)\)$/\2/')
    [ "$process" = "$pid" ] || pids+=("$pid")
}

# shipped_by <log>: the `by` of the shipment a Rust desk printed.
shipped_by() {
    sed -n -E 's/^Shipment \{ order_id: "[^"]*", item: "[^"]*", by: "([^"]*)" \}$/\1/p' "$1"
}

# --------------------------------------------------------------------- 0. the README agrees

say "copying the repository to $scratch"
if command -v rsync >/dev/null 2>&1; then
    rsync -a --exclude target --exclude .git --exclude /quickstart/keys "$repo/" "$scratch/repo/"
else
    mkdir -p "$scratch/repo"
    (cd "$repo" && tar -cf - --exclude target --exclude .git --exclude ./quickstart/keys .) |
        (cd "$scratch/repo" && tar -xf -)
fi

# body <file>: the file without its licence header (the comment lines from the copyright line to
# "limitations under the License.", and the blank line after them).
body() {
    awk '
        !done && /Copyright 2026 Bad Monkey, Inc\./ { inside = 1 }
        inside { if (/limitations under the License\./) { inside = 0; done = 1; gap = 1 }; next }
        gap && /^[[:space:]]*$/ { gap = 0; next }
        { gap = 0; print }
    ' "$1"
}

# snippet <file>: the fenced block after the README's <!-- quickstart/<file> --> marker.
snippet() {
    awk -v mark="<!-- quickstart/$1 -->" '
        $0 == mark { found = 1; next }
        found == 1 && /^```/ { found = 2; next }
        found == 2 && /^```[[:space:]]*$/ { exit }
        found == 2 { print }
    ' "$scratch/repo/README.md"
}

marked=$(sed -n -E 's/^<!-- quickstart\/([^ ]+) -->$/\1/p' "$scratch/repo/README.md")
[ -n "$marked" ] || fail "the README marks no quick start snippet"
for file in $marked; do
    [ -f "$qs/$file" ] || fail "the README shows quickstart/$file, which does not exist"
    if ! diff <(body "$qs/$file") <(snippet "$file") >"$logs/snippet.log"; then
        fail "the README's quickstart/$file differs from the file (< file, > README)"
    fi
done
ok "the README's snippets equal the files: $(echo $marked)"
for command in "$WORKER" "$DESK" "$SLOW_WORKER" "$INSTALL" "$SCRIPT_WORKER" "$CARDS" \
    "$WRITE" "$READ" "$CALL" "$SCRIPT_DESK" './seed.sh'; do
    in_readme "$command"
done
ok "the README gives every command this script runs"

# ------------------------------------------------------------------- 1. install, build, seed

say "$INSTALL (into the scratch directory), then cargo build"
in_readme "$INSTALL"
(cd "$qs" && eval "$INSTALL --root '$scratch/tools' -q") >"$logs/install.log" 2>&1 ||
    fail "cargo install exited with $?"
export PATH="$scratch/tools/bin:$PATH"
(cd "$qs" && cargo build -q) >"$logs/build.log" 2>&1 || fail "cargo build exited with $?"
ok "aspace $(aspace --version | sed 's/^aspace //') installed, the Fulfiller built"

if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    fail "port $port is in use: stop what listens there, or set PORT"
fi
if [ "$port" != 7700 ]; then
    sed -i.orig "s/127\.0\.0\.1:7700/127.0.0.1:$port/" "$qs/fleet.yaml"
fi

say "./seed.sh (aspace seed)"
(cd "$qs" && export HOME="$scratch/home" && exec ./seed.sh "$port") </dev/null >"$logs/seed.log" 2>&1 &
seed=$!
pids+=("$seed")
wait_for "$logs/seed.log" '"event":"listening"' 300 "$seed" seed
grep -q -F "\"listen\":[\"tcp://127.0.0.1:$port\"]" "$logs/seed.log" ||
    fail "the seed does not listen on tcp://127.0.0.1:$port"
ok "aspace seed listens on 127.0.0.1:$port"

# ----------------------------------------------------------- 2. two workers and the desk

say "two workers ($WORKER, twice), then the desk ($DESK)"
start worker-1 "$WORKER"
serving worker-1 "$last"
agent1=$agent pid1=$pid
start worker-2 "$WORKER"
serving worker-2 "$last"
agent2=$agent pid2=$pid
[ "$agent1" != "$agent2" ] || fail "both workers serve as $agent1"
ok "worker 1 serves as $agent1"
ok "worker 2 serves as $agent2"

run desk-1 "$DESK" || fail "the desk exited with $?"
by=$(shipped_by "$logs/desk-1.log")
grep -q -E '^Shipment \{ order_id: "o-[0-9]+", item: "kite", by: ' "$logs/desk-1.log" ||
    fail "the desk printed no kite shipment"
[ "$by" = "$agent1" ] || [ "$by" = "$agent2" ] || fail "the kite was shipped by $by, not a worker"
ok "the desk printed: $(grep '^Shipment' "$logs/desk-1.log")"

say "stopping both workers (SIGTERM, as Ctrl-C)"
kill -TERM "$pid1" "$pid2"
wait_exit "$pid1" 45 worker-1
[ "$status" = 0 ] || fail "worker 1 exited with $status"
wait_exit "$pid2" 45 worker-2
[ "$status" = 0 ] || fail "worker 2 exited with $status"
ok "both workers stopped with status 0"

# ----------------------------------------------------------------------------- 3. kill one

say "kill one: two slow workers ($SLOW_WORKER), the desk, and kill -9 on the one shipping"
start worker-3 "$SLOW_WORKER"
serving worker-3 "$last"
agent3=$agent pid3=$pid
start worker-4 "$SLOW_WORKER"
serving worker-4 "$last"
agent4=$agent pid4=$pid
start desk-2 "$DESK"
desk=$last
wait_for "$logs/desk-2.log" "ordered o-" 60 "$desk" desk
order=$(sed -n -E 's/^ordered (o-[0-9]+)$/\1/p' "$logs/desk-2.log")
deadline=$((SECONDS + 60))
victim=
while [ -z "$victim" ]; do
    if grep -q -F "shipping $order (attempt 1)" "$logs/worker-3.log"; then
        victim=3
    elif grep -q -F "shipping $order (attempt 1)" "$logs/worker-4.log"; then
        victim=4
    fi
    [ -n "$victim" ] || [ "$SECONDS" -lt "$deadline" ] || fail "no worker took $order"
    [ -n "$victim" ] || sleep 0.2
done
if [ "$victim" = 3 ]; then
    killed=$agent3 killed_pid=$pid3 survivor=$agent4 survivor_log=worker-4 survivor_pid=$pid4
else
    killed=$agent4 killed_pid=$pid4 survivor=$agent3 survivor_log=worker-3 survivor_pid=$pid3
fi
# kill -9, then reap it quietly (bash would report the job "Killed").
{ kill -KILL "$killed_pid" && wait "$killed_pid"; } 2>/dev/null || true
ok "worker $victim took $order, and was killed with kill -9"
wait_exit "$desk" 120 desk
[ "$status" = 0 ] || fail "the desk exited with $status"
by=$(shipped_by "$logs/desk-2.log")
[ "$by" = "$survivor" ] || fail "the order was shipped by '$by', expected the survivor $survivor"
grep -q -F "shipping $order (attempt 2)" "$logs/$survivor_log.log" ||
    fail "the survivor did not take $order as attempt 2"
ok "the survivor shipped $order on attempt 2: $(grep '^Shipment' "$logs/desk-2.log")"
kill -TERM "$survivor_pid"
wait_exit "$survivor_pid" 45 survivor
[ "$status" = 0 ] || fail "the survivor exited with $status"
ok "the survivor stopped with status 0 (killed: $killed)"

# ------------------------------------------------------------------------ 4. no Rust code

say "no Rust code: aspace work runs fulfil.sh"
start script "$SCRIPT_WORKER"
script=$last
wait_for "$logs/script.log" "working as" 120 "$script" "aspace work"
ok "$(grep -m 1 -o 'working as [^ ]*' "$logs/script.log")"

run cards "$CARDS" || fail "aspace cards exited with $?"
grep -q -E '^ship +shop\.Order#v1 -> shop\.Shipment#v1 in orders' "$logs/cards.log" ||
    fail "aspace cards lists no ship offering"
ok "aspace cards: $(grep -m 1 -E '^ship ' "$logs/cards.log" | sed -E 's/ +/ /g')"

run write "$WRITE" || fail "aspace write exited with $?"
grep -q -F '"schema":"shop.Order#v1"' "$logs/write.log" || fail "aspace write printed no id"
run read "$READ" || fail "aspace read exited with $?"
grep -q -F '"entry":{"orderId":"o-2","item":"ball","by":"fulfil.sh"}' "$logs/read.log" ||
    fail "aspace read printed no shipment of o-2 by fulfil.sh"
ok "aspace write, then aspace read: $(grep -m 1 -o '"entry":{[^}]*}' "$logs/read.log")"

run call "$CALL" || fail "aspace call exited with $?"
grep -q -F '"offering":"ship"' "$logs/call.log" || fail "aspace call reached no ship offering"
grep -q -F '"entry":{"orderId":"o-3","item":"yo-yo","by":"fulfil.sh"}' "$logs/call.log" ||
    fail "aspace call printed no shipment of o-3 by fulfil.sh"
ok "aspace call: $(grep -m 1 -o '"entry":{[^}]*}' "$logs/call.log")"

run desk-3 "$SCRIPT_DESK" || fail "the desk exited with $?"
[ "$(shipped_by "$logs/desk-3.log")" = fulfil.sh ] || fail "the Rust desk's top was not shipped by fulfil.sh"
ok "the Rust desk, served by the script: $(grep '^Shipment' "$logs/desk-3.log")"
grep -c -F 'aspace: completed ' "$logs/script.log" | grep -q -x 3 ||
    fail "aspace work did not complete exactly three orders"

say "stopping aspace work and the seed (SIGTERM, as Ctrl-C)"
kill -TERM "$script"
wait_exit "$script" 45 "aspace work"
[ "$status" = 0 ] || fail "aspace work exited with $status"
kill -TERM "$seed"
wait_exit "$seed" 30 seed
[ "$status" = 0 ] || fail "the seed exited with $status"
grep -q -x -F 'aspace: stopped' "$logs/seed.log" || fail "the seed did not say it stopped"
pids=()
ok "aspace work and the seed stopped with status 0"

echo "quick start: ok"
