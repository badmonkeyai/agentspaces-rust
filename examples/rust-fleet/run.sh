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

# Example 32: Rust members on example 02's Java research fleet.
#
#   ./run.sh          over tcp
#   ./run.sh --tls    over tls: every Java node requires attestation in channel mode ATTESTED,
#                     and the Rust members dial a tls:// seed, so their channels are attested
#
# The fleet is example 02's group (founding text research-fleet-demo-v1, space tasks):
#   seed           a long-lived Java node with discovery: the workspace's interop seed
#                  (interop/java-seed) founding example 02's group. It keeps the fleet's cards
#                  and its space. Every other member joins through it.
#   rust-worker    the Rust worker, this example's binary.
#   script-worker  `aspace work`, running research.sh once per task.
#   coordinator    example 02's ResearchFleet, run from the installed example-02-research-fleet
#                  0.6.0 jar. It publishes TASKS ResearchTasks (6 by default), prints the
#                  Findings and a tally, and leaves.
#   aspace cards   lists the fleet's offerings.
#   aspace call    writes a ResearchTask for the topic "rust" through the fleet catalogue and
#                  prints the Finding that answers it.
# Then the script stops the workers and the seed, prints what each process said, and checks the
# run. It exits 0 only when:
#   - the coordinator recorded findings from rust-worker and from script-worker;
#   - the call printed a Finding for "rust";
#   - both workers stopped cleanly;
#   - over tls, every link the seed held was tls and attested.
#
# Why a seed beside example 02's coordinator: the coordinator runs no discovery, so it keeps no
# cards. It relays each card, when published, to the members linked at that moment. It also
# leaves once it has tallied. The Rust members link only to their seed. With the coordinator as
# their seed, a caller that joined after the workers would wait for a card refresh (every 5
# minutes), and the workers would stop with no seed to confirm their last results to. A Spring
# Boot or Micronaut host makes the same kind of seed: their starters run discovery.
#
# The coordinator starts once both workers serve and waits for one member, the seed. Over tls, a
# node that requires attestation drops frames that reach it through a relay, so the coordinator
# does not see members that link only to the seed. It still gets their findings: the seed
# forwards them as gossip on its own attested link.
#
# Environment (all optional):
#   ASPACE_BIN, RUST_WORKER_BIN   prebuilt binaries. Without them, the script runs
#                                 `cargo build -p aspace -p rust-fleet` (CARGO_BUILD_JOBS, default 4).
#   JAVA                          the java binary (default $JAVA_HOME/bin/java, else java)
#   TASKS                         how many tasks the coordinator publishes (default 6)
#   TMPDIR                        where the run directory (keystores, logs) is made. The
#                                 directory is removed at the end.
set -euo pipefail

readonly GROUP=research-fleet-demo-v1
readonly RESEARCH_FLEET=ai.badmonkey.agentspaces.examples.fleet.ResearchFleet
readonly SEED_MAIN=ai.badmonkey.agentspaces.interop.Seed
readonly TASK='ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1'
readonly FINDING='ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1'
readonly CALL_INPUT='{"topic":"rust","priority":1}'

scheme=tcp
for arg in "$@"; do
    case $arg in
    --tls) scheme=tls ;;
    -h | --help)
        sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "run.sh: unknown argument $arg (try --help)" >&2
        exit 2
        ;;
    esac
done

here=$(cd "$(dirname "$0")" && pwd)
workspace=$(cd "$here/../.." && pwd)
seed_dir=$workspace/interop/java-seed
tasks=${TASKS:-6}

say() { printf '==> %s\n' "$*"; }

# ---------------------------------------------------------------------------- what runs

if [ -n "${ASPACE_BIN:-}" ] && [ -n "${RUST_WORKER_BIN:-}" ]; then
    aspace=$ASPACE_BIN
    rust_worker=$RUST_WORKER_BIN
else
    say "building aspace and rust-worker"
    (cd "$workspace" && CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4} cargo build -q -p aspace -p rust-fleet)
    target=${CARGO_TARGET_DIR:-$workspace/target}
    aspace=${ASPACE_BIN:-$target/debug/aspace}
    rust_worker=${RUST_WORKER_BIN:-$target/debug/rust-worker}
fi
for binary in "$aspace" "$rust_worker"; do
    if [ ! -x "$binary" ]; then
        echo "run.sh: $binary is not an executable" >&2
        exit 1
    fi
done

if [ -n "${JAVA:-}" ]; then
    java=$JAVA
elif [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    java=$JAVA_HOME/bin/java
else
    java=java
fi
if ! "$java" -version >/dev/null 2>&1; then
    echo "run.sh: $java does not run; install a JDK 21 or later, or set JAVA" >&2
    exit 1
fi

# mvn_offline <dir> <what> <args...>: runs Maven offline in dir, or explains and exits.
mvn_offline() {
    local dir=$1 what=$2
    shift 2
    if ! (cd "$dir" && mvn -q -o "$@"); then
        echo "run.sh: cannot $what offline in $dir; the AgentSpaces 0.6.0 artifacts (example" \
            "02's included) must be installed in ~/.m2" >&2
        exit 1
    fi
}

# Example 02's classpath, which java/pom.xml resolves from the local Maven repository.
fleet_classpath_file=$here/java/target/classpath.txt
if [ ! -s "$fleet_classpath_file" ] || [ "$here/java/pom.xml" -nt "$fleet_classpath_file" ]; then
    say "resolving example 02's classpath"
    mvn_offline "$here/java" "resolve example 02's classpath" dependency:build-classpath \
        -Dmdep.outputFile=target/classpath.txt
fi
fleet_classpath=$(cat "$fleet_classpath_file")

# The seed, compiled when it is not (or when its source is newer than its class).
seed_class=$seed_dir/target/classes/ai/badmonkey/agentspaces/interop/Seed.class
seed_source=$seed_dir/src/main/java/ai/badmonkey/agentspaces/interop/Seed.java
if [ ! -f "$seed_class" ] || [ "$seed_source" -nt "$seed_class" ]; then
    say "compiling the seed (interop/java-seed)"
    mvn_offline "$seed_dir" "compile the seed" compile
fi
if [ ! -s "$seed_dir/target/classpath.txt" ] || [ "$seed_dir/pom.xml" -nt "$seed_dir/target/classpath.txt" ]; then
    mvn_offline "$seed_dir" "resolve the seed's classpath" dependency:build-classpath \
        -Dmdep.outputFile=target/classpath.txt
fi
seed_classpath=$seed_dir/target/classes:$(cat "$seed_dir/target/classpath.txt")

# ---------------------------------------------------------------------------- the run

run_dir=$(mktemp -d "${TMPDIR:-/tmp}/rust-fleet.XXXXXX")
logs=$run_dir/logs
mkdir -p "$logs" "$run_dir/home"
pids=()
seed_open=0

stop_all() {
    local pid round alive
    if [ "$seed_open" = 1 ]; then
        exec 3>&-
        seed_open=0
    fi
    for pid in ${pids[@]+"${pids[@]}"}; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    for round in 1 2 3 4 5 6 7 8 9 10; do
        alive=0
        for pid in ${pids[@]+"${pids[@]}"}; do
            if kill -0 "$pid" 2>/dev/null; then alive=1; fi
        done
        [ "$alive" = 0 ] && break
        sleep 0.5
    done
    for pid in ${pids[@]+"${pids[@]}"}; do
        kill -KILL "$pid" 2>/dev/null || true
    done
    pids=()
}
cleanup() {
    stop_all
    rm -rf "$run_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Two free ports: the seed's and the coordinator's.
if command -v python3 >/dev/null 2>&1; then
    ports=$(python3 -I -c '
import socket
a, b = socket.socket(), socket.socket()
a.bind(("127.0.0.1", 0))
b.bind(("127.0.0.1", 0))
print(a.getsockname()[1], b.getsockname()[1])')
    read -r seed_port coordinator_port <<<"$ports"
else
    seed_port=$((20000 + RANDOM % 20000))
    coordinator_port=$((seed_port + 1 + RANDOM % 1000))
fi

# Prints one process's output, each line prefixed with its name.
show() {
    local name=$1 file=$2
    if [ -s "$file" ]; then
        sed "s/^/[$name] /" "$file"
    fi
}

show_all() {
    show seed "$logs/seed.log"
    show rust-worker "$logs/rust-worker.log"
    show script-worker "$logs/script-worker.log"
    show coordinator "$logs/coordinator.log"
    show cards "$logs/cards.txt"
    show cards "$logs/cards.log"
    show call "$logs/call.json"
    show call "$logs/call.log"
}

fail() {
    printf 'run.sh: %s\n' "$*" >&2
    show_all
    echo "example 32: FAILED ($scheme): $*"
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

# wait_exit <pid> <seconds> <name>: waits for the process to end and sets `status` to its exit
# status.
wait_exit() {
    local pid=$1 limit=$2 name=$3
    local deadline=$((SECONDS + limit))
    while kill -0 "$pid" 2>/dev/null; do
        [ "$SECONDS" -lt "$deadline" ] || fail "$name did not end within ${limit}s"
        sleep 0.2
    done
    status=0
    wait "$pid" || status=$?
}

# seed_says <command> <answer text>: sends the seed a command and waits for its answer.
seed_says() {
    printf '%s\n' "$1" >&3 || fail "the seed no longer reads its commands"
    wait_for "$logs/seed.log" "$2" 30 "$seed" seed
}

# A fleet member's environment: nothing configured but example 02's group through the seed, and
# a HOME of its own, so no fleet file of the user's applies. Each member adds a keystore of its
# own: one keystore is one PeerID.
member=(env -u ASPACE_CONFIG -u ASPACE_JOIN -u ASPACE_PROFILE -u ASPACE_SOCKET -u XDG_CONFIG_HOME
    HOME="$run_dir/home" ASPACE_SEEDS="$scheme://127.0.0.1:$seed_port" ASPACE_GROUP="$GROUP"
    ASPACE_SPACES=tasks)
tls_flags=()
[ "$scheme" = tls ] && tls_flags=(--tls)

say "example 32 over $scheme: example 02's group through a seed on 127.0.0.1:$seed_port"
seed_flags=(--founding "$GROUP" --space tasks)
[ "$scheme" = tls ] && seed_flags+=(--tls --require-attestation --channel-auth ATTESTED)
# The seed reads its commands from a named pipe this script holds open on descriptor 3 (opened
# read-write, so the open never blocks); closing it, here or when the script dies, ends the
# seed. No other process holds the pipe (3>&-).
mkfifo "$run_dir/seed.in"
exec 3<>"$run_dir/seed.in"
seed_open=1
"$java" -cp "$seed_classpath" "$SEED_MAIN" "$seed_port" "${seed_flags[@]}" \
    <"$run_dir/seed.in" >"$logs/seed.log" 2>&1 3>&- &
seed=$!
pids+=("$seed")
wait_for "$logs/seed.log" '"event":"listening"' 90 "$seed" seed

say "the Rust worker: rust-worker"
"${member[@]}" ASPACE_KEYSTORE="$run_dir/k-rust" "$rust_worker" >"$logs/rust-worker.log" 2>&1 3>&- &
worker=$!
pids+=("$worker")
wait_for "$logs/rust-worker.log" "serving as" 60 "$worker" rust-worker

say "the script worker: aspace work --space tasks --take '$TASK' --produces '$FINDING' --action research --name script-worker -- ./research.sh"
"${member[@]}" ASPACE_KEYSTORE="$run_dir/k-script" "$aspace" work --space tasks --take "$TASK" \
    --produces "$FINDING" --action research --name script-worker \
    --description "Researches a topic with a shell script (example 32)" \
    -- "$here/research.sh" >"$logs/script-worker.log" 2>&1 3>&- &
script=$!
pids+=("$script")
wait_for "$logs/script-worker.log" "working as" 60 "$script" script-worker

say "example 02's coordinator: ResearchFleet coordinator $coordinator_port $seed_port $tasks 1${tls_flags[*]+ ${tls_flags[*]}}"
"$java" -cp "$fleet_classpath" "$RESEARCH_FLEET" coordinator "$coordinator_port" "$seed_port" \
    "$tasks" 1 ${tls_flags[@]+"${tls_flags[@]}"} >"$logs/coordinator.log" 2>&1 3>&- &
coordinator=$!
pids+=("$coordinator")
wait_for "$logs/coordinator.log" "tally:" 180 "$coordinator" coordinator
wait_exit "$coordinator" 30 coordinator
say "the coordinator tallied its findings and left"

say "aspace cards"
cards_status=0
"${member[@]}" ASPACE_KEYSTORE="$run_dir/k-cards" "$aspace" cards \
    >"$logs/cards.txt" 2>"$logs/cards.log" 3>&- || cards_status=$?

say "aspace call '$TASK' --json '$CALL_INPUT' --timeout 30s"
call_status=0
"${member[@]}" ASPACE_KEYSTORE="$run_dir/k-call" "$aspace" call "$TASK" --json "$CALL_INPUT" \
    --timeout 30s >"$logs/call.json" 2>"$logs/call.log" 3>&- || call_status=$?

seed_says links '"links":'
seed_says frames '"signed":'

say "stopping the workers (SIGTERM), then the seed"
kill -TERM "$worker" "$script" 2>/dev/null || true
wait_exit "$worker" 45 rust-worker
worker_status=$status
wait_exit "$script" 45 script-worker
script_status=$status
seed_says quit '"bye":true'
exec 3>&-
seed_open=0
wait_exit "$seed" 30 seed
pids=()

show_all

# ---------------------------------------------------------------------------- the checks

by_rust=$(grep -c -E '^finding: .* by rust-worker$' "$logs/coordinator.log" || true)
by_script=$(grep -c -E '^finding: .* by script-worker$' "$logs/coordinator.log" || true)
say "the coordinator recorded $by_rust findings by rust-worker and $by_script by script-worker"
[ "$by_rust" -gt 0 ] || fail "the coordinator recorded no finding by rust-worker"
[ "$by_script" -gt 0 ] || fail "the coordinator recorded no finding by script-worker"

[ "$cards_status" = 0 ] || fail "aspace cards exited with $cards_status"
replicas=$(sed -n -E 's/^research .*, ([0-9]+) replicas\)$/\1/p' "$logs/cards.txt" | head -n 1 || true)
say "aspace cards listed research with ${replicas:-1} replica(s)"

[ "$call_status" = 0 ] || fail "aspace call exited with $call_status"
grep -q -F "\"schema\":\"$FINDING\"" "$logs/call.json" || fail "the call printed no Finding"
grep -q -F '"topic":"rust"' "$logs/call.json" || fail "the call's Finding is not for topic rust"
answered_by=$(sed -n -E 's/.*"worker":"([^"]*)".*/\1/p' "$logs/call.json" | head -n 1 || true)
say "the call printed a Finding for topic rust by $answered_by"

if [ "$scheme" = tls ]; then
    links=$(grep -o '{"peer":[^}]*}' "$logs/seed.log" || true)
    held=$(printf '%s\n' "$links" | grep -c '"peer"' || true)
    attested=$(printf '%s\n' "$links" | grep -c '"scheme":"tls","mode":"attested"' || true)
    bare=$(sed -n -E 's/.*"bare":([0-9]+).*/\1/p' "$logs/seed.log" | tail -n 1 || true)
    say "the seed held $held links, $attested of them tls attested, and sent ${bare:-0} bare frames"
    [ "$held" -ge 2 ] || fail "the seed held $held links, expected the two workers'"
    [ "$attested" = "$held" ] || fail "$((held - attested)) of the seed's links are not tls attested"
    [ "${bare:-0}" -gt 0 ] || fail "the seed sent no bare frame on an attested channel"
fi

say "the workers stopped with exit status $worker_status (rust-worker) and $script_status (script-worker)"
[ "$worker_status" = 0 ] || fail "rust-worker exited with $worker_status"
[ "$script_status" = 0 ] || fail "script-worker exited with $script_status"
echo "example 32: ok ($scheme)"
