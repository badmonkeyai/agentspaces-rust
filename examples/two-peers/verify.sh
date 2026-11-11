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

# Runs two-peers.sh and exits non-zero on any mismatch with what its README says:
#
#   - the seed listens and prints its join URI, and an open membership;
#   - peer 2's note is written, and read back, with the same id;
#   - the worker serves "shout", a third peer sees the offering and its call comes back
#     answered by handler.sh;
#   - a late visitor reads peer 2's note after peer 2 left, and its status lists the seed;
#   - the worker and the seed stop with status 0, the seed having admitted every peer, and no
#     process two-peers.sh started is left running.
#
#   ./verify.sh
#
# Needs only `aspace` on PATH (or ASPACE=/path/to/aspace). PORT is passed through (PORT=0
# lets the system choose the seed's port). The transcript is kept as $LOG when set.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
log=${LOG:-$(mktemp "${TMPDIR:-/tmp}/two-peers-verify.XXXXXX")}

fail() {
    printf 'FAIL %s\n' "$*"
    echo "--- the transcript"
    cat "$log"
    echo "two peers: FAILED"
    [ -n "${LOG:-}" ] || rm -f "$log"
    exit 1
}
ok() { printf 'ok   %s\n' "$*"; }

status=0
"$here/two-peers.sh" >"$log" 2>&1 || status=$?
[ "$status" = 0 ] || fail "two-peers.sh exited with $status"
grep -q -x 'two peers: done' "$log" || fail "two-peers.sh did not finish"
ok "two-peers.sh exited with 0"

# has <text>: the transcript holds the text.
has() { grep -q -F -- "$1" "$log"; }

listening=$(grep -m 1 -F '"event":"listening"' "$log") || fail "the seed printed no listening line"
seed_peer=$(printf '%s\n' "$listening" | sed -n -E 's/.*"peer":"([^"]+)".*/\1/p')
case $listening in
*'"join":"aspace://'*'"membership":"OPEN"'*) ;;
*) fail "the listening line names no join URI or no open membership: $listening" ;;
esac
[ -n "$seed_peer" ] || fail "the listening line names no peer"
ok "the seed listens as $seed_peer"

written=$(grep -m 1 -F '"schema":"demo.Note#v1","space":"notes"}' "$log") || fail "peer 2's write printed no id"
id=$(printf '%s\n' "$written" | sed -n -E 's/^\{"id":"([^"]+)".*/\1/p')
[ -n "$id" ] || fail "peer 2's write printed no id: $written"
note="{\"id\":\"$id\",\"schema\":\"demo.Note#v1\",\"space\":\"notes\",\"entry\":{\"text\":\"hello from peer 2\"}"
[ "$(grep -c -F -- "$note" "$log")" = 2 ] || fail "the note $id was not read back twice (by peer 2 and the late visitor)"
ok "peer 2 wrote and read the note $id"

has "working as " || fail "the worker did not start"
grep -q -E '^shout  demo\.Shout#v1 -> demo\.Shouted#v1 in desk' "$log" ||
    fail "aspace cards listed no shout offering"
has '"offering":"shout"' || fail "aspace call reached no shout offering"
has '"entry":{"text":"hello, fleet","shout":"HELLO, FLEET","by":"handler.sh"}' ||
    fail "aspace call printed no answer by handler.sh"
ok "the call to shout came back: HELLO, FLEET, by handler.sh"

late=$(sed -n '/^==> a late visitor/,$p' "$log")
printf '%s\n' "$late" | grep -q -F -- "$note" || fail "the late visitor did not read the note"
printf '%s\n' "$late" | grep -q -E "^  $seed_peer\$" || fail "the late visitor's status does not list the seed"
ok "the late visitor read the note after peer 2 left, and lists the seed among the members"

has 'the worker stopped with status 0' || fail "the worker did not stop with status 0"
has 'the seed stopped with status 0' || fail "the seed did not stop with status 0"
admitted=$(grep -c -E '^aspace: admitted z' "$log" || true)
[ "$admitted" -ge 4 ] || fail "the seed said it admitted $admitted peers, expected peer 2, the worker, the caller, and the late visitor"
has 'aspace: stopped' || fail "the seed did not say it stopped"
for pid in $(sed -n -E 's/^\(the (seed|worker) runs as pid ([0-9]+)\)$/\2/p' "$log"); do
    if kill -0 "$pid" 2>/dev/null; then
        fail "process $pid that two-peers.sh started is still running"
    fi
done
ok "the worker and the seed stopped with status 0 (the seed admitted $admitted peers); nothing is left running"

[ -n "${LOG:-}" ] || rm -f "$log"
echo "two peers: ok"
