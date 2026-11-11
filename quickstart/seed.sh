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

# The quick start's seed: `aspace seed` on 127.0.0.1:7700, serving the group of fleet.yaml
# ("shop-v1") and keeping its space "orders". Every member of the quick start joins through it.
#
#   ./seed.sh [PORT]
#
# It runs the `aspace` on your PATH, or else builds this repository's (the first run compiles
# it). Its identity is kept in keys/seed. It runs in the foreground; Ctrl-C stops it.
#
# A Java node can be the seed instead: `SEED=java ./seed.sh` runs the scripted Java seed in
# ../interop/java-seed, which the repository's cross-language tests use too. It needs a JDK 21 or
# newer and Maven (the first run compiles it and fetches the AgentSpaces 0.5.0 jars from Maven
# Central; MAVEN_ARGS=-o keeps Maven offline after that), and reads commands on standard input,
# one per line: `members`, `cards`, and `quit`.
set -eu

port=${1:-7700}
here=$(cd "$(dirname "$0")" && pwd)

if [ "${SEED:-aspace}" = java ]; then
    seed=$here/../interop/java-seed
    main=ai.badmonkey.agentspaces.interop.Seed
    class=$seed/target/classes/ai/badmonkey/agentspaces/interop/Seed.class
    source=$seed/src/main/java/ai/badmonkey/agentspaces/interop/Seed.java
    if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
        java=$JAVA_HOME/bin/java
    else
        java=java
    fi
    for tool in "$java" mvn; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "seed.sh: $tool not found; install a JDK 21 or newer and Maven" >&2
            exit 1
        fi
    done
    if [ ! -f "$class" ] || [ "$source" -nt "$class" ]; then
        echo "seed.sh: compiling the Java seed (first run only)" >&2
        (cd "$seed" && mvn -q compile)
    fi
    if [ ! -s "$seed/target/classpath.txt" ] || [ "$seed/pom.xml" -nt "$seed/target/classpath.txt" ]; then
        (cd "$seed" && mvn -q dependency:build-classpath -Dmdep.outputFile=target/classpath.txt)
    fi
    echo "seed.sh: the Java seed: group shop-v1, space orders, on 127.0.0.1:$port" >&2
    exec "$java" -cp "$seed/target/classes:$(cat "$seed/target/classpath.txt")" "$main" "$port" \
        --founding shop-v1 --space orders
fi

if command -v aspace >/dev/null 2>&1; then
    aspace=aspace
else
    if ! command -v cargo >/dev/null 2>&1; then
        echo "seed.sh: neither aspace nor cargo found; install Rust through rustup" >&2
        exit 1
    fi
    echo "seed.sh: building aspace from this repository (first run only)" >&2
    (cd "$here/.." && cargo build -q -p aspace)
    aspace=${CARGO_TARGET_DIR:-$here/../target}/debug/aspace
fi

echo "seed.sh: group shop-v1, space orders, on 127.0.0.1:$port" >&2
cd "$here"
exec "$aspace" --config fleet.yaml --keystore keys/seed seed --listen "tcp://127.0.0.1:$port"
