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

# The quick start's seed: a Java AgentSpaces node on 127.0.0.1:7700 that founds the group
# "shop-v1" with the space "orders". A Rust member only dials out, so every member of the quick
# start joins through this one.
#
#   ./seed.sh [PORT]
#
# It runs the scripted Java seed in ../interop/java-seed, which the repository's cross-language
# tests use too. Needs a JDK 21 or newer and Maven. The first run compiles it and fetches the
# AgentSpaces 0.5.0 jars from Maven Central; MAVEN_ARGS=-o keeps Maven offline after that.
#
# It runs in the foreground and reads commands on standard input, one per line: `members`,
# `cards`, and `quit`. Ctrl-C stops it too.
set -eu

port=${1:-7700}
here=$(cd "$(dirname "$0")" && pwd)
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
    echo "seed.sh: compiling the seed (first run only)" >&2
    (cd "$seed" && mvn -q compile)
fi
if [ ! -s "$seed/target/classpath.txt" ] || [ "$seed/pom.xml" -nt "$seed/target/classpath.txt" ]; then
    (cd "$seed" && mvn -q dependency:build-classpath -Dmdep.outputFile=target/classpath.txt)
fi

echo "seed.sh: group shop-v1, space orders, on 127.0.0.1:$port" >&2
exec "$java" -cp "$seed/target/classes:$(cat "$seed/target/classpath.txt")" "$main" "$port" \
    --founding shop-v1 --space orders
