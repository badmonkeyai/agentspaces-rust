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

# Example 32's script worker.
#
# `aspace work` runs this script once per ResearchTask. The task arrives on standard input as one
# line of JSON, for example {"priority":1,"topic":"rust"}, and ASPACE_ENTRY_ID, ASPACE_SCHEMA,
# and ASPACE_SPACE are set in the environment.
#
# The first JSON object the script prints is its Finding, and `aspace work` completes the task
# with it. Any other outcome (a non-zero exit, no object) lets the task's lease lapse, so another
# worker takes it.
#
# No shell ever runs the entry: it is data on standard input. The topic is copied into the
# Finding still JSON-escaped, so whatever the topic holds, the output stays valid JSON. Plain sh
# and sed only; neither jq nor python is needed.
set -u

task=$(cat)

# The body of the "topic" string, escapes included: a run of characters other than `"` and `\`,
# or escape pairs. The leading T tells an empty topic apart from no topic.
topic=$(printf '%s\n' "$task" |
    sed -n -E 's/.*"topic"[[:space:]]*:[[:space:]]*"(([^"\\]|\\.)*)".*/T\1/p' | head -n 1)
case $topic in
T*) topic=${topic#T} ;;
*)
    echo "no topic in the task: $task" >&2
    exit 1
    ;;
esac

echo "researching $topic" >&2
sleep 0.4
printf '{"topic":"%s","summary":"researched by a shell script: %s","worker":"script-worker"}\n' \
    "$topic" "$topic"
