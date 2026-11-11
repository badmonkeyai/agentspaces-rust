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

# The remote action of the two-peer example: `aspace work` runs this once per task.
# The task arrives on standard input as one line of JSON: {"text":"hello, fleet"}
# The first JSON object printed is the result. It keeps the task's fields (so `aspace call`
# matches it to its task) and adds "shout" and "by". A non-zero exit hands the task back.
set -eu
task=$(cat)
text=$(printf '%s\n' "$task" | sed -n -E 's/.*"text":"([^"]*)".*/\1/p')
[ -n "$text" ] || { echo "handler.sh: no text in $task" >&2; exit 1; }
shout=$(printf '%s' "$text" | tr '[:lower:]' '[:upper:]')
echo "shouting $text" >&2
printf '%s,"shout":"%s","by":"handler.sh"}\n' "${task%\}}" "$shout"
