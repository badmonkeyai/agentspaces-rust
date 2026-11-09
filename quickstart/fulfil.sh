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

# The Fulfiller with no Rust code: `aspace work` runs this once per order.
# The order arrives on standard input as one line of JSON: {"orderId":"o-2","item":"ball"}
# The first JSON object printed is the shipment. A non-zero exit hands the order back.
set -eu
order=$(cat)
echo "shipping $order" >&2
# The shipment is the order plus one field: drop the closing brace and add "by".
printf '%s,"by":"fulfil.sh"}\n' "${order%\}}"
