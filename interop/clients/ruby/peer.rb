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

# A dial-only Ruby peer for the cross-language tests, driven by JSON lines.
#
#     ruby -I <agentspaces-rb>/gems/agentspaces/lib peer.rb SEED GROUP KEYSTORE
#
# SEED is tcp://host:port or tls://host:port; GROUP is aspace://<group-id> (joined by id, the
# founding fetched and verified) or a founding text. It uses the Ruby gem's public API only.
# Once joined it prints {"ready": true, "peer": ..., "lang": "ruby"}, then reads one command per
# line on standard input and answers each with one line (see ../README.md): write, count,
# watch, race, quit. Watch events are printed as {"event": KIND, ...} lines whenever they fold.
# Every wait is bounded.

require "json"
require "agentspaces"

LANG = "ruby"
SPACE = "tasks"
OUT = Mutex.new

def say(message)
  OUT.synchronize do
    $stdout.write("#{JSON.generate(message)}\n")
    $stdout.flush
  end
end

def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)

# A string schema reads as Entry::Unknown; its payload is the Hash.
def plain(value) = value.respond_to?(:payload) ? value.payload : value

def join(seed, group, keystore)
  identity = AgentSpaces::Identity.load_or_create(keystore)
  scheme, address = seed.split("://", 2)
  host, _, port = address.rpartition(":")
  if group.start_with?("aspace://")
    id = group.delete_prefix("aspace://")
    peer = AgentSpaces::Peer.new(identity, id)
    peer.join_by_group_id(host, Integer(port), id, timeout: 15.0, scheme: scheme)
  else
    peer = AgentSpaces::Peer.new(identity, AgentSpaces::Derive.group_id_from_founding(group))
    peer.connect(seed)
  end
  deadline = monotonic + 15
  until peer.seed_peer
    raise "the seed never answered this peer" if monotonic > deadline

    sleep 0.05
  end
  peer.pull_space(SPACE)
  peer
end

# Takes tasks until `idle` takes in a row find none (or a minute passes); each one taken is
# answered with a result entry, then completed.
def race(peer, space, command)
  took = []
  idle = 0
  deadline = monotonic + 60
  while idle < Integer(command.fetch("idle", 3)) && monotonic < deadline
    taken = space.take(command["schema"], lease: "1m", timeout: "1s")
    if taken.nil?
      idle += 1
      next
    end
    idle = 0
    value = plain(taken.value) || {}
    peer.write_entry(SPACE, command["result"],
                     { "task" => value["task"], "taskId" => taken.entry_id, "by" => LANG }, agent_name: LANG)
    taken.complete
    took << { "id" => taken.entry_id, "task" => value["task"] }
  end
  took
end

seed, group, keystore = ARGV
begin
  peer = join(seed, group, keystore)
rescue StandardError, Timeout::Error => e
  say({ "error" => "join: #{e.class}: #{e.message}" })
  exit 1
end
space = peer.space(SPACE, agent_name: LANG)
say({ "ready" => true, "peer" => peer.identity.peer_id, "lang" => LANG })
watches = []
$stdin.each_line do |line|
  next if line.strip.empty?

  command = JSON.parse(line)
  op = command["op"]
  begin
    case op
    when "write"
      id = peer.write_entry(SPACE, command["schema"], command["entry"], agent_name: LANG)
      say({ "op" => op, "id" => id })
    when "count"
      peer.pull_space(SPACE)
      sleep 0.3
      found = space.entries(command["schema"], limit: 1000)
      say({ "op" => op, "n" => found.size,
            "entries" => found.map { |item| { "id" => item.entry_id, "entry" => plain(item.value) } } })
    when "watch"
      schema = command["schema"]
      watches << space.watch(schema) do |event|
        say({ "event" => event.kind, "schema" => schema, "id" => event.item.entry_id,
              "entry" => plain(event.value), "watcher" => LANG })
      end
      say({ "op" => op, "ok" => true })
    when "race"
      say({ "op" => op, "took" => race(peer, space, command) })
    when "quit"
      break
    else
      say({ "op" => op, "error" => "unknown op" })
    end
  rescue StandardError => e
    say({ "op" => op, "error" => "#{e.class}: #{e.message}" })
  end
end
watches.each(&:close)
peer.close
say({ "op" => "quit", "bye" => true })
