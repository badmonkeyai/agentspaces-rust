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

# frozen_string_literal: true

# A scripted MCP client over the Ruby SDK (the `mcp` gem, 1.8 or later: `MCP::Client` with
# `MCP::Client::Stdio`), for the tests of `aspace mcp` (`crates/aspace/tests/mcp_clients.rs`):
# an MCP client that shares no code with rmcp or `aspace`, over standard input and output.
#
#   ruby ruby_client.rb STDERR_FILE COMMAND [ARGS...]
#
# The gem spawns COMMAND (through `/bin/sh -c 'exec ...'`, so the process is the server's and its
# standard error is appended to STDERR_FILE; the gem itself drains and drops it). Operations are
# read from standard input, one JSON object per line, and each is answered with one JSON object
# per line on standard output: `{"ok": true, ...}`, or `{"ok": false, "error": .., "type": ..}`.
#
#   {"op":"connect","mode":"legacy"|"auto"}  initialize + notifications/initialized (legacy), or
#                                            server/discover first (auto) -> serverInfo,
#                                            protocolVersion, capabilities
#   {"op":"tools"}                           tools/list (every page) -> tools
#   {"op":"call","name":..,"arguments":..}   tools/call -> result
#   {"op":"ping"}                            ping
#   {"op":"await","method":..,"timeoutMs":n,"after":k}
#                                            pings every 200 ms (the gem reads the server's stdout
#                                            only while a request waits) until more than k
#                                            notifications of method were read -> count
#   {"op":"frames"}                          every line read from the server's stdout, whether
#                                            each is a JSON-RPC 2.0 message, and the methods of
#                                            the notifications among them
#   {"op":"close"}                           closes the client (the gem's close: stdin closed,
#                                            SIGTERM after 2 s) -> exit, closeMs

require "json"
require "mcp"

# The gem's stdio transport, recording every frame it reads (its read loop skips notifications;
# the record keeps them).
class RecordingStdio < MCP::Client::Stdio
  attr_reader :frames, :wait_thread

  def initialize(**options)
    super
    @frames = []
    @frames_lock = Mutex.new
  end

  def frames_snapshot
    @frames_lock.synchronize { @frames.dup }
  end

  private

  def strip_frame(line)
    stripped = super
    @frames_lock.synchronize { @frames << stripped }
    stripped
  end
end

def notifications_of(frames)
  frames.filter_map do |frame|
    message = JSON.parse(frame)
    message["method"] if message.is_a?(Hash) && message.key?("method") && !message.key?("id")
  rescue JSON::ParserError
    nil
  end
end

stderr_file, command, *args = ARGV
script = 'exec "$0" "$@" 2>>"$ASPACE_TEST_STDERR"'
transport = RecordingStdio.new(
  command: "/bin/sh",
  args: ["-c", script, command, *args],
  env: { "ASPACE_TEST_STDERR" => stderr_file },
)
client = MCP::Client.new(transport: transport)
$stdout.sync = true

def answer(object)
  $stdout.puts(JSON.generate(object))
end

def await_notification(client, transport, op)
  method = op.fetch("method")
  after = op.fetch("after", 0)
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + op.fetch("timeoutMs", 30_000) / 1000.0
  pings = 0
  loop do
    count = notifications_of(transport.frames_snapshot).count(method)
    return { "count" => count, "pings" => pings } if count > after
    if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
      return { "count" => count, "pings" => pings, "timedOut" => true }
    end

    client.ping
    pings += 1
    sleep(0.2)
  end
end

def run(client, transport, op)
  case op.fetch("op")
  when "connect"
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    info = client.connect(
      client_info: { name: "aspace-interop-ruby", version: MCP::VERSION },
      mode: op.fetch("mode", "legacy").to_sym,
    )
    {
      "serverInfo" => info["serverInfo"] || info.dig("_meta", "io.modelcontextprotocol/serverInfo"),
      "protocolVersion" => client.protocol_version,
      "capabilities" => info["capabilities"],
      "pid" => transport.wait_thread&.pid,
      "connectMs" => ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round,
    }
  when "tools"
    {
      "tools" => client.tools.map do |tool|
        {
          "name" => tool.name,
          "description" => tool.description,
          "inputSchema" => tool.input_schema,
          "outputSchema" => tool.output_schema,
        }
      end,
    }
  when "call"
    response = client.call_tool(name: op.fetch("name"), arguments: op.fetch("arguments", {}))
    { "result" => response["result"], "error" => response["error"] }
  when "ping"
    client.ping
    {}
  when "await"
    await_notification(client, transport, op)
  when "frames"
    frames = transport.frames_snapshot
    rpc = frames.map do |frame|
      message = JSON.parse(frame)
      message.is_a?(Hash) && message["jsonrpc"] == "2.0"
    rescue JSON::ParserError
      false
    end
    {
      "count" => frames.size,
      "notJsonRpc" => frames.each_index.reject { |index| rpc[index] }.map { |index| frames[index] },
      "notifications" => notifications_of(frames),
    }
  when "close"
    wait_thread = transport.wait_thread
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    transport.close
    status = wait_thread&.value
    {
      "exit" => status&.exitstatus,
      "signal" => status&.termsig,
      "closeMs" => ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round,
    }
  else
    raise ArgumentError, "unknown op #{op["op"]}"
  end
end

$stdin.each_line do |line|
  next if line.strip.empty?

  begin
    op = JSON.parse(line)
    answer({ "ok" => true }.merge(run(client, transport, op)))
  rescue MCP::Client::ServerError => e
    answer({ "ok" => false, "error" => e.message, "type" => "server", "code" => e.code })
  rescue MCP::Client::RequestHandlerError => e
    answer({ "ok" => false, "error" => e.message, "type" => e.error_type.to_s })
  rescue StandardError => e
    answer({ "ok" => false, "error" => "#{e.class}: #{e.message}", "type" => "exception" })
  end
end
transport.close if transport.connected?
