// Copyright 2026 Bad Monkey, Inc.
// Author: Al Baker
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The command line: global flags (the configuration layer of [`Overrides`]) and the commands,
//! each with examples in its `--help`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use agentspaces::config::Overrides;
use agentspaces::group::MembershipPolicy;
use agentspaces::space::{EventKind, Lease};
use clap::{ArgAction, Args, Parser, Subcommand};

/// What `aspace --help` shows after the commands.
const EXAMPLES: &str = "\
Configuration: --config, then ASPACE_* variables (ASPACE_CONFIG, ASPACE_SEEDS, ASPACE_GROUP,
ASPACE_JOIN, ASPACE_INVITE, ASPACE_KEYSTORE, ASPACE_PROFILE, ASPACE_SOCKET), then the fleet file
(~/.config/agentspaces/fleet.yaml by default); flags override variables, variables the file.
ASPACE_NO_DAEMON=1 is --no-daemon, ASPACE_ALLOW_READABLE_KEY=1 --allow-readable-key, and
ASPACE_MCP_TOKENS and ASPACE_MCP_POLICY name the files of aspace mcp --tokens and --policy.

Results are JSON on standard output (one object, or JSON Lines for streams); diagnostics go to
standard error. Exit codes: 0 success, 1 error, 2 refused or not found, 3 timeout,
4 authentication or authorization.

Examples:
  aspace id
  aspace --profile dev-local seed --found demo      # a group of your own on 127.0.0.1:7700
  aspace --seeds tls://fleet.example.com:7500 --join aspace://zQm... status
  aspace write 'shop.Order#v1' --json '{\"sku\":\"A-1\",\"qty\":2}' --space orders
  aspace read 'shop.Order#v1' --where 'qty>1' --space orders
  aspace work --take 'shop.Order#v1' --space orders --produces 'shop.Shipment#v1' -- ./ship.sh
  aspace daemon &    # later visitors answer through it in milliseconds
  aspace mcp         # the fleet's offerings as MCP tools, for Codex, Claude Code, goose, Zed";

/// `aspace`: a member of an AgentSpaces fleet for scripts, hooks, and shells.
#[derive(Debug, Parser)]
#[command(
    name = "aspace",
    version,
    about = "A member of an AgentSpaces fleet for scripts, hooks, and shells",
    long_about = "aspace joins an AgentSpaces fleet as a visitor, does one thing (write, read, \
                  take, complete, or watch entries of a replicated space), and leaves; `aspace \
                  work` stays and runs a program for each task it takes, `aspace daemon` stays \
                  and serves the visitors, `aspace mcp` stays and serves the fleet's \
                  offerings as MCP tools, and `aspace seed` stays and listens, so other \
                  members link to it and join its group.",
    after_help = EXAMPLES,
    propagate_version = true
)]
pub struct Cli {
    /// The configuration flags every command takes.
    #[command(flatten)]
    pub global: Global,
    /// The command.
    #[command(subcommand)]
    pub command: Command,
}

/// The flags every command takes: the configuration layer over `ASPACE_*` and the fleet file.
#[derive(Debug, Clone, Args)]
#[command(next_help_heading = "Configuration")]
pub struct Global {
    /// The fleet YAML file (over ASPACE_CONFIG and ~/.config/agentspaces/fleet.yaml).
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Comma-separated seeds, scheme://host:port or host:port (over ASPACE_SEEDS).
    #[arg(long, global = true, value_name = "SEEDS")]
    pub seeds: Option<String>,
    /// A group of the fleet file by name, or else a founding text (over ASPACE_GROUP).
    #[arg(long, global = true, value_name = "NAME")]
    pub group: Option<String>,
    /// Join a group by id, `aspace://<group-id>` (over `ASPACE_JOIN`).
    #[arg(
        long,
        global = true,
        value_name = "URI",
        help = "Join a group by id, aspace://<group-id> (over ASPACE_JOIN)"
    )]
    pub join: Option<String>,
    /// An invite key of an INVITE group, aspace-inv1-... as `aspace invite` prints it (over
    /// `ASPACE_INVITE`); with no group named, it names the group.
    #[arg(
        long,
        global = true,
        value_name = "KEY",
        help = "An invite key of an INVITE group, aspace-inv1-... as aspace invite prints it \
                (over ASPACE_INVITE); with no group named, it names the group"
    )]
    pub invite: Option<String>,
    /// The keystore directory (over ASPACE_KEYSTORE and the file's keystore; default
    /// ~/.config/agentspaces/keys).
    #[arg(long, global = true, value_name = "DIR")]
    pub keystore: Option<String>,
    /// The security profile: mtls (the default) or dev-local (over ASPACE_PROFILE).
    #[arg(long, global = true, value_name = "PROFILE")]
    pub profile: Option<String>,
    /// The daemon socket (over `ASPACE_SOCKET`; default: `daemon.sock` in
    /// `$XDG_RUNTIME_DIR/aspace`, else in `${TMPDIR:-/tmp}/aspace-<uid>`).
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "The daemon socket (over ASPACE_SOCKET; default: daemon.sock in \
                $XDG_RUNTIME_DIR/aspace, else in ${TMPDIR:-/tmp}/aspace-<uid>)"
    )]
    pub socket: Option<String>,
    /// Join in this process even when a daemon answers on the socket (or ASPACE_NO_DAEMON=1).
    #[arg(long, global = true)]
    pub no_daemon: bool,
    /// How long joining, linking, and pulling the space may take (default 10s, or the group's
    /// join-timeout-millis).
    #[arg(long, global = true, value_name = "DURATION", value_parser = parse_duration)]
    pub join_timeout: Option<Duration>,
    /// Accept a private key file its group or others may read.
    #[arg(long, global = true)]
    pub allow_readable_key: bool,
    /// More diagnostics on standard error (-v, -vv).
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,
    /// No notes on standard error, only errors.
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

impl Global {
    /// The configuration layer these flags make.
    pub fn overrides(&self) -> Overrides {
        Overrides {
            config: self.config.clone(),
            seeds: self.seeds.clone(),
            group: self.group.clone(),
            join: self.join.clone(),
            keystore: self.keystore.clone(),
            profile: self.profile.clone(),
            socket: self.socket.clone(),
            join_timeout: self.join_timeout,
            invite: self.invite.clone(),
            ..Overrides::default()
        }
    }
}

/// The commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create or show this machine's identity and print its PeerID.
    #[command(after_help = "\
Prints {\"peerId\": ..., \"keystore\": ..., \"created\": true|false}. The keystore is --keystore,
ASPACE_KEYSTORE, the fleet file's keystore, or ~/.config/agentspaces/keys; peer.key and peer.pub
there are shared with the Java, Python, and Ruby peers.

Examples:
  aspace id
  aspace id --keystore ./keys
  aspace id | jq -r .peerId")]
    Id,

    /// Join, report the group, members, link, catalogue, and counters, and leave.
    #[command(after_help = "\
Examples:
  aspace status
  aspace status --json | jq .members
  aspace --config fleet.yaml --group research-fleet status")]
    Status {
        /// Print one JSON object instead of text.
        #[arg(long)]
        json: bool,
    },

    /// Write one entry and print its id.
    #[command(after_help = "\
Prints {\"id\": ..., \"schema\": ..., \"space\": ...}. JSON numbers keep the widths of the
schema's entries the space holds; otherwise an integral number is an integer and any other a
double. --json - reads the object from standard input, --json @file from a file.

Examples:
  aspace write 'shop.Order#v1' --json '{\"sku\":\"A-1\",\"qty\":2}' --space orders
  aspace write 'ops.Alert#v1' --json @alert.json --lease 1h --tag severity=high
  echo '{\"topic\":\"rust\",\"priority\":1}' | aspace write 'research.Task#v1' --json -")]
    Write {
        /// The entry's schema, `<Type>#v<version>`.
        schema: String,
        /// The entry as a JSON object (`-`: standard input, `@file`: a file).
        #[arg(long, value_name = "JSON")]
        json: String,
        /// The space (default: the first space of the configured group).
        #[arg(long)]
        space: Option<String>,
        /// How long the entry lives.
        #[arg(long, default_value = "10m", value_parser = parse_lease)]
        lease: Lease,
        /// A tag, key=value (repeatable).
        #[arg(long = "tag", value_name = "KEY=VALUE", value_parser = parse_tag)]
        tags: Vec<(String, String)>,
    },

    /// Print the available entries of a schema as JSON Lines.
    #[command(after_help = "\
Each line is {\"id\", \"schema\", \"space\", \"entry\", \"tags\", \"issuer\", \"attestation\",
\"expiresAt\"}. Without --timeout, prints what the space holds once joined (exit 2 when nothing
matches); with --timeout, waits that long for a first match (exit 3 when none comes).

Examples:
  aspace read 'shop.Order#v1' --space orders
  aspace read 'shop.Order#v1' --where 'qty>1' --where 'sku=A-1' --limit 5
  aspace read 'ops.Alert#v1' --timeout 30s | jq -c .entry")]
    Read {
        /// The schema to read.
        schema: String,
        /// A clause of the filter grammar, such as 'qty>1' or 'region in eu,us' (repeatable).
        #[arg(long = "where", value_name = "CLAUSE")]
        clauses: Vec<String>,
        /// A tag that must equal a value, key=value (repeatable).
        #[arg(long = "tag", value_name = "KEY=VALUE", value_parser = parse_tag)]
        tags: Vec<(String, String)>,
        /// The most entries to print.
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Wait this long for a first match.
        #[arg(long, value_parser = parse_duration)]
        timeout: Option<Duration>,
        /// The space (default: the first space of the configured group).
        #[arg(long)]
        space: Option<String>,
    },

    /// Take one entry exclusively and print it with its id.
    #[command(after_help = "\
Prints {\"id\", \"schema\", \"space\", \"entry\", \"tags\", \"holder\", \"epoch\", \"expiresAt\"}.
The take is held for --lease; complete it with `aspace complete <id>` from this keystore (any
later invocation), or let it lapse and the entry reappears. Exit 2 when nothing could be taken
at once, 3 when nothing came within --timeout.

Examples:
  aspace take 'shop.Order#v1' --space orders --lease 5m
  id=$(aspace take 'shop.Order#v1' --timeout 30s | jq -r .id)
  aspace take 'shop.Order#v1' --where 'qty>=10' --timeout 1m")]
    Take {
        /// The schema to take.
        schema: String,
        /// A clause of the filter grammar (repeatable).
        #[arg(long = "where", value_name = "CLAUSE")]
        clauses: Vec<String>,
        /// How long the take is held.
        #[arg(long, default_value = "1m", value_parser = parse_lease)]
        lease: Lease,
        /// Wait this long for an entry to take.
        #[arg(long, value_parser = parse_duration)]
        timeout: Option<Duration>,
        /// The space (default: the first space of the configured group).
        #[arg(long)]
        space: Option<String>,
    },

    /// Complete an entry taken earlier with this keystore, with a result or without.
    #[command(after_help = "\
Prints {\"id\", \"space\", \"completed\": true, \"result\": <result id or null>, \"schema\"}.
Exit 2 when the entry is not held by this identity (never taken, lapsed, or completed).

Examples:
  aspace complete 4f6c... --space orders
  aspace complete \"$id\" --json '{\"sku\":\"A-1\",\"tracking\":\"Z9\"}' --produces 'shop.Shipment#v1'")]
    Complete {
        /// The entry id `aspace take` printed.
        id: String,
        /// The result as a JSON object (`-`: standard input, `@file`: a file).
        #[arg(long, value_name = "JSON", requires = "produces")]
        json: Option<String>,
        /// The result's schema.
        #[arg(long, value_name = "SCHEMA", requires = "json")]
        produces: Option<String>,
        /// How long the result lives.
        #[arg(long, default_value = "1h", value_parser = parse_lease)]
        result_lease: Lease,
        /// A tag of the result, key=value (repeatable).
        #[arg(long = "tag", value_name = "KEY=VALUE", value_parser = parse_tag)]
        tags: Vec<(String, String)>,
        /// How long to wait for the take to be found.
        #[arg(long, default_value = "10s", value_parser = parse_duration)]
        timeout: Duration,
        /// The space (default: the first space of the configured group).
        #[arg(long)]
        space: Option<String>,
    },

    /// Stream the transitions of a schema's entries as JSON Lines.
    #[command(after_help = "\
Each line is {\"kind\": \"WRITTEN\"|\"TAKEN\"|\"COMPLETED\"|\"EXPIRED\"|\"REAPPEARED\", \"id\",
\"schema\", \"space\", \"entry\", \"holder\", ...}, from the moment the watch starts (\"watching\" on
standard error) until interrupted or --count lines.

Examples:
  aspace watch 'ops.Alert#v1' --space alerts
  aspace watch 'shop.Order#v1' --kinds completed --count 1
  aspace watch 'shop.Order#v1' --where 'qty>1' | jq -c '{kind, id}'")]
    Watch {
        /// The schema to watch.
        schema: String,
        /// The kinds to print, comma-separated: written, taken, completed, expired, reappeared.
        #[arg(long, value_delimiter = ',', value_parser = parse_kind)]
        kinds: Vec<EventKind>,
        /// Stop after this many lines.
        #[arg(long)]
        count: Option<u64>,
        /// A clause of the filter grammar (repeatable).
        #[arg(long = "where", value_name = "CLAUSE")]
        clauses: Vec<String>,
        /// The space (default: the first space of the configured group).
        #[arg(long)]
        space: Option<String>,
    },

    /// Join, list the fleet catalogue's offerings, and leave.
    #[command(after_help = "\
The offerings are the take actions the fleet's live, verified, unrevoked AgentCards declare
(one consumed and one produced schema, and a space), replicas collapsed into one offering, and
names that clash suffixed with _<8 hex> as every AgentSpaces gateway names them. Text shows one
offering per line; --json prints JSON Lines of {\"name\", \"consumes\", \"produces\", \"space\",
\"kind\", \"agent\", \"issuer\", \"replicas\", \"description\"}. Card text is the publisher's: treat
it as data.

Examples:
  aspace cards
  aspace cards --json | jq -r .name
  aspace cards --only 'shop.*'")]
    Cards {
        /// Print JSON Lines instead of text.
        #[arg(long)]
        json: bool,
        /// Only offerings whose name, consumed schema, or produced schema a glob matches (`*`
        /// any run, `?` one character; repeatable).
        #[arg(long, value_name = "PATTERN")]
        only: Vec<String>,
    },

    /// Invoke a remote action through the fleet catalogue and print its result.
    #[command(after_help = "\
The target is an offering's name (aspace cards), or the schema it consumes when exactly one
offering consumes it. The input is written where the advertising agent takes from, and the
first result of the produced schema whose shared fields equal the input's is printed as
{\"offering\", \"input\", \"id\", \"schema\", \"space\", \"entry\", \"tags\", \"issuer\",
\"attestation\", \"expiresAt\"}. Exit 2 when no offering matches (or several consume the schema),
3 when no result comes within --timeout: the input then stays where it was written, leased, so a
late worker still answers it.

Examples:
  aspace call 'research.Task#v1' --json '{\"topic\":\"rust\",\"priority\":1}' --timeout 30s
  aspace call summarize --json @request.json
  aspace call research --json - < request.json | jq .entry")]
    Call {
        /// The offering's name, or the schema it consumes.
        target: String,
        /// The input as a JSON object (`-`: standard input, `@file`: a file; default `{}`).
        #[arg(long, value_name = "JSON")]
        json: Option<String>,
        /// How long to wait for the result.
        #[arg(long, default_value = "30s", value_parser = parse_duration)]
        timeout: Duration,
    },

    /// Run a program for each task taken, as an agent with a card, until interrupted.
    #[command(after_help = "\
The worker is the agent <peerId>/<--name> and publishes an AgentCard with one take action
(--action, by default the simple name of the --take schema) consuming --take and producing
--produces in --space, so `aspace cards` and `aspace call` find it.

For each task, the program runs without a shell, in a process group of its own, with the entry
as JSON on standard input and ASPACE_ENTRY_ID, ASPACE_SCHEMA, and ASPACE_SPACE set (and PATH,
HOME, LANG, and each --env, nothing else: pass TZ, TMPDIR, USER, ... with --env NAME). The take
lease (2s to 1d) is renewed at half its length while the program runs. On exit 0 the first JSON
object on standard output is the result (completed under --produces; without --produces the
task completes with no result, and the output is discarded); anything else (a non-zero exit, a
signal, --task-timeout, output that is not a JSON object, more than 8 MiB of output under
--produces) kills the program's group and lets the lease lapse, so the task reappears for
another worker. Standard error passes through, each line prefixed with the entry id.
SIGINT, SIGTERM, SIGHUP, or SIGQUIT stops taking and lets running programs finish within
--grace; then each program's group gets SIGTERM and, 2s later, SIGKILL (a second signal does
that at once). A closed terminal stops the worker this way, also under nohup: start a worker
that must outlive its terminal with setsid or under a supervisor. The worker is a member with its keystore's PeerID: run visitors (`aspace call`,
`aspace cards`) and other workers with keystores of their own (--keystore), since a seed takes
every link of one PeerID for one member.

Examples:
  aspace work --take 'shop.Order#v1' --space orders --produces 'shop.Shipment#v1' -- ./ship.sh
  aspace work --take 'research.Task#v1' --space tasks --parallel 4 --task-timeout 2m -- python3 work.py
  aspace work --take 'ops.Alert#v1' --space alerts --env PAGER_TOKEN -- /usr/local/bin/page
  aspace work --take 'shop.ConvertRequest#v1' --produces 'shop.ConvertResult#v1' --space docs \\
              --action convert --name converter --description 'Converts documents' -- ./convert.sh")]
    Work {
        /// The schema of the tasks to take.
        #[arg(long = "take", value_name = "SCHEMA")]
        take: String,
        /// The space to take from (and write results to).
        #[arg(long)]
        space: String,
        /// The schema of the result the program prints.
        #[arg(long, value_name = "SCHEMA")]
        produces: Option<String>,
        /// A clause of the filter grammar the tasks must meet (repeatable).
        #[arg(long = "where", value_name = "CLAUSE")]
        clauses: Vec<String>,
        /// How many programs run at once.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..=256))]
        parallel: u16,
        /// How long one program may run before its group is killed.
        #[arg(long, default_value = "5m", value_parser = parse_positive_duration)]
        task_timeout: Duration,
        /// How long each take is held between renewals (2s to 1d).
        #[arg(long, default_value = "1m", value_parser = parse_work_lease)]
        lease: Lease,
        /// How long running programs may finish after SIGINT, SIGTERM, SIGHUP, or SIGQUIT.
        #[arg(long, default_value = "30s", value_parser = parse_duration)]
        grace: Duration,
        /// How long each result lives.
        #[arg(long, default_value = "1h", value_parser = parse_lease)]
        result_lease: Lease,
        /// The agent's local name: it works as `<peerId>/<NAME>` (default: the action's name).
        #[arg(
            long,
            value_name = "NAME",
            help = "The agent's local name: it works as <peerId>/<NAME> (default: the action's name)"
        )]
        name: Option<String>,
        /// The action's name on the card (default: the simple name of the --take schema).
        #[arg(long, value_name = "NAME")]
        action: Option<String>,
        /// What the agent does, on its card (default: the program's file name and the schema).
        #[arg(long, value_name = "TEXT")]
        description: Option<String>,
        /// Pass a variable to the program: NAME (from this environment) or NAME=VALUE
        /// (repeatable).
        #[arg(long = "env", value_name = "NAME[=VALUE]")]
        env: Vec<String>,
        /// The program and its arguments, after `--`.
        #[arg(last = true, required = true, num_args = 1.., value_name = "PROGRAM")]
        command: Vec<String>,
    },

    /// Stay joined and serve other aspace invocations over a local socket, until interrupted.
    #[command(after_help = "\
The daemon joins the group of its configuration, as a visitor does, and stays. A visitor
command (status, write, read, take, complete, watch, cards, call) whose configuration names the
same group, keystore, and profile then runs on the daemon's peer instead of joining: same
output, same exit codes, in milliseconds. A take through the daemon is held by the daemon's
identity, so `aspace complete` through the daemon completes it. The socket is --socket,
ASPACE_SOCKET, or daemon.sock in $XDG_RUNTIME_DIR/aspace (else ${TMPDIR:-/tmp}/aspace-<uid>):
its directory is 0700, the socket 0600, and only processes of this user are served. Once
serving it prints its hello as one JSON object (socket, pid, peerId, group, ...); a second
daemon on the same socket exits 2. SIGINT, SIGTERM, or SIGHUP stops it and removes the socket.
It runs in the foreground: start it under systemd or launchd, or with setsid. --no-daemon makes
a visitor join itself.

Examples:
  aspace daemon &
  aspace --config fleet.yaml --group research-fleet daemon
  aspace daemon --socket /run/user/1000/aspace-research.sock
  aspace --no-daemon status")]
    Daemon,

    /// Serve the fleet's offerings as MCP tools, over standard input and output or HTTP.
    #[command(after_help = MCP_HELP)]
    Mcp {
        /// Serve Streamable HTTP at this address instead of standard input and output
        /// (`--http` alone: 127.0.0.1:8740).
        #[arg(
            long,
            value_name = "ADDR",
            num_args = 0..=1,
            default_missing_value = "127.0.0.1:8740",
            value_parser = parse_bind
        )]
        http: Option<SocketAddr>,
        /// The bearer token file, YAML or JSON, owner-only (over ASPACE_MCP_TOKENS).
        #[arg(
            long,
            value_name = "FILE",
            requires = "http",
            conflicts_with = "jwt_issuer"
        )]
        tokens: Option<PathBuf>,
        /// Accept JWTs of this issuer (`iss`), with --jwt-audience and --jwks.
        #[arg(long, value_name = "ISSUER", requires_all = ["http", "jwt_audience", "jwks"])]
        jwt_issuer: Option<String>,
        /// The audience (`aud`) a JWT must name: this gateway's URL, usually.
        #[arg(long, value_name = "AUDIENCE", requires = "jwt_issuer")]
        jwt_audience: Option<String>,
        /// The issuer's key set: an https:// URL (http:// to loopback only), or a file.
        #[arg(long, value_name = "URL|FILE", requires = "jwt_issuer")]
        jwks: Option<String>,
        /// Also accept browser requests from this origin, scheme://host[:port|:*]
        /// (repeatable; the loopback origins always are).
        #[arg(
            long = "origin",
            value_name = "ORIGIN",
            requires = "http",
            help = "Also accept browser requests from this origin, scheme://host[:port|:*] \
                    (repeatable; the loopback origins always are)"
        )]
        origins: Vec<String>,
        /// Accept this Host header (repeatable), instead of the loopback names and the bound
        /// address: behind a reverse proxy, or on 0.0.0.0.
        #[arg(long = "allowed-host", value_name = "HOST", requires = "http")]
        allowed_hosts: Vec<String>,
        /// Serve HTTP without a token verifier, every caller anonymous: only behind a proxy
        /// that authenticates every request.
        #[arg(long, requires = "http")]
        allow_unauthenticated: bool,
        /// Only offerings whose name, consumed schema, or produced schema a glob matches, or
        /// whose space `space:<glob>` matches (repeatable).
        #[arg(
            long,
            value_name = "PATTERN",
            help = "Only offerings whose name, consumed schema, or produced schema a glob \
                    matches, or whose space space:<glob> matches (repeatable)"
        )]
        only: Vec<String>,
        /// The policy file: the offerings each token scope, and a caller without a token,
        /// may invoke (over ASPACE_MCP_POLICY).
        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,
        /// How often the catalogue is refreshed, telling clients when the tools change (0:
        /// only at tools/list).
        #[arg(long, default_value = "5s", value_parser = parse_duration)]
        refresh: Duration,
        /// How long a call waits for its result when its arguments name no timeout (at most
        /// 10m, the input's write lease).
        #[arg(long, default_value = "30s", value_parser = parse_call_timeout)]
        call_timeout: Duration,
    },

    /// Check the configuration, the keystore, the seeds, and the join, and report.
    #[command(after_help = "\
Checks: where each setting came from (secrets redacted), the keystore (present, peer.key mode
0600), the daemon socket (its directory owner-only, whether a daemon answers and serves this
configuration), the files of aspace mcp (a token file owner-only and well-formed, a policy file
no one else may write), each seed (resolved, dialed, its TLS attestation), the join (the
founding verified), the clock, and a golden encoding self-check. Exits 1 when a check fails.

Examples:
  aspace doctor
  aspace --config fleet.yaml doctor --json
  aspace doctor --tokens /etc/agentspaces/mcp-tokens.yaml --policy /etc/agentspaces/mcp-policy.yaml")]
    Doctor {
        /// Print one JSON object instead of text.
        #[arg(long)]
        json: bool,
        /// Check this MCP token file (over ASPACE_MCP_TOKENS).
        #[arg(long, value_name = "FILE")]
        tokens: Option<PathBuf>,
        /// Check this MCP policy file (over ASPACE_MCP_POLICY).
        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,
    },

    /// Listen and serve a group as its seed, until interrupted.
    #[command(after_help = SEED_HELP)]
    Seed {
        /// Listen here: tcp://host:port, tls://host:port, or host:port (repeatable; over
        /// ASPACE_LISTEN and the file's bind; default 127.0.0.1:7700, on tcp under dev-local
        /// and tls otherwise).
        #[arg(
            long = "listen",
            value_name = "ADDR",
            help = "Listen here: tcp://host:port, tls://host:port, or host:port (repeatable; over \
                    ASPACE_LISTEN and the file's bind; default 127.0.0.1:7700, on tcp under \
                    dev-local and tls otherwise)"
        )]
        listen: Vec<String>,
        /// The address members dial, when it is not the one bound: host:port, or
        /// scheme://host:port with several listeners (repeatable; over ASPACE_ADVERTISE and the
        /// file's advertise).
        #[arg(
            long = "advertise",
            value_name = "ADDR",
            help = "The address members dial, when it is not the one bound: host:port, or \
                    scheme://host:port with several listeners (repeatable; over \
                    ASPACE_ADVERTISE and the file's advertise)"
        )]
        advertise: Vec<String>,
        /// Found the group NAME: a signed founding made on the first run and kept beside the
        /// keystore (founding-NAME.cbor), so members join it by its aspace:// id.
        #[arg(long, value_name = "NAME")]
        found: Option<String>,
        /// Who may join a group --found founds: open (every verified peer, the default) or
        /// invite (only peers with an invite key from `aspace invite`).
        #[arg(
            long,
            value_name = "POLICY",
            requires = "found",
            value_parser = parse_membership,
            help = "Who may join a group --found founds: open (every verified peer, the \
                    default) or invite (only peers with an invite key from aspace invite)"
        )]
        membership: Option<MembershipPolicy>,
        /// Replicate this space from the start (repeatable; default: the group's spaces,
        /// ASPACE_SPACES or the file's). Every space heard of is replicated too, up to
        /// --max-spaces.
        #[arg(long = "replicate", value_name = "SPACE")]
        replicate: Vec<String>,
        /// The most spaces opened because they were heard of.
        #[arg(long, value_name = "N", default_value_t = 64, value_parser = clap::value_parser!(u16).range(0..=4096))]
        max_spaces: u16,
        /// Admit only members whose link attests them: tls listeners only (SPEC §5.6).
        #[arg(long)]
        require_attestation: bool,
    },

    /// Print an invite key of an INVITE group this keystore founded.
    #[command(after_help = "\
The founder (the keystore `aspace seed --found NAME --membership invite` ran with) signs a
delegation of a fresh invite key to the group, valid for --not-after, and prints it as
{\"invite\": \"aspace-inv1-...\", \"group\", \"join\": \"aspace://...\", \"name\", \"label\",
\"notAfter\"}. Whoever holds the key joins: `aspace --invite KEY --seeds ADDR <command>` (or
ASPACE_INVITE) signs its own PeerID under it and presents that as its join credential. The
delegation only limits first admission: a member admitted in time stays a member. The key
carries a secret: hand it over as you would a password. Exit 2 when the group is not this
keystore's, or is open.

Examples:
  aspace invite --found crew
  aspace invite --found crew --label 'ci runners' --not-after 30d | jq -r .invite
  aspace --invite \"$KEY\" --seeds tcp://127.0.0.1:7700 write 'crew.Note#v1' --json '{}' --space notes")]
    Invite {
        /// The group, as `aspace seed --found NAME` founded it with this keystore.
        #[arg(long, value_name = "NAME")]
        found: String,
        /// The founder's label for the delegation (who it is for).
        #[arg(long, value_name = "TEXT")]
        label: Option<String>,
        /// How long the key admits newcomers (at most 365d).
        #[arg(long, default_value = "7d", value_parser = parse_invite_lifetime, value_name = "DURATION")]
        not_after: Duration,
    },

    /// Print a shell completion script.
    #[command(after_help = "\
Examples:
  aspace completions bash > /etc/bash_completion.d/aspace
  aspace completions zsh > \"${fpath[1]}/_aspace\"
  aspace completions fish > ~/.config/fish/completions/aspace.fish")]
    Completions {
        /// The shell.
        shell: clap_complete::Shell,
    },

    /// Print the manual page (or write one per command to a directory).
    #[command(after_help = "\
Examples:
  aspace man | man -l -
  aspace man --out-dir /usr/local/share/man/man1")]
    Man {
        /// Write `aspace.1` and `aspace-<command>.1` here instead of printing `aspace.1`.
        #[arg(
            long,
            value_name = "DIR",
            help = "Write aspace.1 and aspace-<command>.1 here instead of printing aspace.1"
        )]
        out_dir: Option<PathBuf>,
    },
}

/// What `aspace seed --help` shows after the options.
const SEED_HELP: &str = "\
The seed is a listening member (SPEC §5.1 to §5.4): members dial it, it admits them under the
group's membership, forwards what each one gossips to the others, answers their anti-entropy
pulls, relays the frames they address to one another, and holds the entries (and payload
blocks) of the spaces it replicates, so a writer may leave and a later visitor still reads
what it wrote. It serves one group:

  --found NAME     a group it founds: the signed founding is made on the first run, kept
                   beside the keystore as founding-NAME.cbor, and reused, so the group id
                   stays; members join with --join aspace://<group-id>
  --group TEXT     a group founded from a text (every member passes the same --group)
  --join URI       another seed's group, through --seeds: a second seed of it
  (none)           the fleet file's group, as every command reads it

Once listening it prints one JSON line, {\"event\": \"listening\", \"peer\", \"group\",
\"join\": \"aspace://...\" (null for a group founded from a text), \"listen\": [...],
\"membership\"}, and says on standard error who it admits. The listeners, their
advertisement, and the group's membership and spaces may come from the fleet file
(agentspaces.bind and .advertise, a group's membership and spaces) and from ASPACE_LISTEN and
ASPACE_ADVERTISE; flags override variables, variables the file. A tcp listener outside loopback
needs --profile dev-local. The seed's own address in its seeds is skipped, and the other seeds
are redialed for as long as it runs. SIGINT, SIGTERM, or SIGHUP stops it: it stops accepting,
gives its links 2s to send what they queued, and closes (exit 0; a second signal closes at
once). Give each seed and each member a keystore of its own (--keystore).

Examples:
  aspace --profile dev-local --keystore keys/seed seed --found demo
  aspace --keystore keys/seed seed --found crew --membership invite --listen tls://0.0.0.0:7500 \\
         --advertise seed.example.com:7500
  aspace --profile dev-local --keystore keys/seed seed --group shop-v1 --replicate orders
  aspace --keystore keys/seed2 --seeds tls://seed.example.com:7500 --join aspace://zQm... seed \\
         --listen tls://0.0.0.0:7501 --advertise seed2.example.com:7501";

/// What `aspace mcp --help` shows after the options.
const MCP_HELP: &str = "\
One MCP tool per offering of the fleet catalogue (aspace cards lists the same offerings, under
the same names), refreshed every --refresh: clients that keep a session hear
notifications/tools/list_changed when the list changes. A call writes the tool's input entry
where the advertising agent takes, waits for the correlated result (--call-timeout, or the
call's own \"timeout\"), and answers it as structured content. The arguments are
{\"input\": {<the entry's fields>}, \"timeout\": \"30s\"}. Card text reaches the model as
data: control and invisible characters are stripped and its length capped.

Over standard input and output (the default) standard output carries only the MCP stream and
every diagnostic goes to standard error; the caller is the local user. With --http the gateway
serves Streamable HTTP at /mcp, loopback by default, and refuses to start without a token
verifier (--tokens, or --jwt-issuer, --jwt-audience, and --jwks) unless --allow-unauthenticated:
a request without a valid bearer token is answered 401, a call outside the token's scopes 403
(--policy), and a browser Origin not allowed 403. A token file (chmod 600) is a list of
{token or sha256, principal, scopes}; a policy file maps scopes to offering globs:
  scopes: {\"orders:write\": [\"shop.*\"], reports: [report_*]}
  local: [\"*\"]            # a caller without a token (standard input): everything

aspace mcp is a resident: it joins the group itself (it never goes through aspace daemon) and
stays, a member with its keystore's PeerID. A seed takes every link of one PeerID for one
member, so give it a keystore no running aspace daemon or aspace work uses (--keystore). It
prints {\"mcp\": <url>, ...} on standard output once serving HTTP. SIGINT, SIGTERM, SIGHUP, or
SIGQUIT (or the client closing standard input) stops it with exit 0, a call still waiting on the
fleet first answering that the gateway stopped (its input stays leased for a late worker); a
peer that gives up redialing its seeds stops it with exit 1.

Hosts start the stdio gateway (aspace reads the fleet file and ASPACE_* as always):
  Codex CLI, ~/.codex/config.toml:
    [mcp_servers.fleet]
    command = \"aspace\"
    args = [\"mcp\"]
  Claude Code, .mcp.json:
    {\"mcpServers\": {\"fleet\": {\"command\": \"aspace\", \"args\": [\"mcp\"]}}}
  goose, ~/.config/goose/config.yaml:
    extensions: {fleet: {type: stdio, cmd: aspace, args: [mcp], enabled: true}}
  Zed, settings.json:
    {\"context_servers\": {\"fleet\": {\"command\": \"aspace\", \"args\": [\"mcp\"]}}}

Examples:
  aspace mcp
  aspace mcp --only 'shop.*' --only 'space:orders'
  aspace mcp --http 127.0.0.1:8740 --tokens /etc/agentspaces/mcp-tokens.yaml --only 'shop.*'
  aspace mcp --http --tokens tokens.yaml --policy policy.yaml --origin https://app.example.com
  aspace mcp --http 0.0.0.0:8740 --allowed-host mcp.example.com \\
             --jwt-issuer https://auth.example.com/ --jwt-audience https://mcp.example.com/mcp \\
             --jwks https://auth.example.com/.well-known/jwks.json";

/// An address to serve at: `host:port` with an IP host, `localhost:port`, or a port alone
/// (loopback).
pub fn parse_bind(text: &str) -> Result<SocketAddr, String> {
    let trimmed = text.trim();
    let loopback = |port: &str| {
        port.parse::<u16>()
            .ok()
            .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
    };
    let parsed = if !trimmed.is_empty() && trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        loopback(trimmed)
    } else if let Some(port) = trimmed.strip_prefix("localhost:") {
        loopback(port)
    } else {
        trimmed.parse::<SocketAddr>().ok()
    };
    parsed.ok_or_else(|| {
        format!("{text:?} is not an address to serve at; write 127.0.0.1:8740, [::1]:8740, or 8740")
    })
}

/// A duration: `0`, or the forms of [`Lease::parse`] (`250ms`, `30s`, `10m`, `2h`, `1d`,
/// `PT30S`), or zero in any unit.
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let trimmed = text.trim();
    let digits_zero = trimmed
        .trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == ' ')
        .chars()
        .all(|c| c == '0');
    if !trimmed.is_empty() && trimmed.starts_with('0') && digits_zero {
        let unit = trimmed.trim_start_matches('0').trim();
        if ["", "ms", "s", "m", "h", "d"].contains(&unit) {
            return Ok(Duration::ZERO);
        }
    }
    Lease::parse(trimmed)
        .map(Lease::duration)
        .map_err(|_| format!("{text:?} is not a duration; write 250ms, 30s, 10m, 2h, 1d, or 0"))
}

/// A positive duration ([`parse_duration`] without zero).
pub fn parse_positive_duration(text: &str) -> Result<Duration, String> {
    match parse_duration(text)? {
        duration if duration.is_zero() => Err(format!("{text:?} must be longer than zero")),
        duration => Ok(duration),
    }
}

/// The default wait of an MCP call ([`parse_positive_duration`]): at most 10 minutes, the write
/// lease of the input a call writes, past which no worker can take it.
pub fn parse_call_timeout(text: &str) -> Result<Duration, String> {
    let timeout = parse_positive_duration(text)?;
    if timeout > Lease::DEFAULT_WRITE.duration() {
        return Err(format!(
            "{text:?} is longer than a call's input lives ({}): no worker could take it after",
            Lease::DEFAULT_WRITE
        ));
    }
    Ok(timeout)
}

/// A membership policy: `open` or `invite`.
pub fn parse_membership(text: &str) -> Result<MembershipPolicy, String> {
    MembershipPolicy::parse(text).ok_or_else(|| {
        format!(
            "{text:?} is not a membership; write open (every verified peer joins) or invite \
             (only peers with an invite key)"
        )
    })
}

/// The longest an invite key admits newcomers: a year, the founding's own lifetime.
pub const MAX_INVITE_LIFETIME: Duration = Duration::from_secs(365 * 24 * 3600);

/// How long an invite admits newcomers ([`parse_positive_duration`], at most a year).
pub fn parse_invite_lifetime(text: &str) -> Result<Duration, String> {
    let lifetime = parse_positive_duration(text)?;
    if lifetime > MAX_INVITE_LIFETIME {
        return Err(format!(
            "{text:?} is longer than an invite may last (365d, the founding's lifetime)"
        ));
    }
    Ok(lifetime)
}

/// A lease ([`Lease::parse`]).
pub fn parse_lease(text: &str) -> Result<Lease, String> {
    Lease::parse(text)
        .map_err(|_| format!("{text:?} is not a lease; write 250ms, 30s, 10m, 2h, or 1d"))
}

/// The take lease of `aspace work` ([`parse_lease`]): at least
/// [`MIN_WORK_LEASE`](crate::work::MIN_WORK_LEASE), since a claim is made a settle window and a
/// pull before the program starts, so a shorter hold lapses before its first renewal; at most
/// [`Lease::MAX_TAKE`], since every take refuses a longer one (the worker would advertise work
/// it never does).
pub fn parse_work_lease(text: &str) -> Result<Lease, String> {
    let lease = parse_lease(text)?;
    if lease.duration() < crate::work::MIN_WORK_LEASE {
        return Err(format!(
            "{text:?} is too short for a worker's take: write at least 2s (a claim is made a \
             settle window and a pull before the program starts, so a shorter hold lapses \
             before its first renewal)"
        ));
    }
    if lease > Lease::MAX_TAKE {
        return Err(format!(
            "{text:?} is too long: a take may hold for {} at most",
            Lease::MAX_TAKE
        ));
    }
    Ok(lease)
}

/// `key=value`, both non-empty after trimming the key.
pub fn parse_tag(text: &str) -> Result<(String, String), String> {
    match text.split_once('=') {
        Some((key, value)) if !key.trim().is_empty() => {
            Ok((key.trim().to_owned(), value.to_owned()))
        }
        _ => Err(format!("{text:?} is not a tag; write key=value")),
    }
}

/// An event kind by name, any letter case.
pub fn parse_kind(text: &str) -> Result<EventKind, String> {
    match text.trim().to_ascii_lowercase().as_str() {
        "written" => Ok(EventKind::Written),
        "taken" => Ok(EventKind::Taken),
        "completed" => Ok(EventKind::Completed),
        "expired" => Ok(EventKind::Expired),
        "reappeared" => Ok(EventKind::Reappeared),
        _ => Err(format!(
            "{text:?} is not an event kind; write written, taken, completed, expired, or \
             reappeared"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn durations_tags_and_kinds_parse() {
        assert_eq!(parse_duration("0"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("0s"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("00ms"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("1500ms"), Ok(Duration::from_millis(1500)));
        assert_eq!(parse_duration(" 2m "), Ok(Duration::from_secs(120)));
        assert_eq!(parse_duration("PT1S"), Ok(Duration::from_secs(1)));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("5").is_err());
        assert!(parse_duration("0x").is_err());
        assert!(parse_duration("-1s").is_err());
        assert!(parse_positive_duration("0s").is_err());
        assert_eq!(parse_tag("a=b=c"), Ok(("a".into(), "b=c".into())));
        assert_eq!(parse_tag("k="), Ok(("k".into(), String::new())));
        assert!(parse_tag("=v").is_err());
        assert!(parse_tag("novalue").is_err());
        assert_eq!(parse_kind("Completed"), Ok(EventKind::Completed));
        assert!(parse_kind("done").is_err());
    }

    #[test]
    fn a_workers_lease_is_between_two_seconds_and_a_day() {
        // Refused: shorter than the claim's settle window and pull allow before the first
        // renewal, or longer than any take may hold.
        assert_eq!(
            parse_work_lease("2s").map(Lease::duration),
            Ok(Duration::from_secs(2))
        );
        assert_eq!(parse_work_lease("1d"), Ok(Lease::MAX_TAKE));
        for refused in ["1s", "1500ms", "25h", "2d"] {
            assert!(parse_work_lease(refused).is_err(), "{refused}");
        }
        assert!(parse_work_lease("nope").is_err());
        assert!(
            Cli::try_parse_from([
                "aspace", "work", "--take", "T#v1", "--space", "s", "--lease", "25h", "--", "x"
            ])
            .is_err()
        );
    }

    #[test]
    fn mcp_serves_stdio_by_default_and_http_where_asked() {
        assert_eq!(
            parse_bind("8740"),
            Ok(SocketAddr::from(([127, 0, 0, 1], 8740)))
        );
        assert_eq!(
            parse_bind("localhost:9000"),
            Ok(SocketAddr::from(([127, 0, 0, 1], 9000)))
        );
        assert_eq!(
            parse_bind("[::1]:8740").map(|address| address.ip().is_loopback()),
            Ok(true)
        );
        for refused in ["", "example.com:80", "99999", "127.0.0.1"] {
            assert!(parse_bind(refused).is_err(), "{refused}");
        }
        assert_eq!(parse_call_timeout("10m"), Ok(Duration::from_secs(600)));
        for refused in ["0", "11m", "1h"] {
            assert!(parse_call_timeout(refused).is_err(), "{refused}");
        }
        let http = |args: &[&str]| match Cli::try_parse_from(args).map(|cli| cli.command) {
            Ok(Command::Mcp { http, .. }) => Ok(http),
            Ok(other) => panic!("not mcp: {other:?}"),
            Err(error) => Err(error.kind()),
        };
        assert_eq!(http(&["aspace", "mcp"]), Ok(None), "stdio by default");
        assert_eq!(
            http(&["aspace", "mcp", "--http"]),
            Ok(Some(SocketAddr::from(([127, 0, 0, 1], 8740)))),
            "loopback by default"
        );
        assert_eq!(
            http(&["aspace", "mcp", "--http", "0.0.0.0:9"]),
            Ok(Some(SocketAddr::from(([0, 0, 0, 0], 9))))
        );
        // HTTP-only options need --http; a JWT verifier needs its audience and key set; one
        // verifier at a time.
        for args in [
            &["aspace", "mcp", "--tokens", "t.yaml"][..],
            &["aspace", "mcp", "--allow-unauthenticated"],
            &["aspace", "mcp", "--origin", "https://a.example"],
            &["aspace", "mcp", "--http", "--jwt-issuer", "https://i/"],
            &[
                "aspace",
                "mcp",
                "--http",
                "--tokens",
                "t",
                "--jwt-issuer",
                "i",
                "--jwt-audience",
                "a",
                "--jwks",
                "k",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err(), "{args:?}");
        }
        assert!(
            Cli::try_parse_from([
                "aspace",
                "mcp",
                "--http",
                "--jwt-issuer",
                "https://i/",
                "--jwt-audience",
                "a",
                "--jwks",
                "k.json"
            ])
            .is_ok()
        );
    }

    #[test]
    fn work_takes_the_program_after_the_separator() {
        let cli = Cli::try_parse_from([
            "aspace", "work", "--take", "T#v1", "--space", "tasks", "--", "./run.sh", "--flag",
        ])
        .expect("parses");
        match cli.command {
            Command::Work { command, .. } => assert_eq!(command, ["./run.sh", "--flag"]),
            other => panic!("not work: {other:?}"),
        }
        assert!(
            Cli::try_parse_from(["aspace", "work", "--take", "T#v1", "--space", "s"]).is_err(),
            "a program is required"
        );
    }

    #[test]
    fn every_command_has_examples() {
        let command = Cli::command();
        for sub in command.get_subcommands() {
            let help = sub
                .get_after_help()
                .map(ToString::to_string)
                .unwrap_or_default();
            assert!(
                help.contains("Examples:"),
                "{} has no examples",
                sub.get_name()
            );
        }
    }
}
