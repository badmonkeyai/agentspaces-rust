# Changelog

All notable changes to AgentSpaces for Rust. The crates share one version,
which follows the AgentSpaces core.

## Unreleased: 0.5.0

The first release: a Rust fleet member, the `aspace` command, and an MCP
gateway, on wire version 3 as SPEC v0.1.28 defines it. Not yet on
crates.io: build from a clone (`cargo install --locked --path crates/aspace`
for the command).

The peer is dial-only. It joins a fleet through a seed, any AgentSpaces peer
that listens, such as a Java node.

### Wire rules and interop

The Rust peer agrees with the Java reference node byte for byte:

- **CBOR as Jackson writes it.** Maps are indefinite-length in field order,
  and a map-valued field a signature covers is in canonical key order.
  Arrays and byte strings are definite with minimal heads. Every float is a
  64-bit double. A text longer than 3,996 UTF-16 units is chunked exactly as
  Jackson chunks it. Big integers and decimals use tags 2, 3, and 4 as
  Jackson writes Java's `BigInteger` and `BigDecimal`.
- **One encoding per value.** The decoder reads a network document only in
  that encoding: shortest heads, distinct text keys, no trailing bytes, at
  most 64 levels, and at most the 8 MiB frame cap. It refuses everything
  else without a panic.
- **Golden vectors.** 174 of the specification's 232 golden vectors are
  tested: 135 are reproduced byte for byte, and all 39 hostile inputs are
  refused. The other 58 cover features this release does not have: DTLS,
  WebRTC, the ordered log, persistent trees, the content swarm, connectors,
  the multicast beacon, and a listening peer's digests. The delegated
  join-credential vectors match too.
- **Real Jackson.** Long-text vectors recorded from Jackson
  (`interop/jackson-vectors`) are checked in both directions.

The cross-language suites prove the rest against running programs:

- **The Java reference node**, through a scripted Java seed: membership over
  `tcp` and attested `tls`, writes, takes, and completions crossing both
  ways, take races and crashed takes, agent-attested writes, watches, long
  texts, AgentCards admitted by Java's discovery, Java invoking a Rust
  action, and Rust calling a Java agent.
- **Example 02's Java research fleet** (example 32), over `tcp` and `tls`.
- **Independent MCP clients:** the official TypeScript SDK and the Ruby
  `mcp` gem, over stdio and Streamable HTTP.

### `agentspaces-wire`

The protocol core, with no I/O, no threads, no async runtime, and no clock of
its own. Callers pass bytes and time in and take frames and judgments out.

- The CBOR codec above, plus a lenient decoder for older writers.
- PeerIDs, GroupIDs, and SpaceIDs; Ed25519 peer identities; subordinate
  agent identities and their certificates.
- A `CryptoPort` for every signature, hash, key derivation, and random byte,
  on RustCrypto by default (`ed25519-dalek`, `x25519-dalek`, HKDF, HMAC, and
  SHA-256). A host may install another.
- Founding documents and the receiver's checks, so a peer can join by
  GroupID (`aspace://<group-id>`).
- Hybrid logical clock stamps, envelopes, frames, and a frame filter that
  drops stale, far-ahead, and replayed frames.
- Peer advertisements, AgentCards with declared actions, and AppCards.
- Space records, state transitions, take claims and their lattice, and the
  space fold.
- Revocations of peers, agents, agent keys, and join credentials.
- The filter grammar (`qty>1`, `region in eu,us`) and Java's matchers.
- Seed endpoints, beacon documents, delegated join credentials, the
  session-attestation handshake, and the QUORUM vote tally, as pure
  functions.
- Private keys are wiped on drop and print as `<redacted>`.

### `agentspaces`

The fleet member on Tokio.

- **`Peer`**: joins a group through a seed over `tcp`, or over `tls` 1.3
  with channel certificates (an identity-endorsed key, no CA). It answers
  membership probes, also through relays, re-leases its advertisement, folds
  replicated state, verifies every signature, refuses revoked members, and
  redials a lost seed. Its caches and queues are bounded, and it counts what
  it drops.
- **Payloads over 64 KiB** travel as content-addressed blocks, fetched from
  the writer or another member that holds them.
- **The Space API** (`Fleet`, `Space`): leased `write`, `renew_write`, and
  `cancel`; `read`, `read_all`, and `get`; an exclusive `take` under the
  claim lattice, with `complete` (with or without a result) and `renew`;
  `watch` (written, taken, completed, expired, reappeared); and `notify`.
- **Typed entries**: `#[derive(Entry)]` types are written as Jackson writes
  the equivalent Java record, and read back with `read_typed`, `take_typed`,
  `watch_typed`, and `notify_typed`. A `Registry` keeps entries of unknown
  schemas as values.
- **A JSON bridge** for payloads, with tagged forms (`$int`, `$decimal`)
  where CBOR holds more than JSON.
- **A blocking facade** (`agentspaces::blocking`) for code without an async
  runtime.
- **Workers**: `fleet.agent(name)` binds `take` and `notify` handlers under
  the agent's own identity, so its work reads as `AGENT_ATTESTED`. It
  publishes an AgentCard with its declared actions and refreshes it every 5
  minutes. `ctx.keepalive` renews a take while a long call runs, a failed
  handler lets the take lapse for another worker, and a stop waits out a
  grace period.
- **Remote actions and `FleetCatalog`**: the actions on live, verified,
  unrevoked cards, invoked by writing the input and awaiting the correlated
  result. Replicas fold into one offering, clashing names take a stable
  `_<8 hex>` suffix as every AgentSpaces gateway names them, and no card can
  take another offering's name.
- **Configuration**: the `ASPACE_*` variables over the shared fleet YAML
  (`~/.config/agentspaces/fleet.yaml`) that the Java, Ruby, and Node hosts
  read. A plaintext seed on a host that is not loopback is refused unless the
  profile is `dev-local`.
- **The keystore**: the directory layout Java, Python, and Ruby share, so
  they can run as the same peer. Files are written atomically and
  owner-only, first use is locked so concurrent processes load one identity,
  a half-written pair is refused, and a private key others can read is
  refused unless you allow it.

### `agentspaces-derive`

- `#[derive(Entry)]` with `#[entry(schema = "shop.Order#v1")]` binds a type
  to its wire schema. A missing, repeated, or malformed attribute is a
  compile error that says what to write.

### `aspace`

One binary for scripts, hooks, and shells.

- **Commands**: `id`, `status`, `write`, `read`, `take`, `complete`,
  `watch`, `cards`, `call`, `work`, `daemon`, `mcp`, `doctor`,
  `completions`, and `man`. Every `--help` carries examples.
- **The contract**: results are JSON on standard output (`status`,
  `cards`, and `doctor` print text unless given `--json`), diagnostics go to
  standard error, and the exit codes are 0 success, 1 error, 2 refused or
  not found, 3 timeout, and 4 authentication or authorization.
- **`aspace work -- <program>`** runs the program once per task as an agent
  with a card. There is no shell: the entry arrives on standard input, the
  environment holds only `PATH`, `HOME`, `LANG`, three `ASPACE_*` task
  variables, and what `--env` names, and the program runs in its own process
  group under a deadline. The take is renewed while it runs. Exit 0 with a
  JSON object completes the task; anything else lets it lapse.
- **`aspace daemon`** stays joined and serves the other commands over an
  owner-only Unix socket, checking the connecting user's ID, with the same
  output and exit codes in milliseconds. Commands use it when it is running.
- **`aspace mcp`** serves the fleet's offerings as MCP tools (see
  `agentspaces-mcp`).
- **`aspace doctor`** checks the configuration (secrets redacted), the
  keystore's modes, the daemon socket, the gateway's token and policy files,
  each seed and its TLS attestation, the join, the clock, and a golden
  encoding self-check.

### `agentspaces-mcp`

The fleet catalogue as Model Context Protocol tools, on the official Rust SDK
(`rmcp`).

- **Transports**: stdio, and Streamable HTTP (loopback by default) that
  refuses to start without a token verifier (or an explicit
  `--allow-unauthenticated`, for use behind an authenticating proxy):
  static tokens, compared in constant time, or JWTs checked against an
  issuer, an audience, and a key set.
- **Access**: a policy maps token scopes to offerings (401 without a valid
  token, 403 out of scope), `--only` narrows what is offered, and browser
  Origin and Host headers are checked.
- **Tools**: one per offering, refreshed every 5 s with
  `notifications/tools/list_changed`, with progress notifications and
  cancellation. Card text is stripped of control and invisible characters,
  capped, and framed as data.
- **Schemas**: a Rust host can register entry types (`SchemaRegistry`, with
  the default `schemars` feature), so arguments and results are checked
  against their JSON Schemas.

### Example, documentation, and project

- **Example 32** (`examples/rust-fleet`): a Rust worker and a shell-script
  worker under `aspace work` serve example 02's Java research fleet, and
  `aspace call` invokes them through the catalogue.
- **Documentation**: the gateway guide (`docs/mcp.md`) and recipes for
  Codex, goose, Zed, Claude Code, GitHub Actions, and cron (`docs/recipes`).
- **Project**: the Apache 2.0 licence, contribution and security policies,
  CI on Linux and macOS, `cargo-deny`, and an OSV scan.

### Not in this release

- The clock bounds of SPEC v0.1.30 (the logical-counter limit, the canonical
  stamp grammar, and the far-future rules).
- Session attestation on the peer: the handshake exists in
  `agentspaces-wire`, but the peer uses `tcp` with signed frames or attested
  `tls`.
- Listening, so the peer cannot be a seed; the `ws`, `http`, QUIC, DTLS,
  and WebRTC transports.
- The vote, aggregate, semantic discovery, and connector capabilities; the
  content swarm and artifacts.
- Bindings for C, Swift, Kotlin, and WebAssembly, and framework adapters.
- `aspace` on Windows: the daemon's named pipe compiles but has not run, and
  `work` and the signal handling are Unix-only.
