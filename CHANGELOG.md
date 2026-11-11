# Changelog

All notable changes to AgentSpaces for Rust. The crates share one version,
which follows the AgentSpaces core.

## Unreleased: 0.5.0

The first release: a Rust fleet member, the `aspace` command, and an MCP
gateway, on wire version 3 as SPEC v0.1.33 defines it. Not yet on
crates.io: build from a clone (`cargo install --locked --path crates/aspace`
for the command).

The peer joins a fleet through a seed, any AgentSpaces peer that listens, such
as a Java node or another Rust peer: started with listeners, a Rust peer is a
listening member (a hub) that others link to, so Rust peers form a group with
no other implementation in it. `aspace seed` is that member from a shell, and
the quick start needs no JDK.

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
- **Golden vectors.** 203 of the specification's 293 golden vectors are
  tested (Java's space state and claim hashes, which a listening peer's
  digests name, among them), and all 57 hostile inputs among them are
  refused, each for its own rule. The other 90 cover features this release
  does not have: DTLS, WebRTC, the ordered log, persistent data trees, the
  content swarm and its `pdt` level, connectors, and the multicast beacon.
  The delegated join-credential vectors match too.
- **The wire encoding vectors.** All 205 vectors of SPEC annex I (frames,
  space deltas, refs, signed peer advertisements, documents, and beacon
  documents) get the verdict the vector names.
- **Real Jackson.** Long-text vectors recorded from Jackson
  (`interop/jackson-vectors`) are checked in both directions.

The cross-language suites prove the rest against running programs:

- **The Java reference node**, through a scripted Java seed (listening, or
  dialing a Rust listening peer and taking part through it): membership over
  `tcp` and attested `tls`, writes, takes, and completions crossing both
  ways, take races and crashed takes, agent-attested writes, watches, long
  texts, AgentCards admitted by Java's discovery, Java invoking a Rust
  action, and Rust calling a Java agent.
- **Example 02's Java research fleet** (example 32), over `tcp` and `tls`.
- **The Python, TypeScript, and Ruby clients around a Rust seed**: `aspace
  seed` listens, and the three clients (each through its public API,
  `interop/clients`) and a Rust peer join it, over `tcp` (the group joined
  by id, its founding fetched and verified) and over `tls` with required
  attestation. Each writes tasks, all four race to take them (each task
  completed exactly once), every result is read by the peers of the other
  languages, and a watch in each language hears the others' writes and
  completions.
- **Independent MCP clients:** the official TypeScript SDK and the Ruby
  `mcp` gem, over stdio and Streamable HTTP.

### SPEC v0.1.29 to v0.1.33

What a dial-only member of layers 0 to 3 must do, brought up to SPEC v0.1.33:

- **The wire encoding (SPEC §9.1, §9.2).** Every carrier read from the
  network decodes under its record schema of annex I and is refused unless
  re-encoding what was decoded gives back exactly the bytes received: frames
  and every frame body, space deltas and pulled sync deltas, stored and peer
  advertisements, signed revocations, and session hellos. An unknown field, a
  field out of order, a wrong-typed field (no coercion), or a null where the
  record omits the field makes the carrier undecodable; the peer drops it,
  counts it (`deltas_undecodable` for a space delta), and strikes nobody. A
  frame of an unknown kind no longer decodes. A bare frame on an attested
  link writes its key and signature as null, as Java does.
- **The clock (SPEC §7.3, §7.4, §9, §11a.4).** A stamp has one canonical
  text, and every other text makes its carrier undecodable. A counter above
  65,536 is refused at every merge point: such a frame is dropped and
  counted, and such a state or claim is refused after its signatures
  verify, counted once per distinct signed content under a cache of 4,096
  keys. The clock carries into the next millisecond instead of saturating,
  never repeats a stamp, clamps a merged stamp one millisecond inside the
  drift ceiling, and refuses a node it cannot stamp with. The frame filter
  runs in the specification's order with the 5-second skew margin. A state
  or claim stamped past the ceiling waits as deferred, and one stamped an
  hour further out is refused; an agent-signed state's `signedAt` meets the
  same rule, and a certificate bounds a space's records, claims, and
  `signedAt` by its validity window alone. The peer reports the seven stamp
  counters under Java's names, and the far-past contest rule uses Java's
  200 ms settle window.
- **The AppCard revision (SPEC §6.1a, §6.1b, §6.3).** An AppCard's `kind` is
  `peer`, `fed`, `gateway`, or `assembled`, and `host.signOn` is `idp` or
  `none`; `origin` and `formats` follow their grammars; a card above 65,536
  bytes may travel as a stub whose parts sit in a content-swarm document,
  and the stub's reference and placeholders are checked when the card is
  read. The peer advertises `wire.appcard=2`, writes no gated field into its
  own cards, counts a card it publishes inline past the spill threshold, and
  reads a content store's asset card. Its advertisement cache holds 8,192
  advertisements and 32 MiB of encodings and counts what it refuses.
- **The beacon document (SPEC §9.1).** A signed document must arrive as
  exactly its canonical JSON, with its signature and key in padded standard
  base64, and every member must hold Java's type, signed or not. The signed
  bytes escape a character past U+FFFF as Java does.
- **Agent ids (SPEC §9.2 R5).** A local name holds no `:`.
- **Java interop** runs against the AgentSpaces 0.6.0 core.

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
- Seed endpoints, beacon documents, founder-issued and delegated join
  credentials, the session-attestation handshake, and the QUORUM vote
  tally, as pure functions.
- The serving half of anti-entropy (`serving`): the digests and deltas of a
  space (Java's state and claim hashes, checked against the golden
  vectors), the advertisements, the revocations, and the membership view.
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
- **A listening configuration** (`Overrides::listening`): no seed is
  required, and the listeners come from `--listen`, `ASPACE_LISTEN`, or the
  file's `agentspaces.bind` as the Java starter spells it (a bare
  `host:port` listens on `tls` under `mtls` and on `tcp` under
  `dev-local`; default `127.0.0.1:7700`), with what they advertise from
  `--advertise`, `ASPACE_ADVERTISE`, or the file's `advertise`. A plaintext
  listener outside loopback needs `dev-local`, an advertisement must name a
  listener's scheme when there are several, and every refusal names its
  flag, variable, or key. A group's `membership` (`open`, `invite`) is
  read. A dial-only configuration never reads any of these, so a fleet file
  shared with a Java node that listens never makes a visitor bind.
  `Config::peer_config` binds the listeners of a listening configuration.
- **Invite keys in the configuration** (`--invite`, `ASPACE_INVITE`):
  `Config::peer_config` signs the peer's PeerID under the key's delegation
  and presents it as the `aspace:join` resource hint (SPEC §5.1). With no
  group named, the invite names the group (joined by id); an invite of
  another group than the one named is refused; no refusal shows the key's
  secret. A group the peer founded itself is a configuration layer too
  (`Overrides::founded`).
- **Listening** (`PeerConfig::listen_on`, `Fleet::listen`,
  `Peer::listen_addrs`): a peer started with `tcp` or `tls` listeners
  accepts links and serves the members on them as a hub. It admits a
  newcomer from its own signed introduction under the group's policy
  (`OPEN`, or `INVITE` with a founder-issued or delegated credential,
  refused once revoked; SPEC §5.1), answers with its own introduction and
  the live members' advertisements, and admits nobody from a third party's
  copy. Only an admission spends the admission bucket (a stranger's other
  frames count against its own link), nobody is admitted while a join by
  GroupID waits for its founding, a credential is judged only in the wire
  encoding of its record (so its revocation holds), and an evicted member
  loses every link it owns. A member owns at most four links and hears
  each rumor once, and at the link bound a new link takes the place of the
  oldest one nobody introduced itself on. It forwards each rumor once to
  its other links (what waits for the seed's link is bounded by bytes,
  apart from its own held writes) with the hop budget clamped to 6,
  answers DIGESTs with PULL_RESPs in Java's formats for the view, the
  advertisements, the revocations, and the spaces it replicates
  (the configured ones and every space it hears of, bounded in count,
  entries, and bytes), and runs its own anti-entropy rounds with idle
  backoff. It fetches the payload blocks of replicated entries (so a writer
  may leave once the hub holds the block) and serves them, relays
  RELAY_FRAMEs to its members in the one-hop and path forms, relays
  PING_REQs, and supports SPEC §5.6's required attestation. Links,
  admissions, members, rumor memory, per-link backlogs, inbound bytes,
  pulls, and fetches are bounded, and everything dropped is counted
  (`PeerCounters::listen`).
- **Founding**: `group::found` and `group::found_or_load` found a group
  with a signed founding document and keep it beside the keystore, so a
  listening founder restarts with the same GroupID and serves
  `aspace://<group-id>` joins (a group founded from text serves none).
  `group::load_founding`, `founding_policy`, `founding_name`, and
  `MembershipPolicy::parse` read one back.
- **Draining** (`Peer::drain`): a listening peer stops accepting links and
  waits, bounded, until its links have handed what they queued to their
  transports, before it closes.
- **The membership view on a new link**: a member back on a new link (a
  visitor run again, a member that restarted) hears the live members'
  advertisements again, as a newcomer does, paced by its answer bucket.
- **A byte bound per space** (`PeerConfig::space_max_bytes`, 256 MiB by
  default) beside the entry bound.
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
  `watch`, `cards`, `call`, `work`, `seed`, `invite`, `daemon`, `mcp`,
  `doctor`, `completions`, and `man`. Every `--help` carries examples.
- **`aspace seed`** listens and serves a group until SIGINT, SIGTERM, or
  SIGHUP (it stops accepting, gives its links 2 s to send what they queued,
  and closes with exit 0). It serves a group it founds (`--found NAME`, the
  signed founding kept beside the keystore and reused, `--membership open`
  or `invite`), one founded from a text (`--group`), another seed's
  (`--join` with `--seeds`, the seed's own address skipped among them and
  the others redialed for as long as it runs), or the fleet file's. Flags:
  `--listen` (repeatable), `--advertise`, `--replicate` (repeatable),
  `--max-spaces`, and `--require-attestation`. It prints one JSON line,
  `{"event": "listening", "peer", "group", "join", "listen", "advertise",
  "membership"}`, and says on standard error whom it admits.
- **`aspace invite --found NAME`** prints an invite key (`aspace-inv1-...`)
  of an invite group the keystore founded, a delegation the founder signs
  (`--label`, `--not-after`, 7 days by default). Every command takes it with
  `--invite` or `ASPACE_INVITE`; a visitor that joins an invite group by id
  without one is refused (exit 4), naming the flag.
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
- **Two peers in bash** (`examples/two-peers`): `aspace seed --found demo`,
  a writer, an `aspace work -- ./handler.sh` worker, a caller, and a late
  visitor that reads what the writer wrote after it left, with nothing but
  `aspace`. Its `verify.sh` checks the transcript, and
  `cargo test -p aspace --test two_peers` runs it on a plain runner.
- **The quick start without Java**: `quickstart/seed.sh` starts `aspace
  seed` (the Java seed stays one `SEED=java` away), and
  `quickstart/verify.sh` needs Rust alone.
- **Documentation**: the seed guide (`docs/seed.md`), the gateway guide
  (`docs/mcp.md`), and recipes for Codex, goose, Zed, Claude Code, GitHub
  Actions, and cron (`docs/recipes`).
- **Project**: the Apache 2.0 licence, contribution and security policies,
  CI on Linux and macOS, `cargo-deny`, and an OSV scan.

### Not in this release

- Persistent data trees (SPEC annex H and PDT 2), the content swarm and its
  `pdt` level, and so fetching a spilled card's parts document.
- The hashed digest exchange and the lazy-push gossip tree, with its waits
  (SPEC §9.4); a listening peer answers full digests and pushes rumors to
  every link.
- Session attestation on the peer: the handshake exists in
  `agentspaces-wire`, but the peer uses `tcp` with signed frames or attested
  `tls`.
- A full mesh: a listening peer does not dial the members it learns of, so
  members reach one another through their hub; the `ws`, `http`, QUIC,
  DTLS, and WebRTC transports.
- The vote, aggregate, semantic discovery, and connector capabilities; the
  content swarm and artifacts.
- Bindings for C, Swift, Kotlin, and WebAssembly, and framework adapters.
- `aspace` on Windows: the daemon's named pipe compiles but has not run, and
  `work` and the signal handling are Unix-only.
