# Contributing to AgentSpaces for Rust

Thank you for your interest in contributing. AgentSpaces for Rust is an
Apache 2.0 project from Bad Monkey, Inc., and everything in this repository
stays Apache 2.0.

This repository holds the Rust face of AgentSpaces: a fleet member written in
pure Rust, the `aspace` command, and the MCP gateway. The protocol is the
[AgentSpaces specification](https://github.com/badmonkeyai/agentspaces-spec);
the Java reference node, which every peer must agree with, lives in the
[AgentSpaces core repository](https://github.com/badmonkeyai/agentspaces).

## What the repository holds

| Path | What it is |
|---|---|
| `crates/agentspaces-wire` | The protocol core: the CBOR codec, identities, envelopes, records, claims, revocations, and the space fold. No I/O. |
| `crates/agentspaces` | The peer on Tokio over `tcp` and `tls`: `Fleet`, the space verbs, typed entries, workers, remote actions, the catalogue, configuration, and the keystore. |
| `crates/agentspaces-derive` | `#[derive(Entry)]`, re-exported by `agentspaces`. |
| `crates/aspace` | The `aspace` binary: the verbs from a shell, `work`, `daemon`, `mcp`, and `doctor`. |
| `crates/agentspaces-mcp` | `FleetMcpServer`: the fleet's catalogue as MCP tools over stdio and Streamable HTTP. |
| `examples/rust-fleet` | Example 32: Rust and shell-script workers on the Java research fleet of example 02. |
| `interop/` | Test helpers in other languages: a scripted Java seed, the Jackson vector generator, and two MCP clients. |
| `docs/` | The MCP gateway guide and the recipes for Codex, goose, Zed, Claude Code, GitHub Actions, and cron. |

## Before you start

- **Questions and ideas** are welcome as [GitHub issues](https://github.com/badmonkeyai/agentspaces-rust/issues).
- **Security issues** must not be filed as public issues. See
  [SECURITY.md](SECURITY.md) for private reporting.
- **Code of conduct:** by participating you agree to the
  [code of conduct](CODE_OF_CONDUCT.md).
- **Wire changes start in the specification.** A new frame, entry type,
  golden vector, or wire rule is an issue against
  [agentspaces-spec](https://github.com/badmonkeyai/agentspaces-spec) first.
  This repository follows the specification; it never leads it.

## The rules a change must keep

Every pull request is reviewed against these rules. A change that breaks one
needs a very good reason, written in the pull request.

- **The golden vectors decide conformance.**
  `crates/agentspaces-wire/tests/golden.json` is a vendored copy of the
  specification's `golden.json`. Every byte the peer signs or hashes must
  match it, and a coverage test fails when a vector is neither tested nor
  listed as skipped with a reason. Refresh the copy from the specification
  repository, never by hand: copy `golden.json` from a checkout of
  `agentspaces-spec` (its `sync-golden.sh` does this for every client
  repository checked out beside it, this one included).
- **Generated vectors stay generated.** The `jackson-*-vectors.json` files
  in `crates/agentspaces-wire/tests` are written by a tool too:
  `interop/jackson-vectors` records them from real Jackson. Regenerate
  them; never edit them.
- **The wire crate stays sans-IO.** `agentspaces-wire` opens no socket or
  file, starts no thread, reads no clock, and depends on no async runtime.
  Callers pass bytes and time in and take frames and judgments out. I/O
  belongs in `agentspaces`.
- **No `unsafe`.** The workspace lints forbid `unsafe_code` in every crate,
  and every crate except the proc-macro crate repeats it as
  `#![forbid(unsafe_code)]`. The only place
  `unsafe` may appear is a future FFI crate, each block with a `SAFETY`
  comment.
- **No panics on untrusted input.** Frames, payloads, cards, fleet files,
  token files, JSON from scripts, and MCP arguments come from someone else.
  Return an error: no `unwrap`, `expect`, unchecked indexing, or unchecked
  arithmetic on them, and check every length against the bytes that remain
  before you allocate. Add a hostile-input test with the fix.
- **Jackson-identical CBOR.** The encoder writes exactly what the Java
  codec's Jackson writes, and the decoder accepts exactly the encoding Java
  accepts: one encoding per value. When you need new expected bytes, record
  them from real Jackson (`interop/jackson-vectors`), not from a reading of
  its source.
- **Anything from the wire is data, never a command.** Entry fields, card
  text, tool names, and schema names never reach a shell, `argv`, a format
  string, or a file path. `aspace work` starts its program without a shell,
  passes the entry on standard input, and clears the environment down to
  `PATH`, `HOME`, `LANG`, the three `ASPACE_*` task variables, and what
  `--env` names. Keep it that way: never add `sh -c`.
- **Keys and tokens never print.** Key types zeroize on drop and redact
  themselves under `Debug`. Errors and `aspace doctor` name files, modes,
  and lengths, never secret bytes.
- **The `aspace` contract is stable.** Results go to standard output as
  JSON (`status`, `cards`, and `doctor` print text without `--json`),
  diagnostics to standard error, and the exit codes keep their
  meaning: 0 success, 1 error, 2 refused or not found, 3 timeout, 4
  authentication or authorization. Every command's `--help` carries
  examples.

## Building and testing

You need `rustup`. The toolchain is pinned in `rust-toolchain.toml` (Rust
1.99 with `clippy` and `rustfmt`), and `rustup` installs it on the first
`cargo` command. These are the commands CI runs:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo deny --locked check      # needs cargo-deny: cargo install --locked cargo-deny
```

The core suites run on loopback and in-memory networks and need no network
access. Give every test that starts a peer, a listener, or a process a
timeout, and stop all of them when the test ends, also when it fails.

### The cross-language suites

The tests that put the Rust peer, `aspace`, and the MCP gateway beside the
Java reference node need more than Rust:

- A JDK 21 or newer (`java` on the `PATH`, or `JAVA_HOME`) and Maven.
- The seed's AgentSpaces 0.6.0 artifacts in your local Maven repository
  (`~/.m2`), since the tests run Maven offline (`mvn -o`). 0.6.0 is the
  upcoming release: until it is on Maven Central, install it from a clone of
  the [core repository](https://github.com/badmonkeyai/agentspaces) with
  `mvn install -DskipTests`. Once it is published, one online build of the
  seed fetches them:

  ```
  (cd interop/java-seed && mvn -q compile dependency:build-classpath -Dmdep.outputFile=target/classpath.txt)
  ```

- For example 32: the `example-02-research-fleet` 0.6.0 jar, which is not
  on Maven Central. Install it from a clone of the
  [core repository](https://github.com/badmonkeyai/agentspaces) with
  `mvn install -DskipTests`.
- For the MCP client tests: Node with `@modelcontextprotocol/sdk`
  (point `ASPACE_MCP_NODE_SDK` at the package directory) and Ruby with the
  `mcp` gem.
- For the Rust-seed test (`crates/aspace/tests/clients_seed.rs`): the
  Python, TypeScript, and Ruby clients checked out beside this repository,
  a Python holding the Python client's dependency, Node 22 or later, and
  Ruby 3.3 or later, as [interop/clients](interop/clients/README.md) says.

When one of these is missing, each such test prints why and passes. That is
what happens in CI. Run them before you open a pull request that touches the
wire, the peer, `aspace`, or the gateway, with skips turned into failures:

```
ASPACE_INTEROP_REQUIRED=1 cargo test --workspace --locked
```

The first run builds the Java seed in `interop/java-seed`. `JAVA_HOME`
chooses the `java` binary. To run example 32 by hand, see
[its README](examples/rust-fleet/README.md).

Three Java checks are opt-in. Run them with the cross-language suites:

```
cargo test --workspace -- --ignored java
```

## Pull requests

Open an issue first for anything beyond a fix. Keep the change small, add the
test that fails without it, and sign off your commits (DCO): `git commit -s`.

CI runs on every push to `main` and every pull request against `main`:

- **build:** `cargo fmt --check`, `cargo clippy -D warnings`, the test
  suite, and `cargo doc -D warnings`, on Ubuntu and macOS.
- **cargo-deny:** advisories, licences, duplicate versions, and sources, as
  `deny.toml` sets them.
- **osv-scan:** known vulnerabilities in every dependency manifest, also
  weekly.

CI has no Java artifacts, so the cross-language suites skip there. Say in
your pull request whether you ran them with `ASPACE_INTEROP_REQUIRED=1`.
