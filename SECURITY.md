# Security Policy

AgentSpaces for Rust is a wire-compatible peer of the AgentSpaces fleet: it
holds its own Ed25519 identity, verifies every frame, record, claim, card,
and revocation before it acts on one, and signs everything it writes. It
inherits the security model of the AgentSpaces core (signed, self-certifying
peers and agents; the threat model in the AgentSpaces specification, SPEC
§11) and adds rules of its own:

- no wire or configuration string becomes a command, and `aspace work`
  never uses a shell;
- keys and tokens never print;
- the keystore, the daemon socket, and token files are owner-only;
- no `unsafe` code.

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub's security advisories:

> https://github.com/badmonkeyai/agentspaces-rust/security/advisories/new

A vulnerability in the AgentSpaces protocol or the core libraries belongs in
the core repository's advisories instead:
https://github.com/badmonkeyai/agentspaces/security/advisories/new

Do not open public issues for suspected vulnerabilities, and do not include
exploit details in public discussions until a fix is released.

We will acknowledge your report within five business days, keep you informed
of progress, credit you in the advisory unless you prefer otherwise, and
coordinate the disclosure timeline with you. There is currently no bug bounty
program.

Questions can be sent to `oss [at] badmonkey.ai`

## Scope

In scope: anything that lets an attacker violate a guarantee the fleet
claims through this code. For example:

- **The wire.** A frame, record, state transition, claim, card, or
  revocation that the Rust peer accepts where the Java peer refuses it (the
  hostile inputs of the golden vectors are the baseline), or a CBOR document
  that makes the decoder panic, allocate without bound, or run far longer
  than its size warrants.
- **Attestation and sessions.** A bare frame accepted from anyone but the
  peer its `tls` channel attests, a channel certificate accepted without
  proof of its key, or a session key another party can derive.
- **`aspace work`.** Entry content that reaches a shell or `argv`, or any
  environment variable the program receives beyond `PATH`, `HOME`, `LANG`,
  the three `ASPACE_*` task variables, and those `--env` names.
- **The MCP gateway** (`aspace mcp`, `agentspaces-mcp`). An HTTP request
  served without a valid token, a call outside the caller's scopes, a
  browser Origin or Host header that passes the check without being
  allowed, a token compared in variable time or written to a log or output,
  a JWT accepted with the wrong issuer, audience, key, or expiry, or card
  text that takes another tool's name or gets control or invisible
  characters past the filter.
- **The daemon.** Another local user who can connect to `aspace daemon`,
  send it a command, or put a socket of their own in its place.
- **The keystore.** A private key written readable by others, a torn or
  half-written key pair accepted, or two processes that mint two identities
  for one keystore.
- **Secrets in output.** A private key, a token, or another secret in a log
  line, an error message, `Debug` output, or `aspace doctor` output.

Out of scope:

- `aspace mcp --allow-unauthenticated`, which serves every caller
  anonymously by design, for use only behind a proxy that authenticates
  every request;
- the `dev-local` profile on a shared network (it signs every frame and
  encrypts nothing, `aspace doctor` says so, and it is the only profile that
  accepts a plaintext seed on a host that is not loopback);
- denial of service by a member you admitted.
