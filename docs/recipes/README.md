# Recipes: `aspace` in the tools you already use

Each recipe connects one tool to an AgentSpaces fleet through the `aspace` binary. Each one says:

- what the recipe gives you;
- the configuration block;
- how to check that it works;
- the security notes.

| Recipe | What you get | Checked how (2026-11-08) |
|---|---|---|
| [Claude Code](claude-code.md) | The fleet's offerings as tools (`.mcp.json` or `claude mcp add`, stdio or HTTP), and a `Stop` hook that records each turn in the fleet | Run: Claude Code 2.1.81 and 2.1.318 `claude mcp list` against a live fleet; hook command run with a documented hook payload |
| [Codex CLI](codex.md) | The offerings as tools (`[mcp_servers.fleet]`, stdio or HTTP with a bearer token variable), and a `Stop` hook | Not run: checked against the Codex docs; the server side was run with Codex's environment rules |
| [goose](goose.md) | The offerings as a goose extension (stdio or `streamable_http`) | Not run: checked against goose's source; the server side was run |
| [Zed](zed.md) | The offerings as a context server (stdio or remote) | Not run: checked against Zed's settings source; the server side was run |
| [GitHub Actions](github-actions.md) | A workflow that calls a fleet offering, and one that works a fleet queue, with the identity in secrets | Workflow validated against the published workflow schema; every `run:` step run locally against a live fleet |
| [cron](cron.md) | A crontab line with `flock` and a script that sorts `aspace`'s exit codes | Run on macOS with `lockf` (the BSD equivalent) against a live fleet; the `flock` options checked against flock(1) |

The details of the gateway (options, scopes, tokens, `--only`, `list_changed`) are in [`docs/mcp.md`](../mcp.md).

## Before any recipe

1. **Install `aspace`.** Until release binaries ship, build it from a clone of the repository, in its directory:

   ```sh
   cargo install --locked --path crates/aspace
   ```

   It lands in `~/.cargo/bin`. A host that starts `aspace` needs that directory on its `PATH`, or the absolute path in its `command`.

2. **Write the fleet file** at `~/.config/agentspaces/fleet.yaml`:

   ```yaml
   agentspaces:
     keystore: ~/.config/agentspaces/keys
     security:
       profile: mtls
     groups:
       - name: research-fleet
         join: aspace://zQm...
         seeds: [ "tls://fleet.example.com:7500" ]
         spaces: [ { name: tasks } ]
   ```

3. **Check it:**

   ```sh
   aspace doctor          # configuration, keystore, seeds, join: every line "ok"
   aspace cards           # the offerings, which become the tools
   ```

## Rules every recipe follows

- **One running gateway per keystore.** `aspace mcp` is a member with its keystore's PeerID. A second gateway (or daemon, or worker) running from the same keystore sees no tools. If you open several sessions at once, run one HTTP gateway and point them all at it, or give each host its own `--keystore`. See [docs/mcp.md](../mcp.md#identity-one-gateway-per-keystore).
- **Tokens live in the environment or in owner-only files.** They never go in a configuration file you commit, and never on a command line (other users can read `ps`).
- **Loopback unless a proxy terminates TLS.** `aspace mcp --http` binds `127.0.0.1:8740` and serves plain HTTP.
- **Offer the least.** `--only` limits what a model sees, and a policy file limits what each token may call.
- **A hook must never exit 2 by accident.** In Claude Code and Codex, exit 2 means "block", and `aspace` exits 2 for "refused or not found". Every hook here turns any `aspace` failure into exit 1.
