# Codex CLI

**What it gives you:**

- Every offering of your fleet becomes a Codex tool. Codex starts `aspace mcp` itself (stdio), or reaches a shared gateway over HTTP with a bearer token taken from your environment.
- Optionally, a `Stop` hook records each finished turn as an entry in the fleet.

Before you start, do the steps in [the recipes README](README.md#before-any-recipe): `aspace` on your `PATH`, the fleet file, and `aspace doctor` all `ok`.

## The configuration (stdio)

In `~/.codex/config.toml`:

```toml
[mcp_servers.fleet]
command = "aspace"
args = ["mcp"]
startup_timeout_sec = 20
```

Or let Codex write it for you:

```sh
codex mcp add fleet -- aspace mcp
```

Why `startup_timeout_sec = 20`: the gateway joins the fleet before it answers Codex, and a join may take up to `--join-timeout` (10 s by default). That equals Codex's default startup timeout, so a slow join would lose the race.

### What Codex passes to `aspace`

Codex starts a stdio server with only a short list of your variables: `HOME`, `PATH`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LC_ALL`, `TERM`, `TMPDIR`, `TZ`, and the names you list in `env_vars`. So:

- the default fleet file `~/.config/agentspaces/fleet.yaml` is found (through `HOME`);
- a fleet file under a custom `XDG_CONFIG_HOME`, or any `ASPACE_*` variable, reaches `aspace` only if you forward it, or if you name the file in `args`.

A fuller block that forwards variables, names the fleet file, runs the gateway on a keystore of its own, and offers only one space:

```toml
[mcp_servers.fleet]
command = "aspace"
args = ["--config", "~/.config/agentspaces/fleet.yaml", "--keystore", "~/.config/agentspaces/codex-keys", "mcp", "--only", "space:tasks"]
env_vars = ["ASPACE_SEEDS", "ASPACE_JOIN"]
startup_timeout_sec = 20
tool_timeout_sec = 120
```

- `aspace` expands the leading `~` of `--config` and `--keystore` itself, because Codex passes `args` without a shell.
- `tool_timeout_sec` (60 s by default) must be longer than the longest call you expect. A call waits 30 s unless its arguments ask for more, up to 10 minutes.

### Several sessions at once: use the HTTP gateway

Each Codex session starts its own `aspace mcp`, and a second gateway on the same keystore sees no tools ([why](../mcp.md#identity-one-gateway-per-keystore)). With several sessions, or with Claude Code open beside Codex, run one gateway over HTTP:

1. Make a token and its record with the snippet in [docs/mcp.md](../mcp.md#static-tokens---tokens).

2. Start the gateway on a keystore of its own:

   ```sh
   aspace --keystore ~/.config/agentspaces/mcp-keys mcp --http --tokens ~/.config/agentspaces/mcp-tokens.yaml
   ```

3. Point Codex at it:

   ```toml
   [mcp_servers.fleet]
   url = "http://127.0.0.1:8740/mcp"
   bearer_token_env_var = "FLEET_MCP_TOKEN"
   ```

4. Start Codex with the token in its environment:

   ```sh
   export FLEET_MCP_TOKEN="$(cat ~/.config/agentspaces/fleet-mcp.token)"
   codex
   ```

Codex sends `Authorization: Bearer <value of FLEET_MCP_TOKEN>` with every request. The token never appears in `config.toml`.

A session Codex leaves idle stays open while Codex holds its event stream, so it still hears when the fleet's tools change. If the gateway restarts, its 404 for the old session carries the JSON-RPC error (`-32001`) that MCP clients re-initialize on ([details](../mcp.md#authentication-over-http)).

## Check that it works

1. Check the fleet side first:

   ```sh
   aspace doctor     # every line "ok"
   aspace cards      # the offerings: these are the tools Codex will list
   ```

2. Then Codex:
   - `codex mcp list` shows the `fleet` server.
   - In a session, `/mcp` shows it with its tools.
   - A server that fails to start shows in the TUI with Codex's startup error. Run `aspace doctor` from the same shell to see why.

3. For the HTTP form, check the token and the gateway with `curl` (see [docs/mcp.md](../mcp.md#check-a-gateway)):
   - 401 without the token;
   - 200 with `-H "Authorization: Bearer $FLEET_MCP_TOKEN"`.

## The hook: record each turn in the fleet

Codex runs lifecycle hooks from `config.toml` (hooks are on by default). Add:

```toml
[[hooks.Stop]]

[[hooks.Stop.hooks]]
type = "command"
command = "jq -c '{session: .session_id, turn: .turn_id, cwd: .cwd}' | aspace -q --join-timeout 5s write 'dev.AgentTurn#v1' --json - --space events --lease 1d > /dev/null && echo '{}' || exit 1"
timeout = 30
```

- `jq` keeps three fields of the hook's input. `last_assistant_message`, the transcript path, and everything else stay on your machine.
- `aspace write` writes them as one `dev.AgentTurn#v1` entry into `events`, kept for a day.
- On success the hook prints `{}`, since Codex expects a JSON object from a `Stop` hook that exits 0.
- `|| exit 1` turns any `aspace` failure into a non-blocking error. In Codex, exit 2 means "block", and `aspace` exits 2 for "refused or not found".
- Pick a space your fleet keeps (one a seed or a long-running host holds). A write into a space no member keeps waits 10 s and exits 3.
- With `aspace daemon` running, the write takes 15-30 ms instead of about 0.3 s. Give `aspace mcp` its own keystore when the daemon runs.

Check the command without Codex, by feeding it a payload of the documented shape:

```sh
printf '{"session_id":"check","turn_id":"t1","cwd":"%s","hook_event_name":"Stop","model":"m","stop_hook_active":false,"last_assistant_message":null}' "$PWD" \
  | sh -c "jq -c '{session: .session_id, turn: .turn_id, cwd: .cwd}' | aspace -q --join-timeout 5s write 'dev.AgentTurn#v1' --json - --space events --lease 1d > /dev/null && echo '{}' || exit 1"
echo "exit $?"                                   # {} then 0
aspace read 'dev.AgentTurn#v1' --space events
```

Codex also has `notify`, which runs a program after each turn and passes a JSON argument. Prefer the hook for the fleet: the `notify` payload carries your messages and the assistant's last reply, and a program given it whole would publish them to every member that can read the space.

## Security notes

- **Tokens:**
  - `bearer_token_env_var` keeps the token in your environment. Never write it in `http_headers` (a static value in `config.toml`).
  - The gateway's token file is owner-only (`chmod 600`, enforced). The `sha256:` record form keeps the secret out of it altogether.
- **Loopback:**
  - The gateway binds `127.0.0.1:8740`, and every request needs a valid token (401 otherwise, 403 for a foreign browser origin).
  - To share a gateway beyond this machine, put a TLS proxy in front and pass `--allowed-host`.
- **`--only`, and Codex's own lists:** `--only` narrows what the gateway offers at all. Codex's `enabled_tools` and `disabled_tools` narrow what Codex shows the model. Use `--only`: tools added later through `list_changed` are still filtered.
- **Scopes:**
  - Over HTTP, map token scopes to offerings with `--policy` ([docs/mcp.md](../mcp.md#who-may-call-what-scopes-and-the-policy-file)). A call out of scope is answered 403 and never reaches the fleet.
  - Over stdio, the caller is you, and the policy's `local` rule applies.
- **Approval:**
  - Every fleet tool is marked `readOnlyHint: false`, `openWorldHint: true`: a call writes into the fleet and starts work elsewhere.
  - Keep Codex's approval prompt for these tools (`default_tools_approval_mode = "prompt"` on the server), or approve named tools only (`[mcp_servers.fleet.tools.research] approval_mode = "approve"`).
- **Project configuration:** a `.codex/config.toml` in a repository you trust can start programs. Read its `mcp_servers` and hooks before you trust the project.
- **Card text** in tool descriptions comes from other fleet members, framed as data. Treat it as untrusted.

## How this recipe was checked (2026-11-08)

Codex itself was not run.

- **Against the documentation:** every block was checked against the Codex documentation:
  - <https://learn.chatgpt.com/docs/extend/mcp?surface=cli> (the `mcp_servers` keys, `codex mcp add`);
  - <https://learn.chatgpt.com/docs/config-file/config-reference> (timeouts, `env_vars`, `enabled_tools`);
  - <https://learn.chatgpt.com/docs/hooks.md> (events, `[[hooks.Stop]]`, exit 2 blocks, `Stop` expects JSON);
  - <https://learn.chatgpt.com/docs/config-file/config-advanced> (`notify`);
  - Codex's source for the environment of a stdio server, `codex-rs/rmcp-client/src/utils.rs` (`DEFAULT_ENV_VARS`).
- **The TOML:** every block parsed as TOML.
- **The server side:** started from each block as Codex starts it, with only Codex's default variables plus `env_vars` and `env`, and no `XDG_CONFIG_HOME`. The client was the MCP TypeScript SDK 1.32.1, against a live fleet (the Java seed of `interop/java-seed` with a Java agent). The fleet's tools were listed and a call was answered by Java. The HTTP block was reached with the `FLEET_MCP_TOKEN` header Codex builds.
- **The hook:** its command ran with a documented `Stop` payload. It printed `{}` and exited 0, and the entry was read back from the fleet.
