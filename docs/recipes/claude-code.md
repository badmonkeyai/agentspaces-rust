# Claude Code

**What it gives you:**

- Every offering of your fleet becomes a Claude Code tool (`mcp__fleet__research`, ...). The list follows the fleet: when a worker joins with a new action, the tool appears without a restart.
- Optionally, a `Stop` hook records each finished turn as an entry in the fleet, so other members can react to it.

Before you start, do the steps in [the recipes README](README.md#before-any-recipe): `aspace` on your `PATH`, the fleet file, and `aspace doctor` all `ok`.

## The configuration (stdio)

For one project, put a `.mcp.json` at the project root:

```json
{
  "mcpServers": {
    "fleet": {
      "command": "aspace",
      "args": ["mcp"]
    }
  }
}
```

For every project, add it to your user configuration instead:

```sh
claude mcp add --scope user fleet -- aspace mcp
```

Everything after `--` is the server's command line. To offer only part of the fleet, add `--only` (see [docs/mcp.md](../mcp.md#offering-less---only)):

```sh
claude mcp add --scope user fleet -- aspace mcp --only 'space:tasks'
```

### Several sessions at once: use the HTTP gateway

Each Claude Code session starts its own `aspace mcp`, and a second gateway on the same keystore sees no tools ([why](../mcp.md#identity-one-gateway-per-keystore)). If you keep several sessions open, or run Codex beside Claude Code, run one gateway over HTTP and point every session at it.

1. Make a token and its record. Use the snippet in [docs/mcp.md](../mcp.md#static-tokens---tokens): it writes `~/.config/agentspaces/fleet-mcp.token` and `~/.config/agentspaces/mcp-tokens.yaml`, both owner-only.

2. Start the gateway on a keystore of its own (under launchd or systemd for daily use):

   ```sh
   aspace --keystore ~/.config/agentspaces/mcp-keys mcp --http --tokens ~/.config/agentspaces/mcp-tokens.yaml
   ```

3. Point Claude Code at it. In `.mcp.json`:

   ```json
   {
     "mcpServers": {
       "fleet": {
         "type": "http",
         "url": "http://127.0.0.1:8740/mcp",
         "headers": {
           "Authorization": "Bearer ${FLEET_MCP_TOKEN}"
         }
       }
     }
   }
   ```

   Or for every project (the single quotes keep `${FLEET_MCP_TOKEN}` unexpanded, so Claude Code reads it at start):

   ```sh
   claude mcp add --transport http --scope user fleet http://127.0.0.1:8740/mcp --header 'Authorization: Bearer ${FLEET_MCP_TOKEN}'
   ```

4. Start Claude Code with the token in its environment:

   ```sh
   export FLEET_MCP_TOKEN="$(cat ~/.config/agentspaces/fleet-mcp.token)"
   claude
   ```

A session Claude Code leaves idle stays open while Claude Code holds its event stream, so it still hears when the fleet's tools change. If the gateway restarts, its 404 for the old session carries the JSON-RPC error (`-32001`) that MCP clients re-initialize on ([details](../mcp.md#authentication-over-http)).

## Check that it works

```sh
claude mcp list
```

```text
Checking MCP server health...

fleet: aspace mcp - ✓ Connected
```

- **The HTTP form** shows `fleet: http://127.0.0.1:8740/mcp (HTTP) - ✓ Connected`.
- **Without `FLEET_MCP_TOKEN`:** it shows `Failed to connect`. Newer versions add `HTTP 401` and a warning `Missing environment variables: FLEET_MCP_TOKEN`. Older versions (2.1.81) may first spend a minute or two trying OAuth.
- **A project's `.mcp.json`:** newer versions show `Pending approval (run claude to approve)` until you approve the server in an interactive `claude` session in that project.
- **Inside a session:** `/mcp` lists the server and its tools. `aspace cards` prints the same offerings under the same names.

If the server fails, run `aspace doctor` from the same directory and shell, and check that `which aspace` finds the binary Claude Code starts.

## The hook: record each turn in the fleet

In `.claude/settings.json` (or `~/.claude/settings.json` for every project):

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "jq -c '{session: .session_id, cwd: .cwd}' | aspace -q --join-timeout 5s write 'dev.AgentTurn#v1' --json - --space events --lease 1d > /dev/null || exit 1",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

The command does four things:

- `jq` picks two fields of the hook's input (the session id and the working directory). The transcript path and anything else stay on your machine.
- `aspace write` writes them as one `dev.AgentTurn#v1` entry into the `events` space, kept for a day. `-q` leaves only errors on standard error.
- Standard output goes to `/dev/null`: the hook prints nothing back to Claude Code.
- `|| exit 1` turns any `aspace` failure into a non-blocking error. `aspace` exits 2 for "refused or not found", and exit 2 from a `Stop` hook would keep Claude from stopping.

Pick a space your fleet keeps: one a seed or a long-running host holds. A write into a space no member keeps waits 10 s for a confirmation that never comes, then exits 3 (the hook then exits 1).

With `aspace daemon` running, each write takes about 15-30 ms. Without it, `aspace` joins the group itself, which takes about 0.3 s per turn. If you run the daemon, give `aspace mcp` its own keystore (see above).

Check the hook's command without Claude Code, by feeding it a payload of the documented shape:

```sh
printf '{"session_id":"check","transcript_path":"/dev/null","cwd":"%s","hook_event_name":"Stop","stop_hook_active":false}' "$PWD" \
  | sh -c "jq -c '{session: .session_id, cwd: .cwd}' | aspace -q --join-timeout 5s write 'dev.AgentTurn#v1' --json - --space events --lease 1d > /dev/null || exit 1"
echo "exit $?"                                   # 0
aspace read 'dev.AgentTurn#v1' --space events    # the entry, with "session":"check"
```

## Security notes

- **Tokens:**
  - Keep the token in the environment (`${FLEET_MCP_TOKEN}`), never in `.mcp.json` or `~/.claude.json`.
  - Use a variable name of your own. Claude Code deliberately reads its own and cloud credential variables (such as `ANTHROPIC_API_KEY`) as empty in a remote server's headers.
  - The token file is owner-only (`chmod 600`, which the gateway enforces). The `sha256:` record form keeps the secret out of the gateway's file altogether.
- **Loopback:**
  - `aspace mcp --http` binds `127.0.0.1:8740`, and every request needs a valid token (401 otherwise).
  - Browser origins other than loopback are refused (403).
  - To share a gateway beyond this machine, put a TLS proxy in front and pass `--allowed-host`.
- **`--only`:** a model sees only what the gateway offers. Narrow it to the spaces or schemas this project needs.
- **Scopes:**
  - Over HTTP, give each token only the scopes it needs, and map scopes to offerings in a policy file (`--policy`; see [docs/mcp.md](../mcp.md#who-may-call-what-scopes-and-the-policy-file)).
  - A call out of scope is answered 403 and never reaches the fleet.
  - Over stdio, the caller is you, and the policy's `local` rule applies.
- **Approval:**
  - A fleet tool writes into the fleet and starts work elsewhere. Every tool is marked `readOnlyHint: false`, `openWorldHint: true`.
  - Keep Claude Code's permission prompt for it, or allow named tools only (`"permissions": {"allow": ["mcp__fleet__research"]}`).
  - Avoid allowing the whole server (`mcp__fleet`): tools that appear later through `list_changed` would be allowed too.
- **Project servers:** a `.mcp.json` from a repository you cloned starts a program on your machine. Claude Code asks before using one; read its `command` and `args` first.
- **Card text** in tool descriptions comes from other fleet members. The gateway strips hidden characters and frames it as data, but treat it as untrusted.

## How this recipe was checked (2026-11-08)

- **Tools:** Claude Code 2.1.81 (`~/.local/bin/claude`) and 2.1.318 ran `claude mcp add`, `claude mcp list`, and `claude mcp get` with a scratch `HOME`. They ran against a live fleet: the scripted Java seed of `interop/java-seed` with a Java agent offering `research`, joined through a dev-local fleet file.
- **What connected:**
  - The stdio `.mcp.json` and `claude mcp add --scope user` connected on both versions.
  - 2.1.318 showed the project server as `Pending approval`.
  - The HTTP form, both through `claude mcp add --header 'Authorization: Bearer ${FLEET_MCP_TOKEN}'` (user scope) and in `.mcp.json`, connected with the variable set. Without it, it failed with 401, and 2.1.318 named the missing variable.
- **The hook:** the `settings.json` block validated against the published `claude-code-settings.json` schema. Its command ran with a documented `Stop` payload and exited 0 with nothing on standard output. The entry was read back from the fleet.
- **Not run:** the hook inside a Claude Code session (that needs a model and an account).
