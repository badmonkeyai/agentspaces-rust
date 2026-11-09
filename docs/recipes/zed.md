# Zed

**What it gives you:** every offering of your fleet as a tool of a Zed context server called `fleet`, in Zed's agent panel. Zed starts `aspace mcp` itself (stdio), or reaches a shared gateway over HTTP. Zed reloads the tool list when the gateway sends `list_changed`, so a worker that joins with a new action shows up without a restart.

Before you start, do the steps in [the recipes README](README.md#before-any-recipe): `aspace` on your `PATH`, the fleet file, and `aspace doctor` all `ok`.

## The configuration (stdio)

In Zed's settings file, `~/.config/zed/settings.json` (open it with `zed: open settings file`), add a `context_servers` key to the top-level object:

```json
{
  "context_servers": {
    "fleet": {
      "command": "aspace",
      "args": ["mcp"]
    }
  }
}
```

- `command` may be an absolute path (`/Users/you/.cargo/bin/aspace`) if Zed doesn't see your shell's `PATH`.
- `env` sets variables for the server, for example `"env": {"ASPACE_PROFILE": "mtls"}`.
- `timeout` is the tool-call timeout in seconds (60 by default). Keep it above the longest call you expect: a call waits 30 s unless its arguments ask for more, up to 10 minutes.
- To offer part of the fleet, or to run the gateway on its own keystore, add flags to `args`. `aspace` expands the leading `~` itself:

  ```json
  "args": ["--keystore", "~/.config/agentspaces/zed-keys", "mcp", "--only", "space:tasks"]
  ```

### Several sessions at once: use the HTTP gateway

Each Zed window that starts the server runs its own `aspace mcp`, and a second gateway on the same keystore sees no tools ([why](../mcp.md#identity-one-gateway-per-keystore)). With other hosts open as well, run one gateway over HTTP:

1. Make a token and its record with the snippet in [docs/mcp.md](../mcp.md#static-tokens---tokens).

2. Start the gateway on a keystore of its own:

   ```sh
   aspace --keystore ~/.config/agentspaces/mcp-keys mcp --http --tokens ~/.config/agentspaces/mcp-tokens.yaml
   ```

3. Point Zed at it:

   ```json
   {
     "context_servers": {
       "fleet": {
         "url": "http://127.0.0.1:8740/mcp",
         "headers": {
           "Authorization": "Bearer PASTE-THE-TOKEN-HERE"
         }
       }
     }
   }
   ```

Zed doesn't expand environment variables in `headers`, so the token sits in `settings.json` in plain text:

- Put this block only in your user settings file, never in a project's `.zed/settings.json`, which a repository may carry.
- Keep the user settings file private: `chmod 600 ~/.config/zed/settings.json`.
- Give the token a narrow scope (see below). Prefer the stdio form when only Zed uses the fleet.

## Check that it works

```sh
aspace doctor     # every line "ok"
aspace cards      # the offerings: these are the tools Zed will list
```

Then in Zed:

- Open **Settings → AI → MCP Servers**, or run `agent: open settings` and pick MCP Servers.
- The dot next to `fleet` turns green, and its tooltip says "Server is active".
- The agent panel lists the server's tools under the names `aspace cards` prints.
- A red dot means the server didn't start. Run `aspace doctor` from a terminal to see why.

## Security notes

- **Tokens:** Zed keeps a remote server's headers as literal text, so the HTTP form puts a secret in `settings.json`. Prefer stdio. Otherwise use a token with one narrow scope, keep the file owner-only, and never put it in project settings. The gateway's own token file is owner-only (`chmod 600`, enforced), and its `sha256:` record form keeps the secret out of that file.
- **Loopback:**
  - The gateway binds `127.0.0.1:8740`, and every request needs a valid token (401 otherwise).
  - It refuses browser origins other than loopback (403).
  - To share a gateway beyond this machine, put a TLS proxy in front and pass `--allowed-host`.
- **`--only`:** narrow what the gateway offers to the spaces or schemas you need. Tools added later through `list_changed` are filtered too.
- **Scopes:**
  - Over HTTP, map token scopes to offerings with `--policy` ([docs/mcp.md](../mcp.md#who-may-call-what-scopes-and-the-policy-file)). A call out of scope is answered 403 and never reaches the fleet.
  - Over stdio, the caller is you, and the policy's `local` rule applies.
- **Approval:**
  - Zed asks before each tool call by default (`confirm`). Its per-tool permission keys have the form `mcp:fleet:<tool>`, for example `mcp:fleet:research`.
  - Every fleet tool writes into the fleet and starts work elsewhere (`readOnlyHint: false`, `openWorldHint: true`). Allow named tools only, if any.
- **Card text** in tool descriptions comes from other fleet members, framed as data. Treat it as untrusted.

## Not yet: `agent_servers`

Zed's `agent_servers` runs an agent over the Agent Client Protocol (ACP). Serving a fleet agent that way needs an ACP supervisor, which `aspace` doesn't have yet. This recipe covers the context server only.

## How this recipe was checked (2026-11-08)

Zed itself was not run.

- **Against Zed's documentation:** <https://zed.dev/docs/ai/mcp> covers `context_servers` with `command`, `args`, `env`, `url`, and `headers`, the `list_changed` reload, the indicator, and the `mcp:<server>:<tool>` permission keys.
- **Against Zed's source:** `ContextServerSettingsContent`, in `crates/settings_content/src/project.rs` at <https://github.com/zed-industries/zed>:
  - It is an untagged enum, so a `command` entry is a stdio server and a `url` entry an HTTP one.
  - `command` is the program's path.
  - `timeout` is in seconds (60 by default for stdio).
  - `headers` is a plain map of strings. Neither the source nor the documentation describes variable expansion for it.
- **The JSON:** every block parsed as JSON.
- **The server side:** started from each block as Zed starts it (`command` and `args`, with only `HOME`, `PATH`, and `env`). The client was the MCP TypeScript SDK 1.32.1, against a live fleet (the Java seed of `interop/java-seed` with a Java agent). The tools were listed and a call was answered by Java. The remote block was reached with its literal header.
