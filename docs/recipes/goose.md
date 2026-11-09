# goose

**What it gives you:** every offering of your fleet as a tool of a goose extension called `fleet`. goose starts `aspace mcp` itself (stdio), or reaches a shared gateway over Streamable HTTP with a bearer token from your environment.

Before you start, do the steps in [the recipes README](README.md#before-any-recipe): `aspace` on your `PATH`, the fleet file, and `aspace doctor` all `ok`.

## The configuration (stdio)

In goose's configuration file, `~/.config/goose/config.yaml` on macOS and Linux:

```yaml
extensions:
  fleet:
    enabled: true
    type: stdio
    name: fleet
    cmd: aspace
    args: [mcp]
    timeout: 300
```

- `timeout` is in seconds. It bounds one tool call, so keep it above the longest call you expect: a call waits 30 s unless its arguments ask for more, up to 10 minutes.
- goose expands no variables in `cmd` or `args`. If your fleet file isn't at `~/.config/agentspaces/fleet.yaml`, name it in `args`. `aspace` expands a leading `~` itself:

  ```yaml
      args: [--config, ~/.config/agentspaces/fleet.yaml, --keystore, ~/.config/agentspaces/goose-keys, mcp, --only, "space:tasks"]
  ```

- `envs` sets variables for the server, for example `envs: {ASPACE_PROFILE: mtls}`. goose drops a few names from `envs` for safety, among them `PATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, and `NODE_OPTIONS`.

To try the extension for one session without editing the file:

```sh
goose session --with-extension "aspace mcp"
```

### Several sessions at once: use the HTTP gateway

Each goose session starts its own `aspace mcp`, and a second gateway on the same keystore sees no tools ([why](../mcp.md#identity-one-gateway-per-keystore)). With several sessions, or with other hosts open, run one gateway over HTTP:

1. Make a token and its record with the snippet in [docs/mcp.md](../mcp.md#static-tokens---tokens).

2. Start the gateway on a keystore of its own:

   ```sh
   aspace --keystore ~/.config/agentspaces/mcp-keys mcp --http --tokens ~/.config/agentspaces/mcp-tokens.yaml
   ```

3. Point goose at it:

   ```yaml
   extensions:
     fleet:
       enabled: true
       type: streamable_http
       name: fleet
       uri: http://127.0.0.1:8740/mcp
       env_keys: [FLEET_MCP_TOKEN]
       headers:
         Authorization: Bearer ${FLEET_MCP_TOKEN}
       timeout: 300
   ```

goose fills `${FLEET_MCP_TOKEN}` in `headers` only from the extension's own `envs` and `env_keys`. A name in `env_keys` is looked up in goose's environment (upper-cased), then in goose's secret store. So set the variable before you start goose:

```sh
export FLEET_MCP_TOKEN="$(cat ~/.config/agentspaces/fleet-mcp.token)"
goose session
```

Or keep the token in goose's secret store (the system keyring) instead of your shell.

## Check that it works

```sh
aspace doctor     # every line "ok"
aspace cards      # the offerings: these are the extension's tools
goose info -v     # the configuration file goose read, and the enabled extensions (fleet among them)
```

In a session, ask goose which tools the `fleet` extension has: they carry the names `aspace cards` prints. If the extension fails to start, goose reports it when the session begins. Run `aspace doctor` from the same shell to see why.

## Security notes

- **Tokens:**
  - Use `env_keys` and `${FLEET_MCP_TOKEN}`, never a literal token under `headers` or `envs` in `config.yaml`.
  - The gateway's token file is owner-only (`chmod 600`, enforced). The `sha256:` record form keeps the secret out of it altogether.
- **Loopback:**
  - The gateway binds `127.0.0.1:8740`, and every request needs a valid token (401 otherwise, 403 for a foreign browser origin).
  - To share a gateway beyond this machine, put a TLS proxy in front and pass `--allowed-host`.
- **`--only`:** narrow the gateway to the spaces or schemas the sessions need. Filtering on goose's side (its `available_tools` field) still lets the gateway offer the rest. Only `--only` keeps them out of the list, including tools added later through `list_changed`.
- **Scopes:**
  - Over HTTP, map token scopes to offerings with `--policy` ([docs/mcp.md](../mcp.md#who-may-call-what-scopes-and-the-policy-file)). A call out of scope is answered 403.
  - Over stdio, the caller is you, and the policy's `local` rule applies.
- **Approval:** every fleet tool is marked `readOnlyHint: false`, `openWorldHint: true`: a call writes into the fleet and starts work elsewhere. Keep goose in a mode that asks before such tools, unless you trust every offering the gateway lists.
- **Card text** in tool descriptions comes from other fleet members, framed as data. Treat it as untrusted.

## How this recipe was checked (2026-11-08)

goose itself was not run.

- **Against goose's source and documentation:**
  - The `ExtensionConfig` variants `stdio` and `streamable_http`, their fields, the `envs` blocklist, and the header substitution from `envs` and `env_keys`: `crates/goose/src/agents/extension.rs` at <https://github.com/block/goose>.
  - `ExtensionEntry` (`enabled` beside the flattened config) and the `extensions` key: `crates/goose/src/config/extensions.rs`.
  - The file location: <https://goose-docs.pages.dev/docs/guides/config-files>.
  - `goose session --with-extension` and `goose info -v`: `documentation/docs/guides/goose-cli-commands.md`.
- **The YAML:** every block parsed as YAML.
- **The server side:** started from each block as goose starts it (`cmd` and `args`, with only `HOME`, `PATH`, and `envs`). The client was the MCP TypeScript SDK 1.32.1, against a live fleet (the Java seed of `interop/java-seed` with a Java agent). The tools were listed and a call was answered by Java. The `streamable_http` block was reached with its header filled the way goose fills it.
