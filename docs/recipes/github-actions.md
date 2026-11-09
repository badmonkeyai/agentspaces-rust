# GitHub Actions

**What it gives you:** a workflow with two jobs.

- **`call`** invokes a fleet offering (`aspace call research`) and keeps the result as an artifact. Run it by hand with a topic, or on a schedule.
- **`work`** joins the fleet as a worker for ten minutes (`aspace work`), runs a script from the repository for each task it takes, and stops cleanly.

Each job gets its fleet identity, seeds, and group from repository secrets. Nothing about the fleet lives in the repository.

## Before you start

1. **Make an identity for each job, and let the fleet admit it.** One keystore is one member, and two jobs running at once on one identity would see nothing of each other ([why](../mcp.md#identity-one-gateway-per-keystore)). On your machine:

   ```sh
   aspace --keystore ./ci-call-keys id      # prints {"peerId": ...}: allow this PeerID in the fleet
   aspace --keystore ./ci-work-keys id
   base64 < ci-call-keys/peer.key | gh secret set ASPACE_CALL_KEY
   base64 < ci-call-keys/peer.pub | gh secret set ASPACE_CALL_PUB
   base64 < ci-work-keys/peer.key | gh secret set ASPACE_WORK_KEY
   base64 < ci-work-keys/peer.pub | gh secret set ASPACE_WORK_PUB
   gh secret set ASPACE_SEEDS --body 'tls://fleet.example.com:7500'
   gh secret set ASPACE_JOIN --body 'aspace://zQm...'
   ```

   `peer.key` is the 48-byte PKCS#8 form of an Ed25519 key, and `peer.pub` the raw 32-byte public key. Both files are needed. Delete the local copies (`rm -r ci-call-keys ci-work-keys`) once the local check under [Check that it works](#check-that-it-works) passes.

2. **Add the worker's script** at `ci/research.sh` and make it executable. Example 32's `examples/rust-fleet/research.sh` is one: it reads the task as JSON on standard input and prints the result object.

3. **Install `aspace`.** The workflow installs it with `cargo install` from the `agentspaces-rust` repository, at the tag in `ASPACE_TAG`, and caches the binary. There are no release binaries yet. To build from a checkout instead, run `cargo install --locked --path crates/aspace`.

## The configuration

`.github/workflows/fleet.yml`:

```yaml
name: fleet

on:
  workflow_dispatch:
    inputs:
      topic:
        description: The topic to research
        type: string
        required: true
        default: rust
  schedule:
    - cron: "17 6 * * 1-5"

permissions:
  contents: read

concurrency:
  group: fleet
  cancel-in-progress: false

env:
  ASPACE_SEEDS: ${{ secrets.ASPACE_SEEDS }}
  ASPACE_JOIN: ${{ secrets.ASPACE_JOIN }}
  ASPACE_SPACES: tasks
  ASPACE_NO_DAEMON: "1"
  ASPACE_TAG: v0.5.0

jobs:
  call:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - name: Restore aspace from the cache
        id: cache
        uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6
        with:
          path: ~/.cargo/bin/aspace
          key: aspace-${{ runner.os }}-${{ env.ASPACE_TAG }}

      - name: Install aspace
        if: steps.cache.outputs.cache-hit != 'true'
        run: cargo install --locked --git https://github.com/badmonkeyai/agentspaces-rust --tag "$ASPACE_TAG" aspace

      - name: Restore the fleet identity
        env:
          PEER_KEY: ${{ secrets.ASPACE_CALL_KEY }}
          PEER_PUB: ${{ secrets.ASPACE_CALL_PUB }}
        run: |
          umask 077
          keys="$RUNNER_TEMP/aspace-keys"
          mkdir -p "$keys"
          printf '%s' "$PEER_KEY" | base64 -d > "$keys/peer.key"
          printf '%s' "$PEER_PUB" | base64 -d > "$keys/peer.pub"
          echo "ASPACE_KEYSTORE=$keys" >> "$GITHUB_ENV"

      - name: Check the configuration and the join
        run: aspace doctor

      - name: Call research
        env:
          TOPIC: ${{ inputs.topic || 'rust' }}
        run: |
          jq -n --arg topic "$TOPIC" '{topic: $topic, priority: 1}' > request.json
          status=0
          aspace -q call research --json @request.json --timeout 5m > finding.json || status=$?
          case "$status" in
            0) jq . finding.json ;;
            2) echo "::error::no offering named research (aspace cards lists the offerings)"; exit 1 ;;
            3) echo "::error::no result within 5m; the request stays in the fleet, leased, for a late worker"; exit 1 ;;
            4) echo "::error::the fleet refused this identity: is its PeerID allowed?"; exit 1 ;;
            *) echo "::error::aspace call failed with exit $status"; exit 1 ;;
          esac

      - name: Keep the finding
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7
        with:
          name: finding
          path: finding.json

  work:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          persist-credentials: false

      - name: Restore aspace from the cache
        id: cache
        uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6
        with:
          path: ~/.cargo/bin/aspace
          key: aspace-${{ runner.os }}-${{ env.ASPACE_TAG }}

      - name: Install aspace
        if: steps.cache.outputs.cache-hit != 'true'
        run: cargo install --locked --git https://github.com/badmonkeyai/agentspaces-rust --tag "$ASPACE_TAG" aspace

      - name: Restore the worker identity
        env:
          PEER_KEY: ${{ secrets.ASPACE_WORK_KEY }}
          PEER_PUB: ${{ secrets.ASPACE_WORK_PUB }}
        run: |
          umask 077
          keys="$RUNNER_TEMP/aspace-keys"
          mkdir -p "$keys"
          printf '%s' "$PEER_KEY" | base64 -d > "$keys/peer.key"
          printf '%s' "$PEER_PUB" | base64 -d > "$keys/peer.pub"
          echo "ASPACE_KEYSTORE=$keys" >> "$GITHUB_ENV"

      - name: Work research tasks for ten minutes
        run: |
          timeout --preserve-status --kill-after=90s 10m \
            aspace work --space tasks \
              --take 'ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1' \
              --produces 'ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1' \
              --action research --name ci-researcher --parallel 2 --task-timeout 2m --grace 30s \
              -- ./ci/research.sh
```

How the pieces fit:

- **Configuration:** `aspace` reads `ASPACE_SEEDS`, `ASPACE_JOIN`, `ASPACE_SPACES`, and `ASPACE_KEYSTORE` from the environment. No fleet file is needed.
- **The identity:** each job writes its identity under `$RUNNER_TEMP` with `umask 077`, so `peer.key` is 0600, and tells later steps where it is through `$GITHUB_ENV`.
- **`aspace doctor`:** checks the configuration, the keystore, each seed, and the join before anything is written. It exits 1 when a check fails.
- **The call step:** sorts `aspace`'s exit codes. 2 means no such offering, 3 no result in time, and 4 the fleet refused the identity. A timed-out request stays in the fleet, leased, so a late worker still answers it.
- **The worker:**
  - `timeout` sends SIGTERM after ten minutes. `aspace work` then stops taking, lets running scripts finish within `--grace`, and exits 0. `--preserve-status` passes that 0 on.
  - A script that is still running gets SIGTERM, and SIGKILL 2 s later. `timeout --kill-after` is the last resort.
  - A task whose script fails or is cut off isn't completed. Its lease lapses and another worker takes it.

## Check that it works

1. **Locally, with the same variables** (your own fleet file isn't read once the variables are set):

   ```sh
   ASPACE_SEEDS='tls://fleet.example.com:7500' ASPACE_JOIN='aspace://zQm...' ASPACE_SPACES=tasks \
     ASPACE_KEYSTORE=./ci-call-keys aspace doctor
   ```

2. **In GitHub:** run the workflow from the Actions tab (`workflow_dispatch`) with a topic.
   - The `call` job's "Call research" step prints the finding, and the run keeps `finding.json` as the `finding` artifact.
   - The `work` job's log shows `aspace: working as <peerId>/ci-researcher ...`, a `took` and a `completed` line per task, and at the end `aspace: stopped: N tasks completed, 0 failed`.

3. **While `work` runs,** `aspace cards` on your machine lists `research` with one more replica.

## Security notes

- **Secrets:**
  - The fleet key reaches only the steps that write it, through `env:`. It is never interpolated into a script, and it lives on the runner only under `$RUNNER_TEMP`, owner-only.
  - Give CI its own PeerIDs, allowed only what CI needs by the group's authorizer. Revoke them in the fleet if a secret leaks.
- **Untrusted input:** the workflow input `topic` reaches the script through an environment variable and `jq --arg`, never as `${{ inputs.topic }}` inside `run:`, which would let an input inject shell commands.
- **Triggers:** run only on `workflow_dispatch` and `schedule` (or `push` to protected branches). Pull requests from forks don't get secrets. Never hand the fleet key to `pull_request_target` jobs that build untrusted code.
- **Least privilege on GitHub's side:**
  - `permissions: contents: read`, and `persist-credentials: false` on checkout.
  - Third-party actions are pinned by commit SHA. The SHAs above are the v7, v6, and v7 tags as resolved on 2026-11-08. Keep them current with Dependabot.
- **Transport:**
  - The default profile is `mtls`: a `tls://` seed must attest its PeerID.
  - Plaintext `tcp://` is refused outside loopback unless the profile is `dev-local`, which is not for CI over the internet.
- **The worker's script:** `aspace work` runs it without a shell, with the entry on standard input and a cleared environment (`PATH`, `HOME`, `LANG`, and `ASPACE_ENTRY_ID`, `ASPACE_SCHEMA`, `ASPACE_SPACE`). Pass anything else with `--env NAME`. Task content is data: the script must never `eval` it.
- **A stopped worker's card** stays in the catalogue until it expires. Callers may write tasks no one takes in that window. Those tasks stay leased and then expire, or another `research` worker takes them.

## How this recipe was checked (2026-11-08)

- **The schema:** the workflow validated against the published workflow schema, <https://json.schemastore.org/github-workflow.json>, with ajv.
- **The action tags:** resolved with `git ls-remote` against `actions/checkout`, `actions/cache`, and `actions/upload-artifact`.
- **The steps:** every `run:` step ran locally with bash in the order the jobs run them, against a live fleet: the Java seed of `interop/java-seed` with a Java agent offering `research`. Each step had GitHub's variables `RUNNER_TEMP` and `GITHUB_ENV` (whose lines were applied between steps), and the secrets as variables. Three substitutions were needed for the local fleet:
  - The local seed is a dev-local `tcp://` group founded from a text, so `ASPACE_GROUP` and `ASPACE_PROFILE=dev-local` stood in for `ASPACE_JOIN`.
  - The schemas were those of the seed's agent.
  - macOS has no GNU `timeout`, so a stand-in sent SIGTERM at the deadline. aspace's own exit 0 on SIGTERM was observed directly. `--preserve-status` and `--kill-after` are GNU timeout's, as documented in timeout(1).
- **The install:** `cargo install --locked --path crates/aspace` (the fallback above) was run with the stable toolchain from outside the workspace and built `aspace` 0.5.0. The `--git` form wasn't run.
- **Not run:** GitHub itself.
