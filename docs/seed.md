# `aspace seed`: a group of your own

`aspace seed` is a listening member (SPEC §5.1 to §5.4). Other members dial it to join its group. It admits them under the group's membership, forwards what each one gossips to the others, answers their anti-entropy pulls, relays the frames they address to one another, and holds the entries of the spaces it replicates. A writer may leave, and a later visitor still reads what it wrote. A fleet of Rust members, scripts, and the Python, TypeScript, Ruby, and Java peers needs no other node to start.

[`examples/two-peers`](../examples/two-peers) runs a seed, a writer, a worker, a caller, and a late visitor from one shell script.

- [Start one](#start-one)
- [Which group it serves](#which-group-it-serves)
- [Listeners and what they advertise](#listeners-and-what-they-advertise)
- [Invite groups](#invite-groups)
- [tls and required attestation](#tls-and-required-attestation)
- [A second seed](#a-second-seed)
- [What it replicates, and its bounds](#what-it-replicates-and-its-bounds)
- [Output, stopping, and exit codes](#output-stopping-and-exit-codes)
- [What it counts](#what-it-counts)
- [In a Rust program](#in-a-rust-program)

## Start one

```sh
aspace --profile dev-local --keystore keys/seed seed --found demo
```

It founds the group `demo`, listens on `tcp://127.0.0.1:7700`, and prints one JSON line:

```json
{"event":"listening","peer":"z4kMUM...","group":"z4ZbWj...","join":"aspace://z4ZbWj...","listen":["tcp://127.0.0.1:7700"],"advertise":[],"membership":"OPEN"}
```

Every member then joins with the seed and the `join` URI:

```sh
export ASPACE_PROFILE=dev-local ASPACE_SEEDS=tcp://127.0.0.1:7700 ASPACE_JOIN=aspace://z4ZbWj...
aspace --keystore keys/alice write 'demo.Note#v1' --space notes --json '{"text":"hello"}'
aspace --keystore keys/bob read 'demo.Note#v1' --space notes
```

Give the seed and every member a keystore of its own. One keystore is one PeerID, and the seed takes every link of one PeerID for one member.

## Which group it serves

| Flags | The group |
|---|---|
| `--found NAME` | A group it founds. The signed founding is made on the first run, kept beside the keystore as `founding-NAME.cbor`, and reused, so the GroupID survives restarts. Members join by id: `--join aspace://<group-id>`. |
| `--group TEXT` | A group founded from a text, as the Java demos found them. Its GroupID is the text's hash; members pass the same `--group TEXT`. Such a group has no signed founding, so it cannot be joined by id, and it is always open. |
| `--join URI --seeds ADDR` | Another seed's group: this seed fetches and verifies its founding through `ADDR`, then serves it too. See [A second seed](#a-second-seed). |
| none | The fleet file's group, as every `aspace` command reads it. |

`--found` beside `--group` or `--join` is refused. A founding file that another keystore signed, or that does not verify, is refused with exit 4.

## Listeners and what they advertise

The listeners come from the highest layer that names any:

1. `--listen ADDR` (repeatable),
2. `ASPACE_LISTEN` (comma-separated),
3. the fleet file's `agentspaces.bind`, as the Java starter spells it (a list is read too),
4. else `127.0.0.1:7700`.

Each is `tcp://host:port`, `tls://host:port`, or `host:port`. A bare `host:port` listens on `tls` under the `mtls` profile and on `tcp` under `dev-local`, as Java's `bind` follows its transport. Port `0` lets the system choose; the listening line names the real port.

A plaintext `tcp` listener on an address that is not loopback (`0.0.0.0` included) is refused unless the profile is `dev-local`. Its frames are signed but not encrypted, and members under `mtls` refuse to dial it.

A listener bound to every interface advertises nothing until it is told what members dial: `--advertise host:port` (or `ASPACE_ADVERTISE`, or the file's `agentspaces.advertise`). With several listeners, name the scheme: `--advertise tls://seed.example.com:7500`. An advertisement is taken from the listeners' layer or one above it, so a file written for a Java node's `bind` does not rename a listener a flag named.

```yaml
agentspaces:
  bind: 0.0.0.0:7500
  advertise: seed.example.com:7500
  groups:
    - name: crew
      membership: invite
      seeds: [ "tls://seed.example.com:7500" ]
      spaces: [ tasks, results ]
```

Only a listening command reads `bind` and `advertise`. A visitor reading the same file never binds anything. The seed skips its own address among the group's seeds, so one fleet file serves the seed and its members.

## Invite groups

An `INVITE` group admits only peers that present a credential the founder issued, or one signed under a delegation the founder signed (SPEC §5.1).

```sh
aspace --keystore keys/seed seed --found crew --membership invite --listen tls://0.0.0.0:7500 \
       --advertise seed.example.com:7500
aspace --keystore keys/seed invite --found crew --label 'ci runners' --not-after 30d
```

`aspace invite` runs with the founder's keystore. It mints a fresh invite key, signs a delegation of it to the group that admits newcomers until `--not-after` (7 days by default, a year at most), and prints:

```json
{"invite":"aspace-inv1-...","group":"z7rRbb...","join":"aspace://z7rRbb...","name":"crew","label":"ci runners","notAfter":"2026-12-11T10:20:50.028Z"}
```

Whoever holds the key passes it on any command, with `--invite` or `ASPACE_INVITE`. With no group named, the invite names it:

```sh
export ASPACE_SEEDS=tls://seed.example.com:7500 ASPACE_INVITE='aspace-inv1-...'
aspace --keystore keys/runner-1 write 'crew.Note#v1' --space notes --json '{"text":"in"}'
```

The command signs its own PeerID under the invite and presents that as its `aspace:join` resource hint. The rules:

- The expiry limits first admission only. A member admitted in time stays a member until the founder revokes its credential or the delegation.
- A visitor that joins an `INVITE` group by id with no invite is refused before it does anything (exit 4), naming `--invite`.
- An invite of one group beside another group named is refused, naming both.
- The key carries a secret. No refusal and no `Debug` output shows it, but anyone who reads it can join: hand it over as you would a password.
- The membership is fixed at the founding. `--membership` that differs from the founded group's is refused. A fleet file's `membership: invite` on a group founded from a text is refused too: such a group has no founding to carry it.

## tls and required attestation

A `tls` listener presents the seed's channel certificate, endorsed by its identity (SPEC §5.6). A member that presents its own is attested on the link. `--require-attestation` admits only members whose link attests them:

```sh
aspace --keystore keys/seed seed --found crew --listen tls://0.0.0.0:7500 --require-attestation \
       --advertise seed.example.com:7500
```

With it, every frame must come from the PeerID its link attests, introductions included. Frames that arrive inside a relay are dropped, and a `tcp` listener is refused. The Python, TypeScript, and Ruby clients and every `aspace` command present channel certificates when they dial `tls://`.

## A second seed

A second seed joins the first by id and serves the same group:

```sh
aspace --keystore keys/seed2 --seeds tls://seed1.example.com:7500 --join aspace://zQm... seed \
       --listen tls://0.0.0.0:7501 --advertise seed2.example.com:7501
```

It links to the first seed and forwards between that link and the members it accepts. Entries written through either seed reach the members of both. It redials the other seeds after a lost link, every 5 s, for as long as it runs. A seed of a group it founds, or of one founded from a text, serves its own members while no other seed answers.

## What it replicates, and its bounds

It replicates the spaces `--replicate` names (repeatable). By default it replicates the group's spaces (`ASPACE_SPACES`, or the fleet file's `spaces`) and every space a member writes to, up to `--max-spaces` spaces opened that way (64 by default). Each space holds at most 65,536 entries and 256 MiB of entry states, and collects completed, withdrawn, and lapsed entries past their horizon (SPEC §7.3). The payload block of an entry over 64 KiB is fetched from its writer and held, so the writer may leave.

Everything a remote can send is bounded:

| Bound | Default |
|---|---|
| Accepted links held at once | 1024 (one more takes the place of the oldest link that introduced nobody, and is closed at once when every link carries a member) |
| Links one member holds | 4 (the oldest closes past it); each member hears a rumor once |
| Admitted members | 4096 |
| Admissions | a burst of 64, then 32 per second; only an admission spends it |
| Frames a link carries from peers that are not members | 64 (a link that introduced nobody is then closed) |
| A link with no verified introduction | closed after 30 s |
| A silent link | closed after 120 s |
| A rumor's hop budget | clamped to 6 |
| DIGEST answers per member | paced; the streams one DIGEST may name, and the frames one answer may take, are capped |
| A link's outbound queue | 16 MiB; a burst uses half, and a far end that stops reading is closed after 30 s |

These are the defaults of `agentspaces::peer::ListenConfig`. A Rust program that listens can set each one.

## Output, stopping, and exit codes

The listening line is the only line on standard output. Diagnostics go to standard error: the founding, where it listens and how members join, each member admitted, and the link to another seed lost and back.

SIGINT, SIGTERM, or SIGHUP stops it. It stops accepting links, gives the links it holds 2 s to send what they queued, closes them, and exits 0. A second signal closes at once.

| Exit | When |
|---|---|
| 0 | stopped by a signal |
| 1 | a listener cannot bind (the port is taken: pass `--listen`, port 0 lets the system choose), or the peer closed |
| 2 | a flag, variable, or key refused, each refusal naming it; a membership that differs from the founding's |
| 3 | a second seed's join did not complete in time |
| 4 | a founding file another keystore signed, or one that does not verify; a seed that is not attested |

`aspace status` against a seed lists its members: the seed, and every peer whose signed advertisement is still live.

## What it counts

A Rust program holding the seed's `Peer` reads `Peer::counters().listen` (`agentspaces::peer::ListenCounters`). It counts:

- links accepted, refused, closed, and closed as silent;
- members admitted, and admissions refused by reason: the rate, the membership policy, a revoked PeerID, a forged or foreign advertisement, an expired one, a full membership, an unattested link, a link that already carries another member;
- frames from strangers, frames over a member's rate, and frames dropped under required attestation;
- rumors forwarded, dropped as duplicates, and left unforwarded;
- DIGESTs answered, PULL_RESP frames sent, pulls paced, and digests truncated;
- relays forwarded, and relays refused for a stranger, an unreachable target, or a malformed path;
- blocks fetched, block asks, fetches abandoned, spaces replicated, spaces refused, and GROUP_ADs served.

## In a Rust program

The same role is in the `agentspaces` crate:

```rust
use std::time::Duration;

use agentspaces::config::{Config, Overrides};
use agentspaces::peer::Peer;

async fn seed() -> Result<(), Box<dyn std::error::Error>> {
    let overrides = Overrides {
        listening: true,
        group: Some("shop-v1".to_owned()),
        listen: vec!["tcp://127.0.0.1:7700".to_owned()],
        ..Overrides::default()
    };
    let config = Config::from_env(&overrides)?;
    let peer = Peer::start(config.peer_config(config.identity()?)?).await?;
    println!("listening on {:?}", peer.listen_addrs());
    tokio::signal::ctrl_c().await?;
    peer.drain(Duration::from_secs(2)).await?;
    peer.close().await?;
    Ok(())
}
```

`agentspaces::group::found_or_load` makes or loads a signed founding, as `--found` does. `PeerConfig::listen_on` and `ListenConfig` build a listener in code without the configuration layers.
