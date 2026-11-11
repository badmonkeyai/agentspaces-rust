# The Rust quick start

The files behind "Quick start: build your first agent in Rust" in the [repository README](../README.md). Each README snippet marked `<!-- quickstart/FILE -->` is FILE without its licence header.

| File | What it is |
|---|---|
| `fleet.yaml` | The fleet file: the group `shop-v1` through the seed on `127.0.0.1:7700`, and the space `orders`. |
| `Cargo.toml` | A package of its own, outside the repository's workspace, on the `agentspaces` crate by path. |
| `src/main.rs` | The Fulfiller: a worker with no argument (`cargo run`), a desk with one (`cargo run -- kite`). |
| `fulfil.sh` | The Fulfiller as a shell script, for `aspace work`. |
| `seed.sh` | Starts the seed: `aspace seed` on `127.0.0.1:7700`, serving the group of `fleet.yaml` (`shop-v1`) and keeping the space `orders`. `SEED=java ./seed.sh` starts the Java node in `../interop/java-seed` instead. |
| `verify.sh` | Runs the whole quick start end to end in a scratch copy of the repository. |

```sh
./verify.sh
```

`verify.sh` exits non-zero on any mismatch:

- a README snippet that differs from its file, or a command it runs that the README does not give;
- a step whose output is not what the README says: the shipment, the worker that ships it, the second attempt after a worker is killed, the script's shipments.

It needs Rust through rustup and port 7700 free (`PORT=7711 ./verify.sh` picks another); no Java. It stops every process it starts, also when it fails, and removes its scratch directory unless `KEEP=1`.

Run it at every release, and update the README section whenever a file here changes.
