# wasi-security benchmark suite

Benchmarks for [`elastic-wasi-security`](https://github.com/elasticproject-eu/wasi-security):
what a WASI security policy costs per request, how cost grows with policy size, and what applying a policy adds to a task start.

```
./run.sh            # full run (~15 min): build, criterion micro benches, e2e, figures
./run.sh --quick    # smoke run (~1 min)
```

Requires the `wasm32-wasip2` target, Python 3 with matplotlib and numpy.


## Configurations

* **no policy**: same dirs mounted read-write, `inherit_network()`, TCP/UDP/DNS on (raw cost of each request).
* **policy**: `results/bench_policy.toml` (1 read-only dir, 1 mount, TCP bind on `127.0.0.1:*`, one TCP and one UDP connect peer, DNS on), applied with the host's `configure_wasi`.
* **policy w/o network rules**: same storage, no `[network]` rules, DNS off (TCP/UDP switched off).
* **policy+N**: N non-matching rules placed before the matching one in `bind` and `connect`.

Variants of one request type are sampled round-robin (fresh instance per sample)
so CPU-frequency drift affects them equally. Loopback TCP/UDP sinks run in the host.
