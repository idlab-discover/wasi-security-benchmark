#!/usr/bin/env bash
# Full benchmark run: builds the guest + host, runs micro (criterion) and
# end-to-end benchmarks, then renders the figures.
#   ./run.sh            full run (~10 min)
#   ./run.sh --quick    smoke run (~1 min)
set -euo pipefail
cd "$(dirname "$0")"
QUICK=${1:-}
mkdir -p results

(cd guest && cargo build --release --target wasm32-wasip2)
cargo build --release --bin e2e

if [[ "$QUICK" != "--quick" ]]; then
  cargo bench --bench policy 2>&1 | tee results/criterion.log
  python3 analysis/collect_criterion.py target/criterion results/micro.json
fi

./target/release/e2e guest/target/wasm32-wasip2/release/bench-guest.wasm results/e2e.json $QUICK \
  | tee results/e2e.log

python3 analysis/plot.py results figures
