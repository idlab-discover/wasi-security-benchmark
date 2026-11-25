#!/usr/bin/env python3
"""Turn results/e2e.json (+ results/micro.json) into figures and summary.json.

usage: plot.py <results_dir> <figures_dir>
"""
import json
import pathlib
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

RES = pathlib.Path(sys.argv[1])
FIG = pathlib.Path(sys.argv[2])
FIG.mkdir(parents=True, exist_ok=True)
rng = np.random.default_rng(42)

# ---- palette (validated categorical order, light mode) ---------------------
C = {
    "no policy": "#2a78d6",
    "policy: allowed": "#1baf7a",
    "policy: denied by rule": "#eb6834",
    "policy: capability off": "#eda100",
    "sandbox (cap-std)": "#e87ba4",
}
INK, INK2, MUTED, GRID, AXIS, SURF = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 9.5,
    "axes.edgecolor": AXIS,
    "axes.labelcolor": INK2,
    "axes.titlesize": 11,
    "axes.titleweight": "bold",
    "axes.titlecolor": INK,
    "axes.titlelocation": "left",
    "xtick.color": MUTED,
    "ytick.color": INK2,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.6,
    "axes.axisbelow": True,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.facecolor": SURF,
    "axes.facecolor": SURF,
    "savefig.facecolor": SURF,
    "legend.frameon": False,
})

OP_TITLE = {
    "clock": "monotonic-clock.now",
    "env": "get-environment",
    "fs_stat": "fs stat-at",
    "fs_read": "fs open + read 4 KiB",
    "fs_write": "fs open + write 4 KiB",
    "fs_open_write": "fs open-at (write)",
    "tcp_create": "tcp create-socket",
    "tcp_bind": "tcp bind",
    "tcp_connect": "tcp connect (loopback)",
    "udp_send": "udp send (1 datagram)",
    "dns": "ip-name-lookup",
}
MAIN_GROUPS = list(OP_TITLE)


def category(r):
    if r["profile"] == "baseline":
        return "no policy"
    if r["expect"] == "allow":
        return "policy: allowed"
    if "sandbox" in r["label"]:
        return "sandbox (cap-std)"
    if r["profile"] == "nonet":
        return "policy: capability off"
    return "policy: denied by rule"


def boot_median(a, n=4000):
    a = np.asarray(a)
    idx = rng.integers(0, len(a), (n, len(a)))
    return np.median(a[idx], axis=1)


def save(fig, name):
    for ext in ("png", "svg"):
        fig.savefig(FIG / f"{name}.{ext}", dpi=180, bbox_inches="tight")
    plt.close(fig)
    print("wrote", FIG / f"{name}.png")


e2e = json.loads((RES / "e2e.json").read_text())
micro = json.loads((RES / "micro.json").read_text()) if (RES / "micro.json").exists() else []
rows = e2e["results"]
for r in rows:
    a = np.asarray(r["ns_per_op"])
    r["median"] = float(np.median(a))
    bm = boot_median(a)
    r["ci"] = [float(np.percentile(bm, 2.5)), float(np.percentile(bm, 97.5))]
    r["cv"] = float(a.std(ddof=1) / a.mean()) if len(a) > 1 else 0.0
    r["throughput"] = 1e9 / r["median"]
    r["category"] = category(r)

invalid = [r for r in rows if not r["valid"]]
if invalid:
    print("WARNING: invalid results:", [(r["group"], r["label"]) for r in invalid])

main = [r for r in rows if r["group"] in MAIN_GROUPS]

# ---- Fig 1: throughput per request, every variant ---------------------------
fig, ax = plt.subplots(figsize=(8.6, 9.2))
y, ticks, labels, seps = 0, [], [], []
for g in MAIN_GROUPS:
    rs = [r for r in main if r["group"] == g]
    for r in rs:
        lo, hi = 1e9 / r["ci"][1], 1e9 / r["ci"][0]
        ax.barh(y, r["throughput"], height=0.72, color=C[r["category"]], zorder=2)
        ax.errorbar(r["throughput"], y, xerr=[[r["throughput"] - lo], [hi - r["throughput"]]],
                    fmt="none", ecolor=INK2, elinewidth=0.8, capsize=0, zorder=3)
        txt = f"{r['throughput']/1e6:.2f} M/s" if r["throughput"] >= 1e6 else f"{r['throughput']/1e3:.0f} k/s"
        ax.text(r["throughput"] * 1.12, y, txt, va="center", fontsize=7.5, color=INK2)
        ticks.append(y)
        lab = r["label"].replace("policy: ", "").replace("policy ", "")
        labels.append(f"{OP_TITLE[g]}  ·  {lab}" if r is rs[0] else lab)
        y += 1
    seps.append(y - 0.5)
    y += 0.6
for s in seps[:-1]:
    ax.axhline(s + 0.3, color=GRID, lw=0.8)
ax.set_yticks(ticks, labels, fontsize=7.8)
ax.invert_yaxis()
ax.set_xscale("log")
ax.set_xlim(1e4, 4e7)
ax.set_xlabel("requests per second, single guest thread (log scale) — higher is faster")
ax.set_title("Throughput per WASI request: no policy vs. policy (allowed / denied)")
ax.grid(axis="y", visible=False)
handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in C.values()]
ax.legend(handles, C.keys(), loc="lower right", fontsize=7.8)
save(fig, "fig1_throughput")

# ---- Fig 2: rule-count scaling -----------------------------------------------
scale = {}
for name in ("scale_udp_send", "scale_tcp_connect"):
    rs = [r for r in rows if r["group"] == name]
    base = next(r for r in rs if r["rules"] is None)
    series = {}
    for r in rs:
        if r["rules"] is None:
            continue
        key = "allowed" if r["expect"] == "allow" else "denied"
        series.setdefault(key, []).append((r["rules"], r["median"], r["ci"]))
    scale[name] = {"baseline": base["median"], "series": {k: sorted(v) for k, v in series.items()}}

dec = [m for m in micro if m["group"] == "allows_socket"]
ncols = 3 if dec else 2
fig, axes = plt.subplots(1, ncols, figsize=(4.0 * ncols, 3.8))
for ax, (name, title) in zip(axes, [("scale_udp_send", "UDP send (end-to-end)"),
                                     ("scale_tcp_connect", "TCP connect (end-to-end)")]):
    s = scale[name]
    for key, col in (("allowed", C["policy: allowed"]), ("denied", C["policy: denied by rule"])):
        pts = s["series"][key]
        xs = [p[0] + 1 for p in pts]
        ax.plot(xs, [p[1] / 1e3 for p in pts], color=col, lw=2, marker="o", ms=5,
                markeredgecolor=SURF, markeredgewidth=1.5, label=key)
        ax.fill_between(xs, [p[2][0] / 1e3 for p in pts], [p[2][1] / 1e3 for p in pts], color=col, alpha=0.15, lw=0)
    ax.axhline(s["baseline"] / 1e3, color=C["no policy"], lw=1.2, label="no policy")
    ax.set_xscale("log")
    ax.set_xticks([1, 11, 101, 1001, 10001], ["0", "10", "100", "1k", "10k"])
    ax.minorticks_off()
    ax.set_ylim(0, None)
    ax.set_xlabel("extra (non-matching) rules in policy (log scale)")
    ax.set_ylabel("µs per request")
    ax.set_title(title)
    ax.legend(loc="upper left", fontsize=7.8)
if dec:
    ax = axes[2]
    for fn, col, lab in (("udp_send/deny", C["policy: denied by rule"], "deny (full scan)"),
                         ("udp_send/allow_last_rule", C["policy: allowed"], "allow, rule last"),
                         ("udp_send/allow_first_rule", C["no policy"], "allow, rule first")):
        pts = sorted((int(m["value"]), m["median_ns"]) for m in dec if m["function"] == fn)
        ax.plot([p[0] + 1 for p in pts], [p[1] for p in pts], color=col, lw=2, marker="o", ms=5,
                markeredgecolor=SURF, markeredgewidth=1.5, label=lab)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xticks([1, 11, 101, 1001, 10001], ["0", "10", "100", "1k", "10k"])
    ax.minorticks_off()
    ax.set_xlabel("extra (non-matching) rules in policy (log scale)")
    ax.set_ylabel("ns per decision (log scale)")
    ax.set_title("allows_socket() alone (micro)")
    ax.legend(loc="upper left", fontsize=7.8)
fig.suptitle("Cost vs. policy size: rules are matched by linear scan", x=0.01, ha="left",
             fontweight="bold", fontsize=11.5, color=INK)
fig.tight_layout()
save(fig, "fig2_rule_scaling")

# ---- Fig 3: per-task lifecycle ------------------------------------------------
life = []
for l in e2e["lifecycle"]:
    life.append({k: (float(np.median(l[k])) if isinstance(l[k], list) else l[k]) for k in l})
phases = [("parse_ns", "parse TOML", "#eb6834"), ("build_ctx_ns", "build WasiCtx", "#eda100"),
          ("instantiate_ns", "instantiate", "#2a78d6"), ("run_ns", "run (trivial guest)", "#1baf7a")]
parse_micro = sorted(((int(m["value"]), m["median_ns"]) for m in micro if m["group"] == "parse_policy"
                      and m["function"] == "rules"))
fig, axes = plt.subplots(1, 2 if parse_micro else 1, figsize=(10.5, 3.4), gridspec_kw={"width_ratios": [1.6, 1]} if parse_micro else None)
ax = axes[0] if parse_micro else axes
names = [f"{l['profile']}" for l in life]
left = np.zeros(len(life))
for key, lab, col in phases:
    vals = np.array([l[key] / 1e3 for l in life])
    ax.barh(range(len(life)), vals, left=left, color=col, height=0.6, label=lab, edgecolor=SURF, linewidth=1.5)
    left += vals
for i, t in enumerate(left):
    ax.text(t + 3, i, f"{t:.0f} µs", va="center", fontsize=8, color=INK2)
ax.set_yticks(range(len(life)), ["no policy" if n == "baseline" else n for n in names])
ax.invert_yaxis()
ax.set_xlabel("µs per task start (median)")
ax.set_xlim(0, left.max() * 1.18)
ax.set_title("Per-task cost of applying a policy")
ax.grid(axis="y", visible=False)
ax.legend(ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.22), fontsize=7.8)
if parse_micro:
    ax = axes[1]
    ax.plot([p[0] for p in parse_micro], [p[1] / 1e3 for p in parse_micro], color=C["policy: denied by rule"],
            lw=2, marker="o", ms=5, markeredgecolor=SURF, markeredgewidth=1.5)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("rules in policy file (bind + connect, log scale)")
    ax.set_ylabel("µs to parse (log scale)")
    ax.set_title("WasiSecurity::from_toml (micro)")
fig.tight_layout()
save(fig, "fig3_lifecycle")

# ---- summary.json (numbers behind the figures) -------------------------------
summary = {
    "meta": e2e["meta"],
    "variants": [{k: r[k] for k in ("group", "op", "label", "profile", "expect", "category", "rules", "iters",
                                    "median", "ci", "cv", "throughput", "latency", "errors", "valid")} for r in rows],
    "scaling": scale,
    "lifecycle": life,
    "micro": micro,
    "invalid": len(invalid),
}
(RES / "summary.json").write_text(json.dumps(summary, indent=1))
print("wrote", RES / "summary.json")
