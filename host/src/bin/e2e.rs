//! End-to-end benchmark: runs the guest component under different WASI
//! contexts (no policy / policy) and records per-request cost (allowed and
//! denied), rule-count scaling and per-task lifecycle overhead.
//!
//! usage: e2e <guest.wasm> <out.json> [--samples N] [--quick]

use std::io::Read;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use elastic_wasi_security::WasiSecurity;
use serde::Serialize;
use serde_json::Value;
use wasi_security_bench::*;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p2::bindings::Command;
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;

#[derive(Clone)]
enum Profile {
    Baseline,
    Policy(Box<WasiSecurity>),
}

#[derive(Clone, Copy, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Expect {
    Allow,
    Deny,
}

#[derive(Clone)]
struct Variant {
    label: String,
    profile_name: String,
    profile: Profile,
    vars: Vec<(String, String)>,
    expect: Expect,
    rules: Option<usize>,
}

struct Group {
    name: String,
    op: String,
    iters: u64,
    variants: Vec<Variant>,
}

#[derive(Serialize)]
struct VariantResult {
    group: String,
    op: String,
    label: String,
    profile: String,
    expect: Expect,
    rules: Option<usize>,
    iters: u64,
    /// ns per request, one entry per sample (fresh instance per sample)
    ns_per_op: Vec<f64>,
    /// per-request latency percentiles (ns) from one latency-mode run
    latency: Value,
    /// error code histogram of the last sample (denials show up here)
    errors: Value,
    valid: bool,
}

#[derive(Serialize)]
struct LifecycleResult {
    profile: String,
    rules: usize,
    parse_ns: Vec<f64>,
    build_ctx_ns: Vec<f64>,
    instantiate_ns: Vec<f64>,
    run_ns: Vec<f64>,
}

#[derive(Serialize)]
struct Output {
    meta: Value,
    results: Vec<VariantResult>,
    lifecycle: Vec<LifecycleResult>,
}

struct Harness {
    engine: Engine,
    component: Component,
    linker: Linker<StoreData>,
    dirs: Vec<(String, String)>,
}

struct RunTimes {
    out: Value,
    build_ns: f64,
    inst_ns: f64,
    run_ns: f64,
}

impl Harness {
    async fn run(&self, profile: &Profile, vars: &[(String, String)]) -> Result<RunTimes> {
        let t0 = Instant::now();
        let stdout = MemoryOutputPipe::new(1 << 20);
        let mut b = WasiCtxBuilder::new();
        b.stdout(stdout.clone()).inherit_stderr();
        let env = vars.iter().map(|(k, v)| (k.as_str(), v.as_str()));
        match profile {
            Profile::Baseline => configure_baseline(&mut b, env, &self.dirs)?,
            Profile::Policy(p) => configure_wasi(&mut b, env, &[], Some(p))?,
        }
        let mut store = Store::new(
            &self.engine,
            StoreData { wasi: b.build(), table: ResourceTable::new() },
        );
        let t1 = Instant::now();
        let cmd = Command::instantiate_async(&mut store, &self.component, &self.linker).await?;
        let t2 = Instant::now();
        cmd.wasi_cli_run()
            .call_run(&mut store)
            .await?
            .map_err(|()| anyhow::anyhow!("guest exited with error"))?;
        let t3 = Instant::now();
        let raw = stdout.contents();
        let out: Value = serde_json::from_slice(raw.trim_ascii())
            .with_context(|| format!("bad guest output: {}", String::from_utf8_lossy(&raw)))?;
        Ok(RunTimes {
            out,
            build_ns: (t1 - t0).as_nanos() as f64,
            inst_ns: (t2 - t1).as_nanos() as f64,
            run_ns: (t3 - t2).as_nanos() as f64,
        })
    }
}

fn vars(pairs: &[(&str, String)]) -> Vec<(String, String)> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

fn tcp_sink() -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    let port = l.local_addr()?.port();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            // Wait for the guest to close (EOF), then reset: the handshake always
            // completes cleanly for the guest, and the RST avoids a TIME_WAIT
            // pile-up across ~100k loopback connects.
            let mut buf = [0u8; 64];
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            while matches!(std::io::Read::read(&mut s, &mut buf), Ok(n) if n > 0) {}
            let _ = socket2::SockRef::from(&s).set_linger(Some(Duration::ZERO));
            drop(s);
        }
    });
    Ok(port)
}

fn udp_sink() -> Result<u16> {
    let s = UdpSocket::bind("127.0.0.1:0")?;
    let port = s.local_addr()?.port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        loop {
            let _ = s.recv_from(&mut buf);
        }
    });
    Ok(port)
}

fn parse(toml: &str) -> Result<Profile> {
    Ok(Profile::Policy(Box::new(WasiSecurity::from_toml(toml)?)))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        bail!("usage: e2e <guest.wasm> <out.json> [--samples N] [--quick] [--only GROUP]");
    }
    let guest = PathBuf::from(&args[1]);
    let out_path = PathBuf::from(&args[2]);
    let quick = args.iter().any(|a| a == "--quick");
    let samples: usize = args
        .iter()
        .position(|a| a == "--samples")
        .map(|i| args[i + 1].parse().unwrap())
        .unwrap_or(if quick { 3 } else { 15 });
    let only: Option<String> = args.iter().position(|a| a == "--only").map(|i| args[i + 1].clone());
    let scale = |n: u64| if quick { (n / 10).max(50) } else { n };

    // ---- fixtures -------------------------------------------------------
    let root = std::env::temp_dir().join(format!("wasi-sec-bench-{}", std::process::id()));
    std::fs::create_dir_all(root.join("ro"))?;
    std::fs::create_dir_all(root.join("rw"))?;
    for d in ["ro", "rw"] {
        std::fs::write(root.join(d).join("file.bin"), vec![0x5Au8; 4096])?;
    }
    std::fs::write(root.join("secret.bin"), b"outside the sandbox")?;
    let root_s = root.to_string_lossy().to_string();

    let tcp_a = tcp_sink()?;
    let tcp_b = tcp_sink()?;
    let udp_a = udp_sink()?;
    let udp_b = udp_sink()?;
    let e = Env { root: root_s.clone(), tcp_allowed: tcp_a, udp_allowed: udp_a };

    // ---- engine (same Config as the production host) ----------------------
    let mut config = Config::new();
    config.wasm_reference_types(true);
    config.wasm_bulk_memory(true);
    config.wasm_simd(true);
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, &guest)?;
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    let h = Harness {
        engine,
        component,
        linker,
        dirs: vec![
            (format!("{root_s}/ro"), "/ro".into()),
            (format!("{root_s}/rw"), "/rw".into()),
        ],
    };

    let base = Profile::Baseline;
    let pol_toml = bench_policy_toml(&e, 0, true);
    let pol = parse(&pol_toml)?;
    let nonet = parse(&nonet_policy_toml(&e))?;
    std::fs::write(out_path.with_file_name("bench_policy.toml"), &pol_toml)?;

    let a_tcp = format!("127.0.0.1:{tcp_a}");
    let b_tcp = format!("127.0.0.1:{tcp_b}");
    let a_udp = format!("127.0.0.1:{udp_a}");
    let b_udp = format!("127.0.0.1:{udp_b}");

    let v = |label: &str, pname: &str, p: &Profile, vs: Vec<(String, String)>, ex: Expect| Variant {
        label: label.into(),
        profile_name: pname.into(),
        profile: p.clone(),
        vars: vs,
        expect: ex,
        rules: None,
    };
    use Expect::*;
    let ro = || vars(&[("BENCH_DIR", "/ro".into())]);
    let rw = || vars(&[("BENCH_DIR", "/rw".into())]);

    let mut groups = vec![
        Group {
            name: "clock".into(), op: "clock".into(), iters: scale(200_000),
            variants: vec![
                v("no policy", "baseline", &base, vec![], Allow),
                v("policy", "policy", &pol, vec![], Allow),
            ],
        },
        Group {
            name: "env".into(), op: "env".into(), iters: scale(50_000),
            variants: vec![
                v("no policy", "baseline", &base, vec![], Allow),
                v("policy", "policy", &pol, vec![], Allow),
            ],
        },
        Group {
            name: "fs_stat".into(), op: "fs_stat".into(), iters: scale(50_000),
            variants: vec![
                v("no policy", "baseline", &base, ro(), Allow),
                v("policy (readonly dir)", "policy", &pol, ro(), Allow),
            ],
        },
        Group {
            name: "fs_read".into(), op: "fs_read".into(), iters: scale(20_000),
            variants: vec![
                v("no policy", "baseline", &base, ro(), Allow),
                v("policy (readonly dir)", "policy", &pol, ro(), Allow),
            ],
        },
        Group {
            name: "fs_write".into(), op: "fs_write".into(), iters: scale(20_000),
            variants: vec![
                v("no policy", "baseline", &base, rw(), Allow),
                v("policy (mount dir)", "policy", &pol, rw(), Allow),
            ],
        },
        Group {
            name: "fs_open_write".into(), op: "fs_open_write".into(), iters: scale(20_000),
            variants: vec![
                v("no policy", "baseline", &base, ro(), Allow),
                v("policy: mount dir", "policy", &pol, rw(), Allow),
                v("policy: readonly dir → denied", "policy", &pol, ro(), Deny),
                v(
                    "policy: ../ escape → denied (sandbox)",
                    "policy",
                    &pol,
                    vars(&[("BENCH_DIR", "/rw".into()), ("BENCH_FILE", "../secret.bin".into())]),
                    Deny,
                ),
            ],
        },
        Group {
            name: "tcp_create".into(), op: "tcp_create".into(), iters: scale(20_000),
            variants: vec![
                v("no policy", "baseline", &base, vec![], Allow),
                v("policy", "policy", &pol, vec![], Allow),
                v("policy w/o tcp rules → denied", "nonet", &nonet, vec![], Deny),
            ],
        },
        Group {
            name: "tcp_bind".into(), op: "tcp_bind".into(), iters: scale(10_000),
            variants: vec![
                v("no policy", "baseline", &base, vars(&[("BENCH_ADDR", "127.0.0.1:0".into())]), Allow),
                v("policy: allowed addr", "policy", &pol, vars(&[("BENCH_ADDR", "127.0.0.1:0".into())]), Allow),
                v("policy: denied addr", "policy", &pol, vars(&[("BENCH_ADDR", "127.0.0.2:0".into())]), Deny),
            ],
        },
        Group {
            name: "tcp_connect".into(), op: "tcp_connect".into(), iters: scale(2_000),
            variants: vec![
                v("no policy", "baseline", &base, vars(&[("BENCH_ADDR", a_tcp.clone())]), Allow),
                v("policy: allowed peer", "policy", &pol, vars(&[("BENCH_ADDR", a_tcp.clone())]), Allow),
                v("policy: denied peer", "policy", &pol, vars(&[("BENCH_ADDR", b_tcp.clone())]), Deny),
                v("policy w/o tcp rules → denied", "nonet", &nonet, vars(&[("BENCH_ADDR", b_tcp.clone())]), Deny),
            ],
        },
        Group {
            name: "udp_send".into(), op: "udp_send".into(), iters: scale(50_000),
            variants: vec![
                v("no policy", "baseline", &base, vars(&[("BENCH_ADDR", a_udp.clone())]), Allow),
                v("policy: allowed peer", "policy", &pol, vars(&[("BENCH_ADDR", a_udp.clone())]), Allow),
                v("policy: denied peer", "policy", &pol, vars(&[("BENCH_ADDR", b_udp.clone())]), Deny),
            ],
        },
        Group {
            name: "dns".into(), op: "dns".into(), iters: scale(5_000),
            variants: vec![
                v("no policy", "baseline", &base, vec![], Allow),
                v("policy: lookup allowed", "policy", &pol, vec![], Allow),
                v("policy: lookup off → denied", "nonet", &nonet, vec![], Deny),
            ],
        },
    ];

    // ---- rule-count scaling ---------------------------------------------
    // All rule counts and the no-policy reference are variants of ONE group so
    // they are sampled round-robin (drift-robust comparison across N).
    let rule_counts: &[usize] = if quick { &[0, 100, 1000] } else { &[0, 10, 100, 1_000, 10_000] };
    let mut udp_vs = vec![v("no policy", "baseline", &base, vars(&[("BENCH_ADDR", a_udp.clone())]), Allow)];
    let mut tcp_vs = vec![v("no policy", "baseline", &base, vars(&[("BENCH_ADDR", a_tcp.clone())]), Allow)];
    for &n in rule_counts {
        let p = parse(&bench_policy_toml(&e, n, true))?;
        let pname = format!("policy+{n}");
        let with = |mut x: Variant| { x.rules = Some(n); x };
        udp_vs.push(with(v("allowed (matching rule last)", &pname, &p, vars(&[("BENCH_ADDR", a_udp.clone())]), Allow)));
        udp_vs.push(with(v("denied (scans all rules)", &pname, &p, vars(&[("BENCH_ADDR", b_udp.clone())]), Deny)));
        tcp_vs.push(with(v("allowed (matching rule last)", &pname, &p, vars(&[("BENCH_ADDR", a_tcp.clone())]), Allow)));
        tcp_vs.push(with(v("denied (scans all rules)", &pname, &p, vars(&[("BENCH_ADDR", b_tcp.clone())]), Deny)));
    }
    groups.push(Group { name: "scale_udp_send".into(), op: "udp_send".into(), iters: scale(20_000), variants: udp_vs });
    groups.push(Group { name: "scale_tcp_connect".into(), op: "tcp_connect".into(), iters: scale(2_000), variants: tcp_vs });

    if let Some(o) = &only {
        groups.retain(|g| g.name.contains(o.as_str()));
    }

    // ---- run ------------------------------------------------------------
    let mut results = Vec::new();
    for g in &groups {
        let common = |extra: &[(String, String)], mode: &str, iters: u64| {
            let mut vs = vars(&[
                ("BENCH_OP", g.op.clone()),
                ("BENCH_ITERS", iters.to_string()),
                ("BENCH_WARMUP", (iters / 10).max(10).to_string()),
                ("BENCH_MODE", mode.into()),
            ]);
            vs.extend_from_slice(extra);
            vs
        };
        let mut per: Vec<Vec<f64>> = vec![Vec::new(); g.variants.len()];
        let mut last: Vec<Value> = vec![Value::Null; g.variants.len()];
        // Round-robin over variants so frequency/thermal drift hits all equally.
        for _ in 0..samples {
            for (i, var) in g.variants.iter().enumerate() {
                let r = h.run(&var.profile, &common(&var.vars, "throughput", g.iters)).await?;
                let total = r.out["total_ns"].as_f64().unwrap();
                per[i].push(total / g.iters as f64);
                last[i] = r.out;
            }
        }
        for (i, var) in g.variants.iter().enumerate() {
            let lat_iters = g.iters.min(20_000);
            let lat = h.run(&var.profile, &common(&var.vars, "latency", lat_iters)).await?;
            let out = &last[i];
            let ok = out["ok"].as_u64().unwrap();
            let valid = match var.expect {
                Expect::Allow => ok == g.iters,
                Expect::Deny => ok == 0,
            };
            let mut sorted = per[i].clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let med = sorted[sorted.len() / 2];
            println!(
                "{:<18} {:<8} {:<42} {:>10.1} ns/op {:>12.0} req/s  {}  errors={}",
                g.name,
                var.rules.map(|r| format!("r={r}")).unwrap_or_default(),
                var.label,
                med,
                1e9 / med,
                if valid { "ok " } else { "INVALID" },
                out["errors"]
            );
            results.push(VariantResult {
                group: g.name.clone(),
                op: g.op.clone(),
                label: var.label.clone(),
                profile: var.profile_name.clone(),
                expect: var.expect,
                rules: var.rules,
                iters: g.iters,
                ns_per_op: per[i].clone(),
                latency: lat.out["lat"].clone(),
                errors: out["errors"].clone(),
                valid,
            });
        }
    }

    // ---- lifecycle: per-task cost of applying a policy -------------------
    let mut lifecycle = Vec::new();
    if only.as_deref().is_none_or(|o| "lifecycle".contains(o)) {
        let n_runs = if quick { 30 } else { 300 };
        let cases: Vec<(String, usize, Option<String>)> = vec![
            ("baseline".into(), 0, None),
            ("policy".into(), 2, Some(pol_toml.clone())),
            ("policy+100".into(), 102, Some(bench_policy_toml(&e, 100, true))),
            ("policy+1000".into(), 1002, Some(bench_policy_toml(&e, 1000, true))),
        ];
        let lc_vars = vars(&[
            ("BENCH_OP", "clock".into()),
            ("BENCH_ITERS", "1".into()),
            ("BENCH_WARMUP", "0".into()),
        ]);
        let mut acc: Vec<LifecycleResult> = cases
            .iter()
            .map(|(n, r, _)| LifecycleResult {
                profile: n.clone(),
                rules: *r,
                parse_ns: vec![],
                build_ctx_ns: vec![],
                instantiate_ns: vec![],
                run_ns: vec![],
            })
            .collect();
        for _ in 0..n_runs {
            for (i, (_, _, toml)) in cases.iter().enumerate() {
                let (profile, parse_ns) = match toml {
                    None => (Profile::Baseline, 0.0),
                    Some(t) => {
                        let t0 = Instant::now();
                        let p = WasiSecurity::from_toml(t)?;
                        (Profile::Policy(Box::new(p)), t0.elapsed().as_nanos() as f64)
                    }
                };
                let r = h.run(&profile, &lc_vars).await?;
                acc[i].parse_ns.push(parse_ns);
                acc[i].build_ctx_ns.push(r.build_ns);
                acc[i].instantiate_ns.push(r.inst_ns);
                acc[i].run_ns.push(r.run_ns);
            }
        }
        for l in &acc {
            let med = |v: &Vec<f64>| {
                let mut s = v.clone();
                s.sort_by(|a, b| a.partial_cmp(b).unwrap());
                s[s.len() / 2]
            };
            println!(
                "lifecycle {:<12} parse {:>9.0} ns  build {:>9.0} ns  instantiate {:>9.0} ns  run {:>9.0} ns",
                l.profile,
                med(&l.parse_ns),
                med(&l.build_ctx_ns),
                med(&l.instantiate_ns),
                med(&l.run_ns)
            );
        }
        lifecycle = acc;
    }

    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("model name")).map(|l| l.split(':').nth(1).unwrap().trim().to_string()))
        .unwrap_or_default();
    let mut kernel = String::new();
    let _ = std::fs::File::open("/proc/sys/kernel/osrelease").and_then(|mut f| f.read_to_string(&mut kernel));
    let meta = serde_json::json!({
        "cpu": cpu,
        "kernel": kernel.trim(),
        "samples": samples,
        "quick": quick,
        "wasmtime": "50",
        "guest_target": "wasm32-wasip2",
        "timestamp_unix": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
    });
    let out = Output { meta, results, lifecycle };
    std::fs::write(&out_path, serde_json::to_string_pretty(&out)?)?;
    let _ = std::fs::remove_dir_all(&root);
    let _: SocketAddr = a_tcp.parse()?;
    println!("wrote {}", out_path.display());
    Ok(())
}
