//! Host-side micro-benchmarks of the policy engine itself (no guest involved).

use std::future::Future;
use std::hint::black_box;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use elastic_wasi_security::WasiSecurity;
use wasi_security_bench::*;
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::sockets::SocketAddrUse;

const RULES: &[usize] = &[0, 10, 100, 1_000, 10_000];

fn fixture() -> Env {
    let root = std::env::temp_dir().join("wasi-sec-microbench");
    std::fs::create_dir_all(root.join("ro")).unwrap();
    std::fs::create_dir_all(root.join("rw")).unwrap();
    Env { root: root.to_string_lossy().into(), tcp_allowed: 5432, udp_allowed: 5353 }
}

fn bench_parse(c: &mut Criterion) {
    let e = fixture();
    let mut g = c.benchmark_group("parse_policy");
    let example = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/benches/example_policy.toml"
    ))
    .unwrap();
    g.bench_function("examples/policy.toml", |b| {
        b.iter(|| WasiSecurity::from_toml(black_box(&example)).unwrap())
    });
    for &n in RULES {
        let toml = bench_policy_toml(&e, n, true);
        // bind + connect rules actually in the file
        let total = 2 * n + 3;
        g.throughput(Throughput::Elements(total as u64));
        g.bench_with_input(BenchmarkId::new("rules", total), &toml, |b, t| {
            b.iter(|| WasiSecurity::from_toml(black_box(t)).unwrap())
        });
    }
    g.finish();
}

fn bench_decision(c: &mut Criterion) {
    let e = fixture();
    let allowed_udp: SocketAddr = format!("127.0.0.1:{}", e.udp_allowed).parse().unwrap();
    let allowed_tcp: SocketAddr = format!("127.0.0.1:{}", e.tcp_allowed).parse().unwrap();
    let denied: SocketAddr = "192.168.1.1:9".parse().unwrap();
    let implicit: SocketAddr = "0.0.0.0:0".parse().unwrap();

    let mut g = c.benchmark_group("allows_socket");
    for &n in RULES {
        let p = WasiSecurity::from_toml(&bench_policy_toml(&e, n, true)).unwrap();
        // first-rule allow: matching rule comes first
        let first = WasiSecurity::from_toml(&format!(
            "[network]\nconnect = [\"udp://127.0.0.1:{}\"{}]\n",
            e.udp_allowed,
            (0..n).map(|i| format!(", \"udp://10.0.{}.{}:1\"", (i >> 8) & 0xff, i & 0xff)).collect::<String>()
        ))
        .unwrap();
        g.bench_with_input(BenchmarkId::new("udp_send/allow_first_rule", n), &first, |b, p| {
            b.iter(|| assert!(p.allows_socket(black_box(allowed_udp), SocketAddrUse::UdpSend)))
        });
        g.bench_with_input(BenchmarkId::new("udp_send/allow_last_rule", n), &p, |b, p| {
            b.iter(|| assert!(p.allows_socket(black_box(allowed_udp), SocketAddrUse::UdpSend)))
        });
        g.bench_with_input(BenchmarkId::new("udp_send/deny", n), &p, |b, p| {
            b.iter(|| assert!(!p.allows_socket(black_box(denied), SocketAddrUse::UdpSend)))
        });
        g.bench_with_input(BenchmarkId::new("tcp_connect/allow_last_rule", n), &p, |b, p| {
            b.iter(|| assert!(p.allows_socket(black_box(allowed_tcp), SocketAddrUse::TcpConnect)))
        });
        g.bench_with_input(BenchmarkId::new("tcp_connect/deny", n), &p, |b, p| {
            b.iter(|| assert!(!p.allows_socket(black_box(denied), SocketAddrUse::TcpConnect)))
        });
        g.bench_with_input(BenchmarkId::new("tcp_bind/implicit_probe", n), &p, |b, p| {
            b.iter(|| assert!(p.allows_socket(black_box(implicit), SocketAddrUse::TcpBind)))
        });
        g.bench_with_input(BenchmarkId::new("tcp_accept/unpoliced", n), &p, |b, p| {
            b.iter(|| assert!(p.allows_socket(black_box(denied), SocketAddrUse::TcpAccept)))
        });
    }
    g.finish();
}

type Check = dyn Fn(SocketAddr, SocketAddrUse) -> Pin<Box<dyn Future<Output = bool> + Send + Sync>>
    + Send
    + Sync;

/// The exact closure the production host hands to `socket_addr_check`, polled the way
/// wasmtime does (box the future, poll once; it is always immediately ready).
fn bench_check_callback(c: &mut Criterion) {
    let e = fixture();
    let mut g = c.benchmark_group("socket_addr_check_callback");
    let waker = Waker::noop();
    let run = |f: &Check, a: SocketAddr, u: SocketAddrUse| -> bool {
        let mut fut = f(a, u);
        match fut.as_mut().poll(&mut Context::from_waker(waker)) {
            Poll::Ready(v) => v,
            Poll::Pending => unreachable!(),
        }
    };
    let allowed: SocketAddr = format!("127.0.0.1:{}", e.udp_allowed).parse().unwrap();
    let denied: SocketAddr = "192.168.1.1:9".parse().unwrap();

    let inherit: Box<Check> = Box::new(|_, _| Box::pin(async { true }));
    g.bench_function("inherit_network (no policy)", |b| {
        b.iter(|| run(&*inherit, black_box(allowed), SocketAddrUse::UdpSend))
    });
    for &n in &[0usize, 1_000] {
        let policy = Arc::new(WasiSecurity::from_toml(&bench_policy_toml(&e, n, true)).unwrap());
        let cb: Box<Check> = Box::new(move |addr, use_| {
            let policy = policy.clone();
            Box::pin(async move { policy.allows_socket(addr, use_) })
        });
        g.bench_function(BenchmarkId::new("policy allow", n), |b| {
            b.iter(|| assert!(run(&*cb, black_box(allowed), SocketAddrUse::UdpSend)))
        });
        g.bench_function(BenchmarkId::new("policy deny", n), |b| {
            b.iter(|| assert!(!run(&*cb, black_box(denied), SocketAddrUse::UdpSend)))
        });
    }
    g.finish();
}

fn bench_build_ctx(c: &mut Criterion) {
    let e = fixture();
    let dirs = vec![
        (format!("{}/ro", e.root), "/ro".to_string()),
        (format!("{}/rw", e.root), "/rw".to_string()),
    ];
    let mut g = c.benchmark_group("build_wasi_ctx");
    g.bench_function("no policy (baseline)", |b| {
        b.iter(|| {
            let mut w = WasiCtxBuilder::new();
            configure_baseline(&mut w, [("K", "V")], &dirs).unwrap();
            black_box(w.build())
        })
    });
    for &n in &[0usize, 1_000] {
        let toml = bench_policy_toml(&e, n, true);
        let p = WasiSecurity::from_toml(&toml).unwrap();
        g.bench_function(BenchmarkId::new("policy (pre-parsed)", n), |b| {
            b.iter(|| {
                let mut w = WasiCtxBuilder::new();
                configure_wasi(&mut w, [("K", "V")], &[], Some(&p)).unwrap();
                black_box(w.build())
            })
        });
        g.bench_function(BenchmarkId::new("policy (parse + build)", n), |b| {
            b.iter(|| {
                let p = WasiSecurity::from_toml(&toml).unwrap();
                let mut w = WasiCtxBuilder::new();
                configure_wasi(&mut w, [("K", "V")], &[], Some(&p)).unwrap();
                black_box(w.build())
            })
        });
    }
    g.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(50)
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(2));
    targets = bench_parse, bench_decision, bench_check_callback, bench_build_ctx
}
criterion_main!(benches);
