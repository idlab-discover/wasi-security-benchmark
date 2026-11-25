//! Benchmark guest (wasm32-wasip2 command component).
//!
//! Each run executes ONE operation kind in a tight loop and reports how long it
//! took, measured with `wasi:clocks/monotonic-clock` from inside the guest so
//! instantiation is excluded. All WASI calls go through the raw `wasip2`
//! bindings (no wasi-libc in between), so one loop iteration == the WASI
//! request(s) listed next to each op below.
//!
//! Configuration comes from environment variables set by the host runner:
//!   BENCH_OP      operation name (see `run_once`)
//!   BENCH_ITERS   measured iterations
//!   BENCH_WARMUP  unmeasured warmup iterations
//!   BENCH_MODE    "throughput" (one clock read around the loop) or
//!                 "latency" (clock read around every op -> percentiles)
//!   BENCH_ADDR    ip:port target for socket ops
//!   BENCH_DIR     guest path of the preopen used by fs ops
//!   BENCH_FILE    file name (relative to BENCH_DIR) used by fs ops
//!   BENCH_NAME    host name for dns
//!
//! Output: a single JSON line on stdout.

use std::collections::BTreeMap;

use wasip2::clocks::monotonic_clock;
use wasip2::filesystem::preopens;
use wasip2::filesystem::types::{Descriptor, DescriptorFlags, OpenFlags, PathFlags};
use wasip2::sockets::instance_network::instance_network;
use wasip2::sockets::ip_name_lookup;
use wasip2::sockets::network::{
    ErrorCode, IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, Network,
};
use wasip2::sockets::tcp_create_socket::create_tcp_socket;
use wasip2::sockets::udp::{OutgoingDatagram, OutgoingDatagramStream, UdpSocket};
use wasip2::sockets::udp_create_socket::create_udp_socket;

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn parse_v4(s: &str) -> IpSocketAddress {
    let addr: std::net::SocketAddrV4 = s.parse().expect("BENCH_ADDR must be ipv4:port");
    let o = addr.ip().octets();
    IpSocketAddress::Ipv4(Ipv4SocketAddress {
        port: addr.port(),
        address: (o[0], o[1], o[2], o[3]),
    })
}

/// Everything an op needs, prepared once before the loop.
struct Ctx {
    op: String,
    net: Network,
    addr: Option<IpSocketAddress>,
    dir: Option<Descriptor>,
    file: String,
    name: String,
    payload: Vec<u8>,
    // UDP: socket + outgoing stream are created once, each iteration sends one datagram.
    udp: Option<(UdpSocket, OutgoingDatagramStream)>,
}

fn sock_err(e: ErrorCode) -> String {
    e.name().to_string()
}

fn fs_err(e: wasip2::filesystem::types::ErrorCode) -> String {
    e.name().to_string()
}

/// One iteration of the selected op. `Ok(())` = WASI granted the request.
fn run_once(c: &Ctx) -> Result<(), String> {
    match c.op.as_str() {
        // --- unpoliced reference calls -------------------------------------
        // monotonic-clock.now: cheapest possible host call (call overhead floor).
        "clock" => {
            std::hint::black_box(monotonic_clock::now());
            Ok(())
        }
        // environment.get-environment
        "env" => {
            std::hint::black_box(wasip2::cli::environment::get_environment());
            Ok(())
        }

        // --- filesystem ------------------------------------------------------
        // descriptor.stat-at
        "fs_stat" => {
            let d = c.dir.as_ref().ok_or("no-preopen")?;
            d.stat_at(PathFlags::empty(), &c.file).map_err(fs_err)?;
            Ok(())
        }
        // descriptor.open-at(read) + descriptor.read(4 KiB) + drop
        "fs_read" => {
            let d = c.dir.as_ref().ok_or("no-preopen")?;
            let f = d
                .open_at(PathFlags::empty(), &c.file, OpenFlags::empty(), DescriptorFlags::READ)
                .map_err(fs_err)?;
            let (buf, _) = f.read(4096, 0).map_err(fs_err)?;
            std::hint::black_box(buf);
            Ok(())
        }
        // descriptor.open-at(write) + descriptor.write(4 KiB) + drop
        "fs_write" => {
            let d = c.dir.as_ref().ok_or("no-preopen")?;
            let f = d
                .open_at(PathFlags::empty(), &c.file, OpenFlags::empty(), DescriptorFlags::WRITE)
                .map_err(fs_err)?;
            f.write(&c.payload, 0).map_err(fs_err)?;
            Ok(())
        }
        // descriptor.open-at with a write flag only (the request a read-only mount rejects)
        "fs_open_write" => {
            let d = c.dir.as_ref().ok_or("no-preopen")?;
            let f = d
                .open_at(PathFlags::empty(), &c.file, OpenFlags::empty(), DescriptorFlags::WRITE)
                .map_err(fs_err)?;
            drop(f);
            Ok(())
        }

        // --- tcp -------------------------------------------------------------
        // tcp-create-socket.create-tcp-socket + drop
        "tcp_create" => {
            let s = create_tcp_socket(IpAddressFamily::Ipv4).map_err(sock_err)?;
            drop(s);
            Ok(())
        }
        // create + start-bind + finish-bind + drop
        "tcp_bind" => {
            let s = create_tcp_socket(IpAddressFamily::Ipv4).map_err(sock_err)?;
            s.start_bind(&c.net, c.addr.unwrap()).map_err(sock_err)?;
            s.finish_bind().map_err(sock_err)?;
            Ok(())
        }
        // create + start-connect + poll + finish-connect + drop (full loopback handshake)
        "tcp_connect" => {
            let s = create_tcp_socket(IpAddressFamily::Ipv4).map_err(sock_err)?;
            s.start_connect(&c.net, c.addr.unwrap()).map_err(sock_err)?;
            let p = s.subscribe();
            loop {
                match s.finish_connect() {
                    Ok((i, o)) => {
                        drop(i);
                        drop(o);
                        return Ok(());
                    }
                    Err(ErrorCode::WouldBlock) => p.block(),
                    Err(e) => return Err(sock_err(e)),
                }
            }
        }

        // --- udp -------------------------------------------------------------
        // outgoing-datagram-stream.check-send + send(1 x 64 B datagram, explicit remote)
        "udp_send" => {
            let (_, out) = c.udp.as_ref().ok_or("udp-setup-failed")?;
            loop {
                match out.check_send().map_err(sock_err)? {
                    0 => out.subscribe().block(),
                    _ => break,
                }
            }
            let dg = OutgoingDatagram {
                data: c.payload[..64].to_vec(),
                remote_address: c.addr,
            };
            match out.send(&[dg]).map_err(sock_err)? {
                1 => Ok(()),
                n => Err(format!("sent-{n}")),
            }
        }

        // --- dns -------------------------------------------------------------
        // ip-name-lookup.resolve-addresses + drain resolve-next-address
        "dns" => {
            let stream = ip_name_lookup::resolve_addresses(&c.net, &c.name).map_err(sock_err)?;
            let p = stream.subscribe();
            loop {
                match stream.resolve_next_address() {
                    Ok(Some(a)) => {
                        std::hint::black_box(a);
                    }
                    Ok(None) => return Ok(()),
                    Err(ErrorCode::WouldBlock) => p.block(),
                    Err(e) => return Err(sock_err(e)),
                }
            }
        }
        other => panic!("unknown BENCH_OP {other}"),
    }
}

fn setup_udp(net: &Network) -> Result<(UdpSocket, OutgoingDatagramStream), String> {
    let s = create_udp_socket(IpAddressFamily::Ipv4).map_err(sock_err)?;
    // Wildcard bind (0.0.0.0:0): the "implicit bind" the policy admits when it
    // has any UDP connect rule.
    let any = IpSocketAddress::Ipv4(Ipv4SocketAddress { port: 0, address: (0, 0, 0, 0) });
    s.start_bind(net, any).map_err(sock_err)?;
    let p = s.subscribe();
    loop {
        match s.finish_bind() {
            Ok(()) => break,
            Err(ErrorCode::WouldBlock) => p.block(),
            Err(e) => return Err(sock_err(e)),
        }
    }
    let (_in, out) = s.stream(None).map_err(sock_err)?;
    drop(_in);
    Ok((s, out))
}

fn main() {
    let op = env("BENCH_OP").expect("BENCH_OP");
    let iters: u64 = env("BENCH_ITERS").map(|v| v.parse().unwrap()).unwrap_or(1000);
    let warmup: u64 = env("BENCH_WARMUP").map(|v| v.parse().unwrap()).unwrap_or(100);
    let latency_mode = env("BENCH_MODE").as_deref() == Some("latency");

    let net = instance_network();
    let addr = env("BENCH_ADDR").map(|a| parse_v4(&a));
    let dir = env("BENCH_DIR").and_then(|want| {
        preopens::get_directories()
            .into_iter()
            .find(|(_, p)| *p == want)
            .map(|(d, _)| d)
    });

    let mut setup_error = None;
    let udp = if op == "udp_send" {
        match setup_udp(&net) {
            Ok(u) => Some(u),
            Err(e) => {
                setup_error = Some(e);
                None
            }
        }
    } else {
        None
    };

    let c = Ctx {
        op: op.clone(),
        net,
        addr,
        dir,
        file: env("BENCH_FILE").unwrap_or_else(|| "file.bin".into()),
        name: env("BENCH_NAME").unwrap_or_else(|| "localhost".into()),
        payload: vec![0xA5; 4096],
        udp,
    };

    for _ in 0..warmup {
        let _ = std::hint::black_box(run_once(&c));
    }

    let mut ok = 0u64;
    let mut errs: BTreeMap<String, u64> = BTreeMap::new();
    let mut lat: Vec<u64> = Vec::new();

    let t0 = monotonic_clock::now();
    if latency_mode {
        lat.reserve(iters as usize);
        for _ in 0..iters {
            let a = monotonic_clock::now();
            let r = run_once(&c);
            let b = monotonic_clock::now();
            lat.push(b - a);
            match r {
                Ok(()) => ok += 1,
                Err(e) => *errs.entry(e).or_default() += 1,
            }
        }
    } else {
        for _ in 0..iters {
            match run_once(&c) {
                Ok(()) => ok += 1,
                Err(e) => *errs.entry(e).or_default() += 1,
            }
        }
    }
    let total = monotonic_clock::now() - t0;

    // WASI child resources must be dropped before their parent socket.
    if let Some((sock, out)) = c.udp {
        drop(out);
        drop(sock);
    }

    // Hand-rolled JSON (keeps the guest dependency-free).
    let errs_json = errs
        .iter()
        .map(|(k, v)| format!("\"{k}\":{v}"))
        .collect::<Vec<_>>()
        .join(",");
    let lat_json = if latency_mode {
        lat.sort_unstable();
        let pct = |p: f64| lat[((lat.len() as f64 - 1.0) * p).round() as usize];
        format!(
            ",\"lat\":{{\"p50\":{},\"p90\":{},\"p99\":{},\"p999\":{},\"min\":{},\"max\":{}}}",
            pct(0.5),
            pct(0.9),
            pct(0.99),
            pct(0.999),
            lat[0],
            lat[lat.len() - 1]
        )
    } else {
        String::new()
    };
    let setup_json = setup_error
        .map(|e| format!(",\"setup_error\":\"{e}\""))
        .unwrap_or_default();
    println!(
        "{{\"op\":\"{op}\",\"iters\":{iters},\"total_ns\":{total},\"ok\":{ok},\"errors\":{{{errs_json}}}{lat_json}{setup_json}}}"
    );
}
