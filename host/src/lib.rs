//! Shared pieces of the wasi-security benchmark suite.
//!
//! The `elastic-wasi-security` crate only parses a policy and decides socket
//! accesses; the *host* turns a [`WasiSecurity`] into a [`WasiCtx`]. To
//! benchmark what production does, [`configure_wasi`] is a copy of the
//! production host's `configure_wasi` (which pins `elastic-wasi-security` at
//! rev ee83c55), minus logging.

use std::sync::Arc;

use anyhow::Result;
use elastic_wasi_security::WasiSecurity;
use wasmtime::component::ResourceTable;
use wasmtime_wasi::{FsPerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

pub struct StoreData {
    pub wasi: WasiCtx,
    pub table: ResourceTable,
}

impl WasiView for StoreData {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}

/// Mirror of the production host's `merge_env`: task env first, the policy env wins on conflict.
fn merge_env<'a>(
    env: impl IntoIterator<Item = (&'a str, &'a str)>,
    policy_env: Option<&'a std::collections::HashMap<String, String>>,
) -> Vec<(&'a str, &'a str)> {
    let mut merged: Vec<(&str, &str)> = Vec::new();
    let mut upsert = |k: &'a str, v: &'a str| match merged.iter_mut().find(|(mk, _)| *mk == k) {
        Some(slot) => slot.1 = v,
        None => merged.push((k, v)),
    };
    for (k, v) in env {
        upsert(k, v);
    }
    for (k, v) in policy_env.into_iter().flatten() {
        upsert(k.as_str(), v.as_str());
    }
    merged
}

/// Production mapping of a policy onto a WASI context (copied from the production host).
pub fn configure_wasi<'a>(
    builder: &mut WasiCtxBuilder,
    env: impl IntoIterator<Item = (&'a str, &'a str)>,
    global_preopens: &[String],
    policy: Option<&'a WasiSecurity>,
) -> Result<()> {
    for (key, value) in merge_env(env, policy.and_then(|p| p.env.as_ref())) {
        builder.env(key, value);
    }

    let Some(policy) = policy else {
        for dir in global_preopens {
            builder.preopened_dir(dir, dir, FsPerms::ReadWrite)?;
        }
        return Ok(());
    };

    if let Some(arguments) = &policy.arguments {
        builder.args(arguments);
    }
    for (host, guest) in &policy.storage_readonly {
        builder.preopened_dir(host, guest, FsPerms::ReadOnly)?;
    }
    for (host, guest) in &policy.storage_mount {
        builder.preopened_dir(host, guest, FsPerms::ReadWrite)?;
    }

    let check_policy = Arc::new(policy.clone());
    builder.socket_addr_check(move |addr, use_| {
        let policy = check_policy.clone();
        Box::pin(async move { policy.allows_socket(addr, use_) })
    });
    builder.allow_tcp(policy.uses_tcp());
    builder.allow_udp(policy.uses_udp());
    builder.allow_ip_name_lookup(policy.allow_ip_name_lookup);
    Ok(())
}

/// "No policy" reference: the same directories, mounted read-write, and the
/// network fully open (what `wasmtime run -S inherit-network,allow-ip-name-lookup`
/// gives you). This measures the raw cost of each WASI request.
pub fn configure_baseline<'a>(
    builder: &mut WasiCtxBuilder,
    env: impl IntoIterator<Item = (&'a str, &'a str)>,
    dirs: &[(String, String)],
) -> Result<()> {
    for (k, v) in env {
        builder.env(k, v);
    }
    for (host, guest) in dirs {
        builder.preopened_dir(host, guest, FsPerms::ReadWrite)?;
    }
    builder.inherit_network();
    builder.allow_tcp(true);
    builder.allow_udp(true);
    builder.allow_ip_name_lookup(true);
    Ok(())
}

/// Addresses and paths the generated policies refer to.
#[derive(Clone, Debug)]
pub struct Env {
    pub root: String,
    pub tcp_allowed: u16,
    pub udp_allowed: u16,
}

/// The main benchmark policy: one read-only dir, one mount, TCP bind on
/// 127.0.0.1 (any port), TCP+UDP connect to one allowed endpoint each, DNS on.
/// `filler` prepends that many non-matching rules to `bind` and `connect`, so
/// the matching rule is the *last* one scanned (worst case for an allow) and a
/// denied address scans `filler + n` rules.
pub fn bench_policy_toml(e: &Env, filler: usize, dns: bool) -> String {
    let fill = |i: usize, scheme: &str| {
        format!("\"{scheme}10.{}.{}.{}:{}\"", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff, 1000 + (i % 60000))
    };
    let mut connect: Vec<String> = (0..filler)
        .map(|i| fill(i, if i % 2 == 0 { "tcp://" } else { "udp://" }))
        .collect();
    connect.push(format!("\"tcp://127.0.0.1:{}\"", e.tcp_allowed));
    connect.push(format!("\"udp://127.0.0.1:{}\"", e.udp_allowed));
    let mut bind: Vec<String> = (0..filler).map(|i| fill(i, "tcp://")).collect();
    bind.push("\"tcp://127.0.0.1:0\"".into());
    format!(
        r#"version = "0.0.1"
arguments = ["--bench"]

[env]
LOG_LEVEL = "debug"

[storage]
readonly = ["{root}/ro::/ro"]
mount = ["{root}/rw::/rw"]

[network]
allow_ip_name_lookup = {dns}
bind = [{bind}]
connect = [{connect}]
"#,
        root = e.root,
        bind = bind.join(", "),
        connect = connect.join(", "),
    )
}

/// Same storage, but no network rules and DNS off: TCP/UDP are switched off
/// wholesale (`allow_tcp(false)`), which is what an empty `[network]` gives.
pub fn nonet_policy_toml(e: &Env) -> String {
    format!(
        r#"version = "0.0.1"

[storage]
readonly = ["{root}/ro::/ro"]
mount = ["{root}/rw::/rw"]

[network]
allow_ip_name_lookup = false
"#,
        root = e.root
    )
}
