//! RV5: attacks on the running system, end to end over temporary-directory sockets. Every test
//! states the secure behaviour, and 17 of the V tests fail on `9d50e23` here; V6, V14 and V14b
//! only measure, V7b guards the fix, and V7d's attack is weaker here than where it was found. The
//! D tests are the decisions the report left open.
//!
//! They take minutes, so they are `#[ignore]`d, and the eighth command of the CLAUDE.md §2 loop
//! runs them: `cargo test --release --test rv5_attacks -- --ignored --nocapture --test-threads=1`.
//! The numbers a test measures go to stderr.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr,
    clippy::as_conversions,
    clippy::too_many_lines,
    missing_docs
)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use pep_sidecar::jcs::{self, JcsValue, ParseOptions};
use pep_sidecar::stubs::tool::sha256_hex;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// One attack at a time: the floods take every CPU, and other tests measure time.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The Week 1 tools, with the free `Data` argument (`/memo`) the plan names on `pay_invoice`
/// (P1), and notes up to 4 MiB.
const PINS: &str = r#"{"lockfile_version":1,"release_epoch":7,
  "stores":{"billing://invoices":{"case_insensitive":true},"notes://agent":{"case_insensitive":false}},
  "servers":{
    "a":{"endpoint":"unix:a","identity":"spiffe://tools/a","protocol_version":"2026-07-28",
      "discover":{"cacheScope":"public","capabilities":{"tools":{}},"resultType":"complete","supportedVersions":["2026-07-28"],"ttlMs":0},
      "tools":{
        "get_invoice":{"definition":{"name":"get_invoice","description":"Look up an invoice.","inputSchema":{"type":"object"}},
          "policy":{"effect":"read","args":[{"pointer":"/invoice_id","role":"store_key"}],"store_uri":"billing://invoices","sink_clearance":"secret",
            "output_label":{"conf":"internal","integ":"trusted"},"trusted_fields":["/structuredContent/amount_due_minor","/structuredContent/currency"],
            "max_result_bytes":65536,"max_result_nodes":1024}},
        "pay_invoice":{"definition":{"name":"pay_invoice","description":"Pay an invoice.","inputSchema":{"type":"object"}},
          "policy":{"effect":"mutating_financial","args":[{"pointer":"/invoice_id","role":"entity","kind":"invoice"},{"pointer":"/amount","role":"amount"},{"pointer":"/currency","role":"currency"},{"pointer":"/memo","role":"data"}],
            "sink_clearance":"internal","output_label":{"conf":"internal","integ":"untrusted_external"},
            "amount_binding":{"lookup_tool":"get_invoice","entity_arg_pointer":"/invoice_id","lookup_entity_pointer":"/invoice_id",
              "result_amount_pointer":"/structuredContent/amount_due_minor","result_currency_pointer":"/structuredContent/currency"},
            "max_result_bytes":65536,"max_result_nodes":1024}}}},
    "b":{"endpoint":"unix:b","identity":"spiffe://tools/b","protocol_version":"2026-07-28",
      "discover":{"cacheScope":"public","capabilities":{"tools":{}},"resultType":"complete","supportedVersions":["2026-07-28"],"ttlMs":0},
      "tools":{
        "save_note":{"definition":{"name":"save_note","inputSchema":{"type":"object"}},
          "policy":{"effect":"mutating_internal","args":[{"pointer":"/key","role":"store_key"},{"pointer":"/text","role":"store_write"}],"store_uri":"notes://agent",
            "sink_clearance":"secret","output_label":{"conf":"internal","integ":"untrusted_external"},"max_result_bytes":4194304,"max_result_nodes":1024}},
        "get_note":{"definition":{"name":"get_note","inputSchema":{"type":"object"}},
          "policy":{"effect":"read","args":[{"pointer":"/key","role":"store_key"}],"store_uri":"notes://agent",
            "sink_clearance":"secret","output_label":{"conf":"internal","integ":"untrusted_external"},"max_result_bytes":4194304,"max_result_nodes":1024}}}}}}"#;

const INVOICES: &str = r#"{"INV-1001":{"amount_due_minor":30000,"currency":"USD","status":"executed"},
    "INV-2002":{"amount_due_minor":60000,"currency":"USD","status":"executed"},
    "INV-3003":{"amount_due_minor":30000,"currency":"USD","status":"declined"},
    "INV-4004":{"amount_due_minor":30000,"currency":"USD","status":"pending"}}"#;

#[derive(Clone)]
struct Options {
    connections: usize,
    log_max_bytes: u64,
    read_timeout_ms: u64,
    call_burst: u32,
    call_rate: u32,
    broker_connections: usize,
    upstream_ms: u64,
    max_calls: u32,
    body_bytes: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            connections: 64,
            log_max_bytes: 1 << 20,
            read_timeout_ms: 5000,
            call_burst: 500,
            call_rate: 500,
            broker_connections: 16,
            upstream_ms: 2000,
            max_calls: 50,
            body_bytes: 1 << 20,
        }
    }
}

struct World {
    base: PathBuf,
    pins_text: String,
    options: Options,
    children: Vec<(&'static str, Child)>,
    pep: Option<Child>,
    _turn: MutexGuard<'static, ()>,
}

impl Drop for World {
    fn drop(&mut self) {
        for (_, child) in &mut self.children {
            drop(child.kill());
            drop(child.wait());
        }
        if let Some(pep) = &mut self.pep {
            drop(pep.kill());
            drop(pep.wait());
        }
        drop(fs::remove_dir_all(&self.base));
    }
}

fn ids() -> (u32, u32) {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let field = |name: &str| -> u32 {
        let line = status.lines().find(|line| line.starts_with(name)).unwrap();
        line.split_whitespace().nth(2).unwrap().parse().unwrap()
    };
    (field("Uid:"), field("Gid:"))
}

fn wait_for_socket(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while UnixStream::connect(path).is_err() {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("{} exited: {status}", path.display());
        }
        assert!(
            Instant::now() < deadline,
            "{} never came up",
            path.display()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn spawn(binary: &str, config: &Path) -> Child {
    Command::new(binary)
        .arg(config)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

impl World {
    fn new(options: Options) -> Self {
        let turn = one_at_a_time();
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!("pep-rv5-{}-{n}", std::process::id()));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let pins_text = PINS
            .replace(
                "unix:a",
                &format!("unix:{}/tool-a/tool.sock", base.display()),
            )
            .replace(
                "unix:b",
                &format!("unix:{}/tool-b/tool.sock", base.display()),
            );
        let world = Self {
            base,
            pins_text,
            options,
            children: Vec::new(),
            pep: None,
            _turn: turn,
        };
        world.write_files();
        world
    }

    fn path(&self, name: &str) -> PathBuf {
        self.base.join(name)
    }

    fn write_files(&self) {
        let (uid, gid) = ids();
        for (name, mode) in [
            ("pep", 0o750),
            ("ctl", 0o750),
            ("broker", 0o750),
            ("tool-a", 0o750),
            ("tool-b", 0o750),
            ("pub", 0o700),
            ("state", 0o700),
            ("logs", 0o700),
            ("secrets", 0o700),
        ] {
            let path = self.base.join(name);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        }
        fs::write(self.path("pins.json"), &self.pins_text).unwrap();
        for (server, credential) in [("a", "credential-a"), ("b", "credential-b")] {
            fs::write(
                self.path(&format!("secrets/verifier-{server}")),
                sha256_hex(credential.as_bytes()),
            )
            .unwrap();
            fs::write(self.path(&format!("secrets/cred-{server}")), credential).unwrap();
        }
        let p = |name: &str| self.path(name).display().to_string();
        for server in ["a", "b"] {
            fs::write(
                self.path(&format!("tool-{server}.json")),
                format!(
                    r#"{{"server_id":"{server}","listen":"unix:{}","verifier":"{}","pins":"{}","store":"{}","log":"{}","invoices":{INVOICES}}}"#,
                    p(&format!("tool-{server}/tool.sock")),
                    p(&format!("secrets/verifier-{server}")),
                    p("pins.json"),
                    p(&format!("state/dedupe-{server}.jsonl")),
                    p(&format!("logs/tool-{server}.jsonl")),
                ),
            )
            .unwrap();
        }
        let o = &self.options;
        fs::write(
            self.path("broker.json"),
            format!(
                r#"{{"socket":"{}","pep":{{"uid":{uid},"gid":{gid}}},"pep_key":"{}","pins":"{}",
                "routes":{{"a":{{"endpoint":"unix:{}","credential":"{}"}},"b":{{"endpoint":"unix:{}","credential":"{}"}}}},
                "replay_cache_entries":32768,"clock_skew_ms":2000,"connections":{},"upstream_timeout_ms":{},"log":"{}"}}"#,
                p("broker/broker.sock"),
                p("pub/call-proof.pub"),
                p("pins.json"),
                p("tool-a/tool.sock"),
                p("secrets/cred-a"),
                p("tool-b/tool.sock"),
                p("secrets/cred-b"),
                o.broker_connections,
                o.upstream_ms,
                p("logs/broker.jsonl"),
            ),
        )
        .unwrap();
        let pins = jcs::parse_with(self.pins_text.as_bytes(), &ParseOptions::definition())
            .unwrap()
            .value;
        let digest = jcs::digest_value(&pins);
        let intent = |kind: &str, ids: &str| {
            format!(
                r#"{{"release_epoch":7,"lockfile_digest":"{digest}","limits":{{"currency":"USD","per_call_max_minor":100000,"cumulative_max_minor":5000000,"max_calls":{},"step_up_over_minor":50000,"max_declines":3}},
                "entities":{{"kind":"{kind}","ids":{ids},"per_entity_max_uses":1}},"seq":"unconstrained"}}"#,
                o.max_calls
            )
        };
        let invoices = r#"["INV-1001","INV-2002","INV-3003","INV-4004"]"#;
        fs::write(
            self.path("pep.json"),
            format!(
                r#"{{"agent":{{"uid":{uid},"gid":{gid},"socket":"{}"}},"operator":{{"uid":{uid},"gid":{gid},"socket":"{}"}},
                "broker":{{"uid":{uid},"gid":{gid},"socket":"{}"}},"pep":{{"spiffe_id":"spiffe://corp.example/pep","pubkey_dir":"{}"}},
                "lockfile":{{"path":"/etc/pep/lockfile.dsse.json","min_accepted_epoch":7,"signers":[],"thresholds":{{}}}},
                "journal":{{"path":"{}","lock":"{}"}},"log":{{"path":"{}","max_bytes":{}}},
                "limits":{{"connections":{},"control_connections":4,"header_bytes":16384,"body_bytes":{},"read_timeout_ms":{},
                  "upstream_timeout_ms":{},"step_up_timeout_ms":10000,"episode_idle_ms":600000,"episodes":8,"call_burst":{},"call_rate_per_s":{},
                  "clock_skew_ms":2000,"replay_cache_entries":32768}},
                "intents":{{"pay1":{},"pay2":{},"notes":{}}},"pins":{}}}"#,
                p("pep/agent.sock"),
                p("ctl/ctl.sock"),
                p("broker/broker.sock"),
                p("pub"),
                p("state/journal.jsonl"),
                p("state/journal.lock"),
                p("logs/decisions.jsonl"),
                o.log_max_bytes,
                o.connections,
                o.body_bytes,
                o.read_timeout_ms,
                o.upstream_ms,
                o.call_burst,
                o.call_rate,
                intent("invoice", invoices),
                intent("invoice", invoices),
                intent("recipient", r#"["rcpt_A"]"#),
                self.pins_text,
            ),
        )
        .unwrap();
    }

    fn start(mut self) -> Self {
        for (server, name) in [("a", "tool-a"), ("b", "tool-b")] {
            let mut child = spawn(
                env!("CARGO_BIN_EXE_stub-tool"),
                &self.path(&format!("tool-{server}.json")),
            );
            wait_for_socket(&self.path(&format!("tool-{server}/tool.sock")), &mut child);
            self.children.push((name, child));
        }
        self.start_broker();
        self.start_pep();
        self
    }

    fn start_broker(&mut self) {
        let mut broker = spawn(env!("CARGO_BIN_EXE_stub-broker"), &self.path("broker.json"));
        wait_for_socket(&self.path("broker/broker.sock"), &mut broker);
        self.children.push(("broker", broker));
        let since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        thread::sleep(Duration::from_millis(
            1050 - u64::from(since_epoch.subsec_millis()),
        ));
    }

    fn kill(&mut self, name: &str) {
        let index = self
            .children
            .iter()
            .position(|(child, _)| *child == name)
            .unwrap();
        let (_, mut child) = self.children.remove(index);
        drop(child.kill());
        drop(child.wait());
    }

    /// The pid of a running stub.
    fn pid(&self, name: &str) -> u32 {
        self.children
            .iter()
            .find(|(child, _)| *child == name)
            .unwrap()
            .1
            .id()
    }

    fn start_pep(&mut self) {
        if let Some(mut old) = self.pep.take() {
            drop(old.kill());
            drop(old.wait());
        }
        let mut pep = spawn(env!("CARGO_BIN_EXE_pep-sidecar"), &self.path("pep.json"));
        let mut lines = Vec::new();
        let mut reader = BufReader::new(pep.stderr.take().unwrap());
        loop {
            let mut line = String::new();
            assert!(
                reader.read_line(&mut line).unwrap() > 0,
                "the PEP exited: {lines:?}"
            );
            lines.push(line.trim().to_owned());
            if line.contains("serving") {
                break;
            }
        }
        thread::spawn(move || {
            let mut rest = String::new();
            drop(reader.read_to_string(&mut rest));
        });
        self.pep = Some(pep);
    }

    fn pep_alive(&mut self) -> bool {
        matches!(self.pep.as_mut().unwrap().try_wait(), Ok(None))
    }

    fn operator(&self, request: &str) -> JcsValue {
        let output = Command::new(env!("CARGO_BIN_EXE_stub-operator"))
            .arg(self.path("ctl/ctl.sock"))
            .arg(request)
            .output()
            .unwrap();
        jcs::parse(String::from_utf8(output.stdout).unwrap().trim().as_bytes()).unwrap()
    }

    fn start_episode(&self, intent: &str) -> String {
        let started = self.operator(&format!(
            r#"{{"call":"start_episode","intent":"{intent}"}}"#
        ));
        started
            .pointer("/result/episode_token")
            .unwrap_or_else(|| panic!("{started:?}"))
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn call(&self, id: u64, tool: &str, arguments: &str, token: &str) -> JcsValue {
        call_at(&self.path("pep/agent.sock"), id, tool, arguments, token)
    }

    /// `log` up to its first NUL. The journal is preallocated, so its size says nothing, and its
    /// `reserve` and `outcome` records are queued, not waited for, so they can reach the file a
    /// moment after the reply: wait for it to stop growing.
    fn settled(&self, log: &str) -> String {
        let read = || {
            let text = fs::read_to_string(self.path(log)).unwrap_or_default();
            text.split('\0').next().unwrap_or_default().to_owned()
        };
        let mut seen = read();
        if !log.contains("journal") {
            return seen;
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(40));
            let now = read();
            if now == seen {
                break;
            }
            seen = now;
        }
        seen
    }

    fn lines(&self, log: &str) -> Vec<JcsValue> {
        self.settled(log)
            .lines()
            .map(|line| {
                jcs::parse_with(line.as_bytes(), &ParseOptions::definition())
                    .unwrap()
                    .value
            })
            .collect()
    }

    /// The results of the journal's payment outcomes.
    fn outcomes(&self) -> Vec<String> {
        self.lines("state/journal.jsonl")
            .iter()
            .filter_map(|line| {
                line.get("result")
                    .and_then(JcsValue::as_str)
                    .map(str::to_owned)
            })
            .collect()
    }

    fn executed_payments(&self) -> Vec<JcsValue> {
        self.lines("logs/tool-a.jsonl")
            .into_iter()
            .filter(|line| {
                line.get("tool").and_then(JcsValue::as_str) == Some("pay_invoice")
                    && line.get("executed").and_then(JcsValue::as_bool) == Some(true)
            })
            .collect()
    }
}

fn mcp_head(method: &str, name: Option<&str>, extra: &str, length: usize) -> String {
    let name = name.map_or_else(String::new, |name| format!("Mcp-Name: {name}\r\n"));
    format!(
        "POST /mcp HTTP/1.1\r\nHost: pep.local\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: {method}\r\n{name}{extra}Content-Length: {length}\r\n\r\n"
    )
}

fn meta(token: Option<&str>) -> String {
    let token_meta = token.map_or_else(String::new, |token| {
        format!(r#","dev.pep-sidecar/episode":"{token}""#)
    });
    format!(
        r#""_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{{}}{token_meta}}}"#
    )
}

fn raw_at(socket: &Path, request: &[u8]) -> (String, String) {
    let mut stream = UnixStream::connect(socket).unwrap();
    // The PEP may close at once, on a full pool.
    drop(stream.write_all(request));
    let mut out = String::new();
    drop(stream.read_to_string(&mut out));
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    (
        head.lines().next().unwrap_or_default().to_owned(),
        body.to_owned(),
    )
}

fn parse_reply(payload: &str) -> JcsValue {
    jcs::parse_with(payload.as_bytes(), &ParseOptions::definition())
        .unwrap_or_else(|error| panic!("{error}: {payload}"))
        .value
}

fn call_at(socket: &Path, id: u64, tool: &str, arguments: &str, token: &str) -> JcsValue {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments},{}}}}}"#,
        meta(Some(token))
    );
    let head = mcp_head("tools/call", Some(tool), "", body.len());
    let mut request = head.into_bytes();
    request.extend_from_slice(body.as_bytes());
    let (status, payload) = raw_at(socket, &request);
    assert!(status.starts_with("HTTP/1.1 200"), "{status}: {payload}");
    parse_reply(&payload)
}

fn list_at(socket: &Path, id: u64, token: &str) -> Option<JcsValue> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/list","params":{{{}}}}}"#,
        meta(Some(token))
    );
    let mut request = mcp_head("tools/list", None, "", body.len()).into_bytes();
    request.extend_from_slice(body.as_bytes());
    let (status, payload) = raw_at(socket, &request);
    status
        .starts_with("HTTP/1.1 200")
        .then(|| parse_reply(&payload))
}

fn is_unavailable(reply: &JcsValue) -> bool {
    reply.pointer("/error/code").and_then(JcsValue::as_i64) == Some(-31503)
}

fn status_of(reply: &JcsValue) -> Option<String> {
    reply
        .pointer("/result/structuredContent/status")
        .and_then(JcsValue::as_str)
        .map(str::to_owned)
}

const PAY_1001: &str = r#"{"invoice_id":"INV-1001","amount":30000,"currency":"USD"}"#;
const LOOKUP_1001: &str = r#"{"invoice_id":"INV-1001"}"#;

/// The hard `RLIMIT_NOFILE` of `pid`.
fn hard_nofile(pid: u32) -> u64 {
    fs::read_to_string(format!("/proc/{pid}/limits"))
        .unwrap()
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .unwrap()
        .split_whitespace()
        .nth(4)
        .unwrap()
        .parse()
        .unwrap()
}

fn set_nofile(pid: u32, soft: u64, hard: u64) {
    assert!(
        Command::new("prlimit")
            .args([format!("--pid={pid}"), format!("--nofile={soft}:{hard}")])
            .status()
            .unwrap()
            .success()
    );
}

/// The lowest descriptor number `pid` has free. `RLIMIT_NOFILE` limits the numbers, not the
/// count, so only a soft limit at this number leaves it none: with a hole below the count of open
/// descriptors, `accept` would still succeed and the attack would prove nothing.
fn lowest_free_fd(pid: u32) -> u64 {
    let open: std::collections::BTreeSet<u64> = fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .parse()
                .unwrap()
        })
        .collect();
    (0..=open.len() as u64)
        .find(|fd| !open.contains(fd))
        .unwrap()
}

fn percentile(sorted: &[Duration], p: usize) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    sorted[(sorted.len() - 1) * p / 100]
}

/// D2. An admitted connection is never evicted (V7), so without a share of the pool one token's
/// slow calls would hold every slot, and a new connection from any other episode would be closed.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn d2_one_token_cannot_hold_every_slot() {
    let world = World::new(Options {
        connections: 16,
        upstream_ms: 4000,
        ..Options::default()
    })
    .start();
    let notes = world.start_episode("notes");
    let other = world.start_episode("pay1");
    let socket = world.path("pep/agent.sock");
    let tool_b = world.pid("tool-b").to_string();
    assert!(
        Command::new("kill")
            .args(["-STOP", &tool_b])
            .status()
            .unwrap()
            .success()
    );
    let mut slow = Vec::new();
    for id in 0..16 {
        let socket = socket.clone();
        let notes = notes.clone();
        slow.push(thread::spawn(move || {
            call_at(&socket, id, "get_note", r#"{"key":"k"}"#, &notes)
        }));
    }
    thread::sleep(Duration::from_millis(400));
    let served = (0..20)
        .filter(|id| list_at(&socket, *id, &other).is_some())
        .count();
    assert!(
        Command::new("kill")
            .args(["-CONT", &tool_b])
            .status()
            .unwrap()
            .success()
    );
    for call in slow {
        drop(call.join());
    }
    eprintln!("D2: 16 slow calls from one token: {served} of 20 calls from another served");
    assert_eq!(served, 20, "one token held the pool");
}

/// D3. A token holder's allowed calls are bounded, but its denials were not: at a high enough
/// rate they rotated its own executed payment's `allow` record away. Past its quota an episode's
/// denials go to the noise file.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn d3_one_token_cannot_flush_the_decision_log() {
    let world = World::new(Options {
        call_burst: 1_000_000,
        call_rate: 1_000_000,
        ..Options::default()
    })
    .start();
    let token = world.start_episode("pay1");
    world.call(1, "get_invoice", LOOKUP_1001, &token);
    let paid = world.call(2, "pay_invoice", PAY_1001, &token);
    assert_eq!(status_of(&paid).as_deref(), Some("executed"));
    let socket = world.path("pep/agent.sock");
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let socket = socket.clone();
            let token = token.clone();
            thread::spawn(move || {
                for id in 0..1500 {
                    call_at(&socket, id, "no_such_tool", "{}", &token);
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    let has_allow = |name: &str| {
        fs::read_to_string(world.path(name)).is_ok_and(|text| text.contains(r#""verdict":"allow""#))
    };
    let main = fs::metadata(world.path("logs/decisions.jsonl")).map_or(0, |m| m.len());
    let noise = fs::read_to_string(world.path("logs/decisions.jsonl.protocol")).unwrap();
    let spilled = noise
        .lines()
        .filter(|line| line.contains(r#""eid":"0"#))
        .count();
    eprintln!("D3: 6000 denials: main log {main} bytes, {spilled} denials in the noise file");
    assert!(
        has_allow("logs/decisions.jsonl") || has_allow("logs/decisions.jsonl.1"),
        "one token flushed its own payment's allow record"
    );
    assert!(spilled >= 1000, "{spilled}");
}

/// V1. Two intents may name the same invoice (R1 says so). `per_entity_max_uses: 1` and
/// `PaymentPending` are per engine, and the PEP-wide set holds only `NeedsReconcile`, so the
/// second intent's payment executes under a different F-07 key, which the provider cannot
/// dedupe. The invoice is paid twice.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v1_one_invoice_cannot_be_paid_twice_across_intents() {
    let mut world = World::new(Options::default()).start();
    let first = world.start_episode("pay1");
    let second = world.start_episode("pay2");
    assert!(
        world
            .call(1, "get_invoice", LOOKUP_1001, &first)
            .get("result")
            .is_some()
    );
    let paid = world.call(2, "pay_invoice", PAY_1001, &first);
    assert_eq!(status_of(&paid).as_deref(), Some("executed"), "{paid:?}");
    assert!(
        world
            .call(1, "get_invoice", LOOKUP_1001, &second)
            .get("result")
            .is_some()
    );
    let again = world.call(2, "pay_invoice", PAY_1001, &second);
    let executions = world.executed_payments();
    eprintln!(
        "V1: second intent's reply: {}; executions at the tool: {}",
        String::from_utf8_lossy(&again.to_canonical_bytes()),
        executions.len()
    );
    assert_eq!(
        executions.len(),
        1,
        "the same invoice executed twice, under two F-07 keys"
    );
    // A restart keeps it: the claim comes back from the journal.
    world.start_pep();
    let after_restart = world.start_episode("pay2");
    world.call(1, "get_invoice", LOOKUP_1001, &after_restart);
    let third = world.call(2, "pay_invoice", PAY_1001, &after_restart);
    eprintln!(
        "V1: after a restart: {}",
        String::from_utf8_lossy(&third.to_canonical_bytes())
    );
    assert_eq!(
        world.executed_payments().len(),
        1,
        "a restart forgot the first intent's payment"
    );
}

/// V1 in flight: the first intent's payment waits for step-up; the second intent pays the same
/// invoice meanwhile; then the approval lands too.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v1b_a_step_up_wait_blocks_the_same_invoice_in_another_intent() {
    let world = World::new(Options::default()).start();
    let first = world.start_episode("pay1");
    let second = world.start_episode("pay2");
    let invoice = r#"{"invoice_id":"INV-2002"}"#;
    let pay = r#"{"invoice_id":"INV-2002","amount":60000,"currency":"USD"}"#;
    world.call(1, "get_invoice", invoice, &first);
    let waiting = {
        let socket = world.path("pep/agent.sock");
        let first = first.clone();
        thread::spawn(move || call_at(&socket, 2, "pay_invoice", pay, &first))
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let approval = loop {
        let pending = world.operator(r#"{"call":"pending"}"#);
        if let Some(found) = pending.pointer("/result/approvals/0") {
            break found.clone();
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(20));
    };
    // The same payment from the other intent. It needs step-up as well, so approve both.
    world.call(1, "get_invoice", invoice, &second);
    let other = {
        let socket = world.path("pep/agent.sock");
        let second = second.clone();
        thread::spawn(move || call_at(&socket, 2, "pay_invoice", pay, &second))
    };
    thread::sleep(Duration::from_millis(300));
    let pending = world.operator(r#"{"call":"pending"}"#);
    let approvals = pending
        .pointer("/result/approvals")
        .unwrap()
        .as_array()
        .unwrap()
        .to_vec();
    eprintln!(
        "V1b: payments of INV-2002 awaiting approval at once: {}",
        approvals.len()
    );
    for approval in &approvals {
        let text = |key: &str| approval.get(key).unwrap().as_str().unwrap().to_owned();
        world.operator(&format!(
            r#"{{"call":"approve","eid":"{}","rid":{},"action_digest":"{}","amount_minor":60000}}"#,
            text("eid"),
            approval.get("rid").unwrap().as_i64().unwrap(),
            text("action_digest")
        ));
    }
    drop(approval);
    drop(waiting.join());
    drop(other.join());
    let executions = world.executed_payments();
    assert_eq!(
        executions.len(),
        1,
        "INV-2002 executed {} times",
        executions.len()
    );
}

fn memo_payment(memo: &str) -> String {
    format!(r#"{{"invoice_id":"INV-1001","amount":30000,"currency":"USD","memo":{memo}}}"#)
}

/// The canonical length of the request the engine parses, for a memo of `memo_len` bytes.
fn engine_request_len(token: &str, memo_len: usize) -> usize {
    let id = "01JBAE0Z1TFCQ9Y41W9NF6YYMB";
    let memo = "x".repeat(memo_len);
    format!(
        r#"{{"id":"{id}","jsonrpc":"2.0","method":"tools/call","params":{{"_meta":{{"dev.pep-sidecar/episode":"{token}","io.modelcontextprotocol/clientCapabilities":{{}},"io.modelcontextprotocol/protocolVersion":"2026-07-28"}},"arguments":{{"amount":30000,"currency":"USD","invoice_id":"INV-1001","memo":"{memo}"}},"name":"pay_invoice"}}}}"#
    )
    .len()
}

/// V2. The engine's request cap counts the agent's `_meta`; the broker's counts the PEP's, which
/// is longer (the Call Proof, `clientInfo`). So the agent can size a memo the engine accepts and
/// the broker refuses with a bare 400. The PEP reads "no usable reply" as `unknown`, so a
/// payment that never left the broker blocks its invoice in every intent, for good (no
/// reconciliation in Week 2), and stays counted in `reserved`. One call does it.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v2_a_payment_the_broker_refuses_unsent_is_not_unknown() {
    let mut world = World::new(Options::default()).start();
    let token = world.start_episode("pay1");
    world.call(1, "get_invoice", LOOKUP_1001, &token);
    let base = engine_request_len(&token, 0);
    let memo = "x".repeat(jcs::MAX_REQUEST_BYTES - base - 8);
    let reply = world.call(
        2,
        "pay_invoice",
        &memo_payment(&format!("\"{memo}\"")),
        &token,
    );
    eprintln!(
        "V2: engine request {} bytes (cap {}); reply: {}",
        engine_request_len(&token, memo.len()),
        jcs::MAX_REQUEST_BYTES,
        String::from_utf8_lossy(&reply.to_canonical_bytes())
    );
    let outcomes = world.outcomes();
    eprintln!(
        "V2: journal outcomes {outcomes:?}; tool executions {}",
        world.executed_payments().len()
    );
    assert_eq!(
        world.executed_payments().len(),
        0,
        "nothing reached the tool"
    );
    // The invoice must still be payable: nothing was sent.
    let second = {
        world.call(3, "get_invoice", LOOKUP_1001, &token);
        world.call(4, "pay_invoice", PAY_1001, &token)
    };
    eprintln!(
        "V2: same intent, normal retry: {}",
        String::from_utf8_lossy(&second.to_canonical_bytes())
    );
    let other = world.start_episode("pay2");
    world.call(1, "get_invoice", LOOKUP_1001, &other);
    let third = world.call(2, "pay_invoice", PAY_1001, &other);
    eprintln!(
        "V2: other intent: {}",
        String::from_utf8_lossy(&third.to_canonical_bytes())
    );
    world.start_pep();
    let after_restart = world.start_episode("pay2");
    world.call(1, "get_invoice", LOOKUP_1001, &after_restart);
    let fourth = world.call(2, "pay_invoice", PAY_1001, &after_restart);
    eprintln!(
        "V2: after a restart: {}",
        String::from_utf8_lossy(&fourth.to_canonical_bytes())
    );
    assert!(
        !outcomes.iter().any(|outcome| outcome == "unknown"),
        "a payment that was never forwarded was journaled unknown: {outcomes:?}"
    );
    assert_eq!(
        status_of(&second).as_deref(),
        Some("executed"),
        "one oversized call blocked the invoice for good"
    );
}

/// V2 by value count: the broker parses with the request profile's 8,192 values, and the PEP's
/// `_meta` has three more values than the agent's.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v2b_the_same_wedge_by_value_count() {
    let world = World::new(Options::default()).start();
    let token = world.start_episode("pay1");
    world.call(1, "get_invoice", LOOKUP_1001, &token);
    // Size the array so the engine's parse sees exactly the cap.
    let shape = |count: usize| {
        let items = vec!["0"; count].join(",");
        format!(
            r#"{{"id":"01JBAE0Z1TFCQ9Y41W9NF6YYMB","jsonrpc":"2.0","method":"tools/call","params":{{"_meta":{{"dev.pep-sidecar/episode":"{token}","io.modelcontextprotocol/clientCapabilities":{{}},"io.modelcontextprotocol/protocolVersion":"2026-07-28"}},"arguments":{{"amount":30000,"currency":"USD","invoice_id":"INV-1001","memo":[{items}]}},"name":"pay_invoice"}}}}"#
        )
    };
    let probe = jcs::parse_with(shape(0).as_bytes(), &ParseOptions::request())
        .unwrap()
        .nodes;
    let count = jcs::MAX_REQUEST_NODES - probe;
    let items = vec!["0"; count].join(",");
    let reply = world.call(
        2,
        "pay_invoice",
        &memo_payment(&format!("[{items}]")),
        &token,
    );
    let outcomes = world.outcomes();
    eprintln!(
        "V2b: {count} memo items; reply {}; outcomes {outcomes:?}; executions {}",
        String::from_utf8_lossy(&reply.to_canonical_bytes()),
        world.executed_payments().len()
    );
    assert!(
        !outcomes.iter().any(|outcome| outcome == "unknown"),
        "the broker refused it unsent, yet it is unknown"
    );
}

/// V3. A broker that is down: `connect` fails, so not one byte left the PEP. That is
/// `DefinitelyNotExecuted`, yet it reads as `unknown`, and blocks the invoice for good.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v3_a_payment_that_could_not_connect_is_not_unknown() {
    let mut world = World::new(Options::default()).start();
    let token = world.start_episode("pay1");
    world.call(1, "get_invoice", LOOKUP_1001, &token);
    world.kill("broker");
    let reply = world.call(2, "pay_invoice", PAY_1001, &token);
    assert!(is_unavailable(&reply), "{reply:?}");
    world.start_broker();
    world.call(3, "get_invoice", LOOKUP_1001, &token);
    let retried = world.call(4, "pay_invoice", PAY_1001, &token);
    let outcomes = world.outcomes();
    eprintln!(
        "V3: journal outcomes {outcomes:?}; retry after the broker is back: {}",
        String::from_utf8_lossy(&retried.to_canonical_bytes())
    );
    assert_eq!(
        status_of(&retried).as_deref(),
        Some("executed"),
        "the invoice stays blocked for good"
    );
}

/// V4. One slow tool server fills the shared broker pool, and a healthy server's payment, on
/// another route, is dropped by the broker's accept loop with no reply: `unknown` for good.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v4_a_slow_server_cannot_poison_a_healthy_servers_payment() {
    let mut world = World::new(Options {
        broker_connections: 8,
        upstream_ms: 4000,
        ..Options::default()
    })
    .start();
    let notes = world.start_episode("notes");
    let token = world.start_episode("pay1");
    world.call(1, "get_invoice", LOOKUP_1001, &token);
    // Tool server b stops answering (rug-pulled, or just slow).
    let tool_b = world.pid("tool-b");
    assert!(
        Command::new("kill")
            .args(["-STOP", &tool_b.to_string()])
            .status()
            .unwrap()
            .success()
    );
    let mut slow = Vec::new();
    for id in 0..8 {
        let socket = world.path("pep/agent.sock");
        let notes = notes.clone();
        slow.push(thread::spawn(move || {
            call_at(&socket, id, "get_note", r#"{"key":"k"}"#, &notes)
        }));
    }
    thread::sleep(Duration::from_millis(400));
    let reply = world.call(2, "pay_invoice", PAY_1001, &token);
    assert!(
        Command::new("kill")
            .args(["-CONT", &tool_b.to_string()])
            .status()
            .unwrap()
            .success()
    );
    for call in slow {
        drop(call.join());
    }
    world.call(3, "get_invoice", LOOKUP_1001, &token);
    let retried = world.call(4, "pay_invoice", PAY_1001, &token);
    let outcomes = world.outcomes();
    eprintln!(
        "V4: first payment {}; outcomes {outcomes:?}; executions at tool a: {}; retry {}",
        String::from_utf8_lossy(&reply.to_canonical_bytes()),
        world.executed_payments().len(),
        String::from_utf8_lossy(&retried.to_canonical_bytes()),
    );
    world.kill("tool-b");
    assert!(
        !outcomes.iter().any(|outcome| outcome == "unknown")
            || world.executed_payments().len() == 1,
        "a payment the broker dropped unread is unknown for good"
    );
    assert_eq!(
        world.executed_payments().len(),
        1,
        "the healthy payment never ran"
    );
}

/// V5. An agent with no token floods protocol errors, 16 KiB of its own text each, until the
/// decision log has rotated its own payment's `allow` record away, and no copy remains.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v5_an_unauthenticated_flood_cannot_erase_an_allow_record() {
    let log_max_bytes: u64 = 64 << 20;
    let world = World::new(Options {
        log_max_bytes,
        ..Options::default()
    })
    .start();
    let token = world.start_episode("pay1");
    world.call(1, "get_invoice", LOOKUP_1001, &token);
    let paid = world.call(2, "pay_invoice", PAY_1001, &token);
    assert_eq!(status_of(&paid).as_deref(), Some("executed"));
    let log = world.path("logs/decisions.jsonl");
    let rotated = world.path("logs/decisions.jsonl.1");
    let has_allow = |path: &Path| {
        fs::read(path).is_ok_and(|bytes| {
            bytes.split(|&byte| byte == b'\n').any(|line| {
                line.windows(16)
                    .any(|window| window == br#""verdict":"allow"#)
            })
        })
    };
    assert!(has_allow(&log), "the allow record is there first");
    let junk = "A".repeat(16_000);
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{{{}}}}}"#,
        meta(None)
    );
    let mut request = mcp_head(&junk, None, "", body.len()).into_bytes();
    request.extend_from_slice(body.as_bytes());
    let request = Arc::new(request);
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let mut flood = Vec::new();
    for _ in 0..4 {
        let socket = world.path("pep/agent.sock");
        let request = Arc::clone(&request);
        let stop = Arc::clone(&stop);
        let sent = Arc::clone(&sent);
        flood.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(mut stream) = UnixStream::connect(&socket) {
                    drop(stream.write_all(&request));
                    let mut sink = [0u8; 1024];
                    drop(stream.read(&mut sink));
                    sent.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    // On `dd05303` it took under 2 s, on two CPUs.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut erased = None;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(200));
        if !has_allow(&log) && !has_allow(&rotated) {
            erased = Some(start.elapsed());
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    for thread in flood {
        drop(thread.join());
    }
    eprintln!(
        "V5: {} requests in {:?}; log {} bytes, rotated {} bytes; allow erased after {erased:?}",
        sent.load(Ordering::Relaxed),
        start.elapsed(),
        fs::metadata(&log).map_or(0, |m| m.len()),
        fs::metadata(&rotated).map_or(0, |m| m.len()),
    );
    assert!(
        erased.is_none(),
        "the allow record of an executed payment is gone"
    );
}

/// V6. An unauthenticated flood of forged tokens: on `dd05303` every one costs a P-256 verify,
/// under the mutex every episode and the control socket need. A measurement: it reports what an
/// honest agent and the operator see (H1 says a flooding agent cannot delay the operator), and
/// asserts only that both are still served. Timings are for `--release`.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v6_forged_tokens_cannot_starve_honest_calls_and_the_operator() {
    let world = World::new(Options::default()).start();
    let token = world.start_episode("notes");
    let socket = world.path("pep/agent.sock");
    let measure = |label: &str, world: &World| {
        let mut calls = Vec::new();
        let mut controls = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(4);
        let mut id = 10;
        while Instant::now() < deadline {
            id += 1;
            let start = Instant::now();
            let reply = list_at(&socket, id, &token);
            if reply.is_some_and(|reply| reply.get("result").is_some()) {
                calls.push(start.elapsed());
            }
            let start = Instant::now();
            world.operator(r#"{"call":"pending"}"#);
            controls.push(start.elapsed());
        }
        calls.sort();
        controls.sort();
        eprintln!(
            "V6 {label}: tools/list n={} p50={:?} p99={:?} max={:?}; control pending n={} p50={:?} p99={:?} max={:?}",
            calls.len(),
            percentile(&calls, 50),
            percentile(&calls, 99),
            calls.last().copied().unwrap_or_default(),
            controls.len(),
            percentile(&controls, 50),
            percentile(&controls, 99),
            controls.last().copied().unwrap_or_default(),
        );
        assert!(!calls.is_empty(), "no honest call was served: {label}");
        assert!(!controls.is_empty(), "no control call was served: {label}");
    };
    measure("baseline", &world);
    // A forged token: the real header and claims, with a well-formed low-S signature that does
    // not verify, so it costs the full P-256 verify.
    let (signing_input, _) = token.rsplit_once('.').unwrap();
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11u8; 64]);
    let forged = format!("{signing_input}.{signature}");
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));
    let mut flood = Vec::new();
    for _ in 0..8 {
        let socket = socket.clone();
        let forged = forged.clone();
        let stop = Arc::clone(&stop);
        let sent = Arc::clone(&sent);
        flood.push(thread::spawn(move || {
            let body = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{{}}}}}"#,
                meta(Some(&forged))
            );
            let mut request = mcp_head("tools/list", None, "", body.len()).into_bytes();
            request.extend_from_slice(body.as_bytes());
            while !stop.load(Ordering::Relaxed) {
                let (_, _) = raw_at(&socket, &request);
                sent.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    thread::sleep(Duration::from_millis(500));
    let start = Instant::now();
    measure("under flood", &world);
    let elapsed = start.elapsed();
    stop.store(true, Ordering::Relaxed);
    for thread in flood {
        drop(thread.join());
    }
    let forged_total = sent.load(Ordering::Relaxed);
    eprintln!(
        "V6: {forged_total} forged requests, {}/s",
        forged_total / elapsed.as_secs().max(1)
    );
}

/// V7. Any uid 20001 process, with no token, holds every connection slot with requests it
/// never finishes, and honest calls are closed unread.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v7_idle_connections_cannot_lock_out_an_honest_agent() {
    let world = World::new(Options {
        connections: 16,
        read_timeout_ms: 30_000,
        ..Options::default()
    })
    .start();
    let token = world.start_episode("notes");
    let socket = world.path("pep/agent.sock");
    assert!(
        list_at(&socket, 1, &token).is_some(),
        "served before the attack"
    );
    let mut held = Vec::new();
    for _ in 0..16 {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream.write_all(b"POST /mcp HTTP/1.1\r\n").unwrap();
        held.push(stream);
    }
    thread::sleep(Duration::from_millis(200));
    let mut served = 0;
    for id in 0..50 {
        if list_at(&socket, id, &token).is_some() {
            served += 1;
        }
    }
    eprintln!("V7: with 16 idle connections held, {served} of 50 honest calls were served");
    drop(held);
    assert!(served > 40, "only {served} of 50 honest calls got through");
}

/// V7b. The same, against an attacker who keeps reconnecting: what an honest agent gets. It passes
/// on `dd05303` too, where the attacker's own closes free the slots. It guards the fix, whose
/// eviction such an attacker could otherwise turn on honest connections.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v7b_an_attacker_who_keeps_reconnecting() {
    let world = World::new(Options {
        connections: 64,
        read_timeout_ms: 30_000,
        ..Options::default()
    })
    .start();
    let token = world.start_episode("notes");
    let socket = world.path("pep/agent.sock");
    let stop = Arc::new(AtomicBool::new(false));
    let opened = Arc::new(AtomicU64::new(0));
    let mut flood = Vec::new();
    for _ in 0..4 {
        let socket = socket.clone();
        let stop = Arc::clone(&stop);
        let opened = Arc::clone(&opened);
        flood.push(thread::spawn(move || {
            let mut held = std::collections::VecDeque::new();
            while !stop.load(Ordering::Relaxed) {
                if let Ok(mut stream) = UnixStream::connect(&socket) {
                    drop(stream.write_all(b"POST /mcp HTTP/1.1\r\n"));
                    held.push_back(stream);
                    opened.fetch_add(1, Ordering::Relaxed);
                    if held.len() > 200 {
                        held.pop_front();
                    }
                }
            }
        }));
    }
    thread::sleep(Duration::from_millis(300));
    let start = Instant::now();
    let mut served = 0;
    let mut times = Vec::new();
    for id in 0..60 {
        let at = Instant::now();
        if list_at(&socket, id, &token).is_some() {
            served += 1;
            times.push(at.elapsed());
        }
    }
    let elapsed = start.elapsed();
    stop.store(true, Ordering::Relaxed);
    for thread in flood {
        drop(thread.join());
    }
    times.sort();
    eprintln!(
        "V7b: attacker opened {} connections; {served} of 60 honest calls served in {elapsed:?}, p50 {:?}, p99 {:?}",
        opened.load(Ordering::Relaxed),
        percentile(&times, 50),
        percentile(&times, 99)
    );
    assert!(served >= 30, "only {served} of 60 honest calls got through");
}

/// V7c. Found by attacking the first version of the V7 fix. A connection past its request cannot
/// be evicted, and `finish` drained with a timeout per read, not in total, so a client with no
/// token sends one whole `server/discover`, then one byte every 20 ms, and holds its slot for up
/// to 64 KiB of them: 22 minutes.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v7c_a_trickling_client_cannot_hold_a_slot_past_its_reply() {
    let world = World::new(Options {
        connections: 16,
        read_timeout_ms: 30_000,
        ..Options::default()
    })
    .start();
    let token = world.start_episode("notes");
    let socket = world.path("pep/agent.sock");
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{{{}}}}}"#,
        meta(None)
    );
    let mut request = mcp_head("server/discover", None, "", body.len()).into_bytes();
    request.extend_from_slice(body.as_bytes());
    let stop = Arc::new(AtomicBool::new(false));
    let mut held = Vec::new();
    for _ in 0..16 {
        let socket = socket.clone();
        let request = request.clone();
        let stop = Arc::clone(&stop);
        held.push(thread::spawn(move || {
            let opened = Instant::now();
            let mut stream = UnixStream::connect(&socket).unwrap();
            stream.write_all(&request).unwrap();
            while !stop.load(Ordering::Relaxed) && stream.write_all(b" ").is_ok() {
                thread::sleep(Duration::from_millis(20));
            }
            opened.elapsed()
        }));
    }
    thread::sleep(Duration::from_millis(500));
    let mut served = 0;
    for id in 0..50 {
        if list_at(&socket, id, &token).is_some() {
            served += 1;
        }
    }
    stop.store(true, Ordering::Relaxed);
    let longest = held
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .max()
        .unwrap();
    eprintln!(
        "V7c: 16 trickling clients: {served} of 50 honest calls served; longest held for {longest:?}"
    );
    assert!(served > 40, "only {served} of 50 honest calls got through");
}

/// V7d. Also found by attacking the V7 fix. Every whole request spends up to 50 ms draining, and
/// could not be evicted in that time, so a client with no token that keeps sending whole
/// `server/discover` requests, at a rate far below what one CPU can do, keeps the pool full of
/// connections it has finished with.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v7d_a_flood_of_whole_requests_cannot_fill_the_pool() {
    let world = World::new(Options {
        connections: 16,
        ..Options::default()
    })
    .start();
    let token = world.start_episode("notes");
    let socket = world.path("pep/agent.sock");
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{{{}}}}}"#,
        meta(None)
    );
    let mut request = mcp_head("server/discover", None, "", body.len()).into_bytes();
    request.extend_from_slice(body.as_bytes());
    let request = Arc::new(request);
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));
    let mut flood = Vec::new();
    for _ in 0..4 {
        let socket = socket.clone();
        let request = Arc::clone(&request);
        let stop = Arc::clone(&stop);
        let sent = Arc::clone(&sent);
        flood.push(thread::spawn(move || {
            // Each stays open until it has aged out of this queue: well past the drain.
            let mut held = std::collections::VecDeque::new();
            while !stop.load(Ordering::Relaxed) {
                if let Ok(mut stream) = UnixStream::connect(&socket) {
                    drop(stream.write_all(&request));
                    held.push_back(stream);
                    sent.fetch_add(1, Ordering::Relaxed);
                    if held.len() > 200 {
                        held.pop_front();
                    }
                }
            }
        }));
    }
    thread::sleep(Duration::from_millis(300));
    let start = Instant::now();
    let mut served = 0;
    let mut times = Vec::new();
    for id in 0..60 {
        let at = Instant::now();
        if list_at(&socket, id, &token).is_some() {
            served += 1;
            times.push(at.elapsed());
        }
    }
    let elapsed = start.elapsed();
    stop.store(true, Ordering::Relaxed);
    for thread in flood {
        drop(thread.join());
    }
    times.sort();
    eprintln!(
        "V7d: {} whole requests from the flood; {served} of 60 honest calls served in {elapsed:?}, p50 {:?}, p99 {:?}",
        sent.load(Ordering::Relaxed),
        percentile(&times, 50),
        percentile(&times, 99)
    );
    assert!(served >= 30, "only {served} of 60 honest calls got through");
}

/// V14b. What V14's worst case does under a flood: clients with no token send 1 MiB bodies NFC
/// must sort, each costing the PEP tens of milliseconds of CPU and the client almost none. The
/// transport parses them before it can see a token, because the token is inside. A measurement:
/// it asserts only that honest calls are still served.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v14b_a_flood_of_expensive_bodies_does_not_stop_honest_calls() {
    let world = World::new(Options::default()).start();
    let token = world.start_episode("notes");
    let socket = world.path("pep/agent.sock");
    let measure = |label: &str| {
        let mut times = Vec::new();
        let mut asked = 0;
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            asked += 1;
            let at = Instant::now();
            if list_at(&socket, asked, &token).is_some() {
                times.push(at.elapsed());
            }
        }
        times.sort();
        eprintln!(
            "V14b {label}: {} of {asked} honest calls served, p50 {:?}, p99 {:?}, max {:?}",
            times.len(),
            percentile(&times, 50),
            percentile(&times, 99),
            times.last().copied().unwrap_or_default(),
        );
        assert!(!times.is_empty(), "no honest call was served: {label}");
    };
    measure("baseline");
    let marks = "\u{0301}\u{0316}\u{0321}\u{0334}".repeat((jcs::MAX_REQUEST_BYTES - 400) / 8);
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{"x":"a{marks}",{}}}}}"#,
        meta(None)
    );
    let mut request = mcp_head("tools/list", None, "", body.len()).into_bytes();
    request.extend_from_slice(body.as_bytes());
    let request = Arc::new(request);
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));
    let mut flood = Vec::new();
    for _ in 0..8 {
        let socket = socket.clone();
        let request = Arc::clone(&request);
        let stop = Arc::clone(&stop);
        let sent = Arc::clone(&sent);
        flood.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(mut stream) = UnixStream::connect(&socket) {
                    drop(stream.write_all(&request));
                    sent.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    thread::sleep(Duration::from_millis(300));
    measure("under flood");
    stop.store(true, Ordering::Relaxed);
    for thread in flood {
        drop(thread.join());
    }
    eprintln!("V14b: {} bodies sent", sent.load(Ordering::Relaxed));
}

/// V8. `limits.body_bytes` and `limits.header_bytes` are parsed and range-checked, and then
/// nothing reads them: the config says 1 KiB, and a 100 KiB body is served.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v8_the_configured_body_limit_is_enforced() {
    let world = World::new(Options {
        body_bytes: 1024,
        ..Options::default()
    })
    .start();
    let token = world.start_episode("notes");
    let padding = "x".repeat(100 * 1024);
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{"pad":"{padding}",{}}}}}"#,
        meta(Some(&token))
    );
    let mut request = mcp_head("tools/list", None, "", body.len()).into_bytes();
    request.extend_from_slice(body.as_bytes());
    let (status, _) = raw_at(&world.path("pep/agent.sock"), &request);
    eprintln!("V8: limits.body_bytes=1024, 100 KiB body: {status}");
    assert!(status.starts_with("HTTP/1.1 400"), "{status}");
}

/// V9. An episode has node and pointer quotas but no byte quota: one 1 MiB note read 256 times
/// keeps gigabytes alive, per episode, with `limits.episodes` of them.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v9_one_episode_cannot_grow_the_pep_without_bound() {
    let world = World::new(Options::default()).start();
    let token = world.start_episode("notes");
    let text = "n".repeat(900 * 1024);
    let saved = world.call(
        1,
        "save_note",
        &format!(r#"{{"key":"big","text":"{text}"}}"#),
        &token,
    );
    assert!(saved.get("result").is_some(), "{saved:?}");
    let pid = world.pep.as_ref().unwrap().id();
    let rss = || {
        fs::read_to_string(format!("/proc/{pid}/status"))
            .unwrap()
            .lines()
            .find(|line| line.starts_with("VmRSS:"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u64>()
            .unwrap()
            / 1024
    };
    let before = rss();
    let mut reads = 0;
    for id in 2..300 {
        let reply = world.call(id, "get_note", r#"{"key":"big"}"#, &token);
        if reply.get("result").is_some() {
            reads += 1;
        } else {
            break;
        }
    }
    let after = rss();
    eprintln!(
        "V9: {reads} reads of a 900 KiB note: PEP RSS {before} MiB to {after} MiB ({} MiB per episode; limits.episodes 64 would be {} GiB)",
        after - before,
        (after - before) * 64 / 1024
    );
    assert!(
        after - before < 128,
        "one episode pinned {} MiB",
        after - before
    );
}

/// V10. `accept` fails with EMFILE when the PEP runs out of file descriptors, and `accept_loop`
/// returned on any error, so the agent could make the whole PEP exit: every token void, and every
/// payment in flight unresolved. Here the shortage is induced at run time: a limit the budget
/// check would refuse at boot (V10b) is one that a later `prlimit`, or leaked descriptors, can
/// still produce.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v10_running_out_of_fds_does_not_stop_the_pep() {
    let mut world = World::new(Options {
        read_timeout_ms: 30_000,
        ..Options::default()
    })
    .start();
    let token = world.start_episode("notes");
    let socket = world.path("pep/agent.sock");
    let pid = world.pep.as_ref().unwrap().id();
    let fds = fs::read_dir(format!("/proc/{pid}/fd")).unwrap().count() as u64;
    let hard = hard_nofile(pid);
    let limit = |soft: u64| set_nofile(pid, soft, hard);
    limit(fds + 16);
    let stop = Arc::new(AtomicBool::new(false));
    let mut held = Vec::new();
    for _ in 0..4 {
        let socket = socket.clone();
        let stop = Arc::clone(&stop);
        held.push(thread::spawn(move || {
            let mut streams = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                if let Ok(stream) = UnixStream::connect(&socket) {
                    streams.push(stream);
                }
                thread::sleep(Duration::from_millis(1));
            }
        }));
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && world.pep_alive() {
        thread::sleep(Duration::from_millis(50));
    }
    stop.store(true, Ordering::Relaxed);
    for thread in held {
        drop(thread.join());
    }
    let alive = world.pep_alive();
    eprintln!(
        "V10: {fds} fds open, soft limit {}: PEP alive after the flood: {alive}",
        fds + 16
    );
    assert!(alive, "the agent made the PEP exit");
    limit(hard);
    thread::sleep(Duration::from_millis(200));
    assert!(list_at(&socket, 1, &token).is_some(), "it serves again");
}

/// V10b. Limits the process cannot hold are refused at boot, not discovered under attack.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v10b_limits_beyond_the_fd_budget_are_refused_at_boot() {
    let world = World::new(Options {
        connections: 200,
        ..Options::default()
    });
    let mut pep = Command::new("prlimit")
        .arg("--nofile=64:64")
        .arg(env!("CARGO_BIN_EXE_pep-sidecar"))
        .arg(world.path("pep.json"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A PEP that does not refuse has no reason to stop.
    let deadline = Instant::now() + Duration::from_secs(5);
    while pep.try_wait().unwrap().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    drop(pep.kill());
    let output = pep.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("V10b: {stderr}");
    assert!(stderr.contains("RLIMIT_NOFILE"), "{stderr}");
}

/// V11. A transient EMFILE on the control socket ends its accept loop for good, while the agent
/// socket keeps serving: no `end_episode`, approve or decline until a restart.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v11_a_transient_emfile_does_not_kill_the_control_socket() {
    let world = World::new(Options::default()).start();
    let token = world.start_episode("notes");
    let socket = world.path("pep/agent.sock");
    let pid = world.pep.as_ref().unwrap().id();
    let hard = hard_nofile(pid);
    // Induce the condition: no fd free for a moment, as a burst of connections would.
    set_nofile(pid, lowest_free_fd(pid), hard);
    // The operator's connection arrives during the shortage.
    let control = world.path("ctl/ctl.sock");
    let probe = UnixStream::connect(&control).unwrap();
    thread::sleep(Duration::from_millis(100));
    drop(probe);
    set_nofile(pid, hard, hard);
    thread::sleep(Duration::from_millis(100));
    let agent_ok = list_at(&socket, 1, &token).is_some();
    let answered = Arc::new(AtomicBool::new(false));
    {
        let answered = Arc::clone(&answered);
        let control = control.clone();
        thread::spawn(move || {
            let body = r#"{"call":"pending"}"#;
            let mut stream = UnixStream::connect(&control).unwrap();
            let request = format!(
                "POST /control HTTP/1.1\r\nHost: pep\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            drop(stream.write_all(request.as_bytes()));
            let mut out = String::new();
            drop(stream.read_to_string(&mut out));
            answered.store(out.contains("approvals"), Ordering::SeqCst);
        });
    }
    thread::sleep(Duration::from_secs(2));
    let control_ok = answered.load(Ordering::SeqCst);
    eprintln!(
        "V11: after a transient EMFILE: agent socket serves: {agent_ok}; control socket serves: {control_ok}"
    );
    assert!(agent_ok, "the agent plane survived");
    assert!(
        control_ok,
        "the operator lost the kill switch, and the agent did not"
    );
}

/// V12. The broker writes its log line after the upstream leg, so a broker killed mid-call
/// leaves an execution with no broker record, and the oracle join (§2a) calls that a bypass. RV3 A6 fixed
/// the same hole on the PEP's side (`allow` before the write), but not here.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v12_an_execution_always_has_a_broker_record() {
    let mut world = World::new(Options::default()).start();
    let token = world.start_episode("pay1");
    world.call(1, "get_invoice", LOOKUP_1001, &token);
    let tool_a = world.pid("tool-a").to_string();
    assert!(
        Command::new("kill")
            .args(["-STOP", &tool_a])
            .status()
            .unwrap()
            .success()
    );
    let paying = {
        let socket = world.path("pep/agent.sock");
        let token = token.clone();
        thread::spawn(move || call_at(&socket, 2, "pay_invoice", PAY_1001, &token))
    };
    thread::sleep(Duration::from_millis(400));
    world.kill("broker");
    assert!(
        Command::new("kill")
            .args(["-CONT", &tool_a])
            .status()
            .unwrap()
            .success()
    );
    drop(paying.join());
    thread::sleep(Duration::from_millis(300));
    let executed = world.executed_payments();
    let broker = world.lines("logs/broker.jsonl");
    let line_for = |upstream: &str| {
        broker
            .iter()
            .find(|line| line.get("upstream_id").and_then(JcsValue::as_str) == Some(upstream))
            .cloned()
    };
    let orphans = executed
        .iter()
        .filter(|execution| {
            line_for(execution.get("upstream_id").unwrap().as_str().unwrap()).is_none()
        })
        .count();
    eprintln!(
        "V12: executions {}; broker lines {}; executions with no broker line {orphans}",
        executed.len(),
        broker.len()
    );
    assert_eq!(
        orphans, 0,
        "an execution with no broker record reads as a bypass (§2a)"
    );
}

/// V13. `Post::timeout` says "the deadline for the whole exchange", but `connect` on a Unix
/// socket whose backlog is full blocks with no deadline: a hung broker hangs the worker, the
/// leg never ends, and the episode can never finish (the timeout row of P1 never fires).
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v13_the_upstream_deadline_covers_connect() {
    use pep_sidecar::forward::discover_request;
    use pep_sidecar::upstream::BrokerClient;
    let _turn = one_at_a_time();
    let dir = std::env::temp_dir().join(format!("pep-rv5-backlog-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("broker.sock");
    drop(fs::remove_file(&path));
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    // Fill the backlog: a broker that has stopped accepting.
    let filler = {
        let path = path.clone();
        thread::spawn(move || {
            let mut held = Vec::new();
            for _ in 0..8192 {
                match UnixStream::connect(&path) {
                    Ok(stream) => held.push(stream),
                    Err(_) => break,
                }
            }
            held
        })
    };
    thread::sleep(Duration::from_millis(1500));
    let (uid, gid) = ids();
    let client = BrokerClient::new(path.clone(), uid, gid, 1 << 20);
    let request = discover_request("01JBAE0Z1TFCQ9Y41W9NF6YYMB", "a").unwrap();
    let (done, finished) = std::sync::mpsc::channel();
    let started = Instant::now();
    thread::spawn(move || {
        let result = client.exchange(&request, Duration::from_millis(300));
        let _ = done.send(result.is_ok());
    });
    let outcome = finished.recv_timeout(Duration::from_secs(3));
    eprintln!(
        "V13: exchange with a 300 ms deadline, backlog full: {:?} after {:?}",
        outcome.as_ref().map_err(|_| "still blocked"),
        started.elapsed()
    );
    let hung = outcome.is_err();
    drop(listener);
    drop(filler);
    drop(fs::remove_dir_all(&dir));
    assert!(!hung, "connect ignored the deadline");
}

/// V14. What one request costs, before and after authentication. These bodies pass framing, and
/// the transport parses them before it looks at the token.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v14_worst_case_cost_of_one_request() {
    use pep_sidecar::engine::{ContentDigest, is_taint_indexable};
    let _turn = one_at_a_time();
    let cap = jcs::MAX_REQUEST_BYTES;
    let wrap = |inner: &str| {
        format!(r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{"x":{inner}}}}}"#)
    };
    let mut cases: Vec<(&str, String)> = Vec::new();
    cases.push((
        "ascii string",
        wrap(&format!("\"{}\"", "a".repeat(cap - 100))),
    ));
    // Combining marks in an order NFC must sort, in one run (ccc 230, 220, 202, 1...).
    let marks = "\u{0301}\u{0316}\u{0321}\u{0334}".repeat((cap - 100) / 8);
    cases.push((
        "one combining run, unsorted",
        wrap(&format!("\"a{marks}\"")),
    ));
    // Characters NFC must expand: U+1D15E is 4 bytes, and 3 code points of 12.
    cases.push((
        "NFC expansion",
        wrap(&format!("\"{}\"", "\u{1D15E}".repeat((cap - 100) / 4))),
    ));
    cases.push((
        "Hangul jamo to compose",
        wrap(&format!(
            "\"{}\"",
            "\u{1100}\u{1161}\u{11A8}".repeat((cap - 100) / 9)
        )),
    ));
    let keys: Vec<String> = (0..4000)
        .map(|i| format!("\"{}{i:06}\":0", "k".repeat(240)))
        .collect();
    cases.push((
        "4,000 long keys, shared prefix",
        wrap(&format!("{{{}}}", keys.join(","))),
    ));
    let mut deep = String::from("0");
    for _ in 0..60 {
        deep = format!("[{deep}]");
    }
    cases.push(("depth 60", wrap(&deep)));
    cases.push((
        "escapes",
        wrap(&format!("\"{}\"", "\\u0041".repeat((cap - 100) / 6))),
    ));
    for (name, body) in &cases {
        let start = Instant::now();
        let result = jcs::parse(body.as_bytes());
        let elapsed = start.elapsed();
        eprintln!(
            "V14: parse {name}: {} KiB in {elapsed:?} ({})",
            body.len() / 1024,
            if result.is_ok() {
                "accepted"
            } else {
                "refused"
            }
        );
    }
    // After the token: a store write hashes every container down to depth 8 (F-08).
    let mut nested = format!("\"{}\"", "s".repeat(cap - 2000));
    for _ in 0..8 {
        nested = format!("{{\"a\":{nested}}}");
    }
    let value = jcs::parse(wrap(&nested).as_bytes()).unwrap();
    let start = Instant::now();
    let mut digests = 0;
    value.walk(&mut |depth, node| {
        if (node.is_scalar() || depth <= 8)
            && is_taint_indexable(node)
            && ContentDigest::of(node).is_some()
        {
            digests += 1;
        }
    });
    eprintln!(
        "V14: F-08 digests of a 1 MiB write nested 8 deep: {digests} digests in {:?}",
        start.elapsed()
    );
}

/// V15. RV4 #8's rule looks only at `mutating_internal` writers. An `external_sink` that declares
/// a `store_write` taints the store just the same (`planned_writes`), so a reader of that store
/// should need the high-water label too, and it loads without it.
#[test]
#[ignore = "attack suite: cargo test --release --test rv5_attacks -- --ignored --test-threads=1"]
fn v15_the_store_reader_rule_sees_every_writer() {
    let pins = r#"{"lockfile_version":1,"release_epoch":7,"stores":{"notes://agent":{"case_insensitive":false}},
      "servers":{"b":{"endpoint":"unix:b","identity":"spiffe://tools/b","protocol_version":"2026-07-28","discover":{},"tools":{
        "publish_note":{"definition":{"name":"publish_note"},"policy":{"effect":"external_sink","args":[{"pointer":"/key","role":"store_key"},{"pointer":"/text","role":"store_write"}],"store_uri":"notes://agent",
          "sink_clearance":"internal","output_label":{"conf":"internal","integ":"untrusted_external"},"max_result_bytes":65536,"max_result_nodes":1024}},
        "search_notes":{"definition":{"name":"search_notes"},"policy":{"effect":"read","args":[{"pointer":"/query","role":"data"}],"reads_stores":["notes://agent"],
          "sink_clearance":"secret","output_label":{"conf":"internal","integ":"untrusted_external"},"max_result_bytes":65536,"max_result_nodes":1024}}}}}}"#;
    let value = jcs::parse_with(pins.as_bytes(), &ParseOptions::definition())
        .unwrap()
        .value;
    let loaded = pep_sidecar::lockfile::parse_payload(&value, "pins");
    eprintln!(
        "V15: store reader with a low label, writer is an external_sink: {:?}",
        loaded.as_ref().err()
    );
    assert!(
        loaded.is_err_and(|error| error.to_string().contains("RV4 #8")),
        "a reader of a store an external sink writes loads with a low label"
    );
}
