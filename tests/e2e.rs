//! End to end over temporary-directory sockets (`WEEK2_PLAN` step 7): the real `pep-sidecar`
//! with the stub broker, two stub tool servers and the scripted operator, all as this user.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use pep_sidecar::jcs::{self, JcsValue, ParseOptions};
use pep_sidecar::stubs::oracle::{self, Expect, Finding, Layout};
use pep_sidecar::stubs::tool::sha256_hex;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

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
          "policy":{"effect":"mutating_financial","args":[{"pointer":"/invoice_id","role":"entity","kind":"invoice"},{"pointer":"/amount","role":"amount"},{"pointer":"/currency","role":"currency"}],
            "sink_clearance":"internal","output_label":{"conf":"internal","integ":"untrusted_external"},
            "amount_binding":{"lookup_tool":"get_invoice","entity_arg_pointer":"/invoice_id","lookup_entity_pointer":"/invoice_id",
              "result_amount_pointer":"/structuredContent/amount_due_minor","result_currency_pointer":"/structuredContent/currency"},
            "max_result_bytes":65536,"max_result_nodes":1024}}}},
    "b":{"endpoint":"unix:b","identity":"spiffe://tools/b","protocol_version":"2026-07-28",
      "discover":{"cacheScope":"public","capabilities":{"tools":{}},"resultType":"complete","supportedVersions":["2026-07-28"],"ttlMs":0},
      "tools":{
        "save_note":{"definition":{"name":"save_note","inputSchema":{"type":"object"}},
          "policy":{"effect":"mutating_internal","args":[{"pointer":"/key","role":"store_key"},{"pointer":"/text","role":"store_write"}],"store_uri":"notes://agent",
            "sink_clearance":"secret","output_label":{"conf":"internal","integ":"untrusted_external"},"max_result_bytes":65536,"max_result_nodes":1024}},
        "get_note":{"definition":{"name":"get_note","inputSchema":{"type":"object"}},
          "policy":{"effect":"read","args":[{"pointer":"/key","role":"store_key"}],"store_uri":"notes://agent",
            "sink_clearance":"secret","output_label":{"conf":"internal","integ":"untrusted_external"},"max_result_bytes":65536,"max_result_nodes":1024}}}}}}"#;

/// One world: its directory, its processes, and how to reach them.
struct World {
    base: PathBuf,
    pins_text: String,
    pins: JcsValue,
    children: Vec<Child>,
    pep: Option<Child>,
    step_up_ms: u64,
    broker_credential_b: String,
    /// Whether the broker is G3's capturing one.
    capture: bool,
    /// Extra members for tool-a's config: its misbehaviour.
    tool_a_extra: String,
    /// The upstream deadline, for the PEP and the broker.
    upstream_ms: u64,
}

impl Drop for World {
    fn drop(&mut self) {
        for child in self.children.iter_mut().chain(self.pep.iter_mut()) {
            drop(child.kill());
            drop(child.wait());
        }
        drop(fs::remove_dir_all(&self.base));
    }
}

/// The pins, with each server's real endpoint: the broker refuses a route that differs.
fn pins_for(base: &Path) -> String {
    let base = base.display();
    PINS.replace("unix:a", &format!("unix:{base}/tool-a/tool.sock"))
        .replace("unix:b", &format!("unix:{base}/tool-b/tool.sock"))
}

fn ids() -> (u32, u32) {
    // Our own ids, from /proc, without another dependency.
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let field = |name: &str| -> u32 {
        let line = status.lines().find(|line| line.starts_with(name)).unwrap();
        line.split_whitespace().nth(2).unwrap().parse().unwrap()
    };
    (field("Uid:"), field("Gid:"))
}

fn dir(base: &Path, name: &str, mode: u32) -> PathBuf {
    let path = base.join(name);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
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

impl World {
    /// A world whose payments wait `step_up_ms` for an approval, and whose broker presents
    /// `credential_b` to tool server `b` (its real credential unless a test says otherwise).
    fn new(step_up_ms: u64, credential_b: Option<&str>) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!("pep-e2e-{}-{n}", std::process::id()));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let pins_text = pins_for(&base);
        let pins = jcs::parse_with(pins_text.as_bytes(), &ParseOptions::definition())
            .unwrap()
            .value;
        Self {
            base,
            pins_text,
            pins,
            children: Vec::new(),
            pep: None,
            step_up_ms,
            broker_credential_b: credential_b
                .map_or_else(|| "credential-b".to_owned(), str::to_owned),
            capture: false,
            tool_a_extra: String::new(),
            upstream_ms: 5000,
        }
    }

    /// Where the oracle finds this world's logs.
    fn layout(&self) -> Layout {
        Layout {
            decisions: self.path("logs/decisions.jsonl"),
            broker: self.path("logs/broker.jsonl"),
            tools: vec![
                self.path("logs/tool-a.jsonl"),
                self.path("logs/tool-b.jsonl"),
            ],
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.base.join(name)
    }

    fn write_files(&self) {
        let (uid, gid) = ids();
        for name in ["pep", "ctl", "broker", "tool-a", "tool-b"] {
            dir(&self.base, name, 0o750);
        }
        for name in ["pub", "state", "logs", "secrets"] {
            dir(&self.base, name, 0o700);
        }
        fs::write(self.path("pins.json"), &self.pins_text).unwrap();
        for (server, credential) in [("a", "credential-a"), ("b", "credential-b")] {
            fs::write(
                self.path(&format!("secrets/verifier-{server}")),
                sha256_hex(credential.as_bytes()),
            )
            .unwrap();
        }
        fs::write(self.path("secrets/cred-a"), "credential-a").unwrap();
        fs::write(self.path("secrets/cred-b"), &self.broker_credential_b).unwrap();
        let p = |name: &str| self.path(name).display().to_string();
        let invoices = r#"{"INV-1001":{"amount_due_minor":30000,"currency":"USD","status":"executed"},
            "INV-2002":{"amount_due_minor":60000,"currency":"USD","status":"executed"},
            "INV-3003":{"amount_due_minor":30000,"currency":"USD","status":"declined"},
            "INV-4004":{"amount_due_minor":30000,"currency":"USD","status":"pending"},
            "INV-6001":{"amount_due_minor":1000,"currency":"USD","status":"executed"},
            "INV-6002":{"amount_due_minor":1000,"currency":"USD","status":"executed"},
            "INV-6003":{"amount_due_minor":1000,"currency":"USD","status":"executed"},
            "INV-6004":{"amount_due_minor":1000,"currency":"USD","status":"executed"},
            "INV-6005":{"amount_due_minor":1000,"currency":"USD","status":"declined"},
            "INV-6006":{"amount_due_minor":1000,"currency":"USD","status":"executed"},
            "INV-6007":{"amount_due_minor":1000,"currency":"USD","status":"executed"}}"#;
        for server in ["a", "b"] {
            fs::write(
                self.path(&format!("tool-{server}.json")),
                format!(
                    r#"{{"server_id":"{server}","listen":"unix:{}","verifier":"{}","pins":"{}","store":"{}","log":"{}","invoices":{invoices}{}}}"#,
                    p(&format!("tool-{server}/tool.sock")),
                    p(&format!("secrets/verifier-{server}")),
                    p("pins.json"),
                    p(&format!("state/dedupe-{server}.jsonl")),
                    p(&format!("logs/tool-{server}.jsonl")),
                    if server == "a" {
                        self.tool_a_extra.as_str()
                    } else {
                        ""
                    },
                ),
            )
            .unwrap();
        }
        fs::write(
            self.path("broker.json"),
            format!(
                r#"{{"socket":"{}","pep":{{"uid":{uid},"gid":{gid}}},"pep_key":"{}","pins":"{}",
                "routes":{{"a":{{"endpoint":"unix:{}","credential":"{}"}},"b":{{"endpoint":"unix:{}","credential":"{}"}}}},
                "replay_cache_entries":1000,"clock_skew_ms":2000,"connections":16,"upstream_timeout_ms":{},"log":"{}"}}"#,
                p("broker/broker.sock"),
                p("pub/call-proof.pub"),
                p("pins.json"),
                p("tool-a/tool.sock"),
                p("secrets/cred-a"),
                p("tool-b/tool.sock"),
                p("secrets/cred-b"),
                self.upstream_ms,
                p("logs/broker.jsonl"),
            ),
        )
        .unwrap();
        let digest = jcs::digest_value(&self.pins);
        let intent = |kind: &str, ids: &str, max_calls: u32| {
            format!(
                r#"{{"release_epoch":7,"lockfile_digest":"{digest}","limits":{{"currency":"USD","per_call_max_minor":100000,"cumulative_max_minor":500000,"max_calls":{max_calls},"step_up_over_minor":50000,"max_declines":3}},
                "entities":{{"kind":"{kind}","ids":{ids},"per_entity_max_uses":1}},"seq":"unconstrained"}}"#
            )
        };
        fs::write(
            self.path("pep.json"),
            format!(
                r#"{{"agent":{{"uid":{uid},"gid":{gid},"socket":"{}"}},"operator":{{"uid":{uid},"gid":{gid},"socket":"{}"}},
                "broker":{{"uid":{uid},"gid":{gid},"socket":"{}"}},"pep":{{"spiffe_id":"spiffe://corp.example/pep","pubkey_dir":"{}"}},
                "lockfile":{{"path":"/etc/pep/lockfile.dsse.json","min_accepted_epoch":7,"signers":[],"thresholds":{{}}}},
                "journal":{{"path":"{}","lock":"{}"}},"log":{{"path":"{}","max_bytes":1048576}},
                "limits":{{"connections":16,"control_connections":4,"header_bytes":16384,"body_bytes":1048576,"read_timeout_ms":5000,
                  "upstream_timeout_ms":{},"step_up_timeout_ms":{},"episode_idle_ms":600000,"episodes":4,"call_burst":50,"call_rate_per_s":50,
                  "clock_skew_ms":2000,"replay_cache_entries":1000}},
                "intents":{{"pay":{},"notes":{},"chaos":{}}},"pins":{}}}"#,
                p("pep/agent.sock"),
                p("ctl/ctl.sock"),
                p("broker/broker.sock"),
                p("pub"),
                p("state/journal.jsonl"),
                p("state/journal.lock"),
                p("logs/decisions.jsonl"),
                self.upstream_ms,
                self.step_up_ms,
                intent("invoice", r#"["INV-1001","INV-2002","INV-3003","INV-4004"]"#, 5),
                intent("recipient", r#"["rcpt_A"]"#, 5),
                intent(
                    "invoice",
                    r#"["INV-6001","INV-6002","INV-6003","INV-6004","INV-6005","INV-6006","INV-6007"]"#,
                    10
                ),
                self.pins_text,
            ),
        )
        .unwrap();
    }

    fn spawn(binary: &str, config: &Path) -> Child {
        Command::new(binary)
            .arg(config)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    /// Starts the tool servers and the broker, then the PEP.
    fn start(mut self) -> Self {
        self.write_files();
        for server in ["a", "b"] {
            let mut child = Self::spawn(
                env!("CARGO_BIN_EXE_stub-tool"),
                &self.path(&format!("tool-{server}.json")),
            );
            wait_for_socket(&self.path(&format!("tool-{server}/tool.sock")), &mut child);
            self.children.push(child);
        }
        let mut broker = if self.capture {
            Command::new(env!("CARGO_BIN_EXE_stub-broker-capture"))
                .arg(self.path("state/proofs.jsonl"))
                .arg(self.path("broker.json"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        } else {
            Self::spawn(env!("CARGO_BIN_EXE_stub-broker"), &self.path("broker.json"))
        };
        wait_for_socket(&self.path("broker/broker.sock"), &mut broker);
        self.children.push(broker);
        // R1: the broker refuses proofs issued in its boot second; let it pass.
        let since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        thread::sleep(Duration::from_millis(
            1050 - u64::from(since_epoch.subsec_millis()),
        ));
        self.start_pep();
        self
    }

    /// Starts (or restarts) the PEP, and returns its boot log.
    fn start_pep(&mut self) -> Vec<String> {
        if let Some(mut old) = self.pep.take() {
            drop(old.kill());
            drop(old.wait());
        }
        let mut pep = Self::spawn(env!("CARGO_BIN_EXE_pep-sidecar"), &self.path("pep.json"));
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
        lines
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
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn agent(
        &self,
        id: u64,
        method: &str,
        name: Option<&str>,
        params: &str,
        token: Option<&str>,
    ) -> JcsValue {
        agent_at(
            &self.path("pep/agent.sock"),
            id,
            method,
            name,
            params,
            token,
        )
    }

    fn raw(&self, request: &[u8]) -> (String, String) {
        raw_at(&self.path("pep/agent.sock"), request)
    }

    fn call(&self, id: u64, tool: &str, arguments: &str, token: &str) -> JcsValue {
        call_at(&self.path("pep/agent.sock"), id, tool, arguments, token)
    }

    fn lines(&self, log: &str) -> Vec<JcsValue> {
        let settled = self.settled(log);
        settled
            .lines()
            .map(|line| {
                jcs::parse_with(line.as_bytes(), &ParseOptions::definition())
                    .unwrap()
                    .value
            })
            .collect()
    }

    fn settled(&self, log: &str) -> String {
        // The journal's `reserve` and `outcome` records are queued, not waited for, so they can
        // reach the file a moment after the reply.
        if log.contains("journal") {
            // The file is preallocated, so its size says nothing: count up to the first NUL.
            let path = self.path(log);
            let size = || {
                let bytes = fs::read(&path).unwrap_or_default();
                bytes
                    .iter()
                    .position(|&byte| byte == 0)
                    .unwrap_or(bytes.len())
            };
            let mut seen = size();
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                thread::sleep(Duration::from_millis(40));
                let now = size();
                if now == seen {
                    break;
                }
                seen = now;
            }
        }
        let text = fs::read_to_string(self.path(log)).unwrap_or_default();
        text.split('\0').next().unwrap_or_default().to_owned()
    }
}

/// One agent request on `socket`: `method` with `params` (without `_meta`), the token in
/// `_meta`.
fn agent_at(
    socket: &Path,
    id: u64,
    method: &str,
    name: Option<&str>,
    params: &str,
    token: Option<&str>,
) -> JcsValue {
    let token_meta = token.map_or_else(String::new, |token| {
        format!(r#","dev.pep-sidecar/episode":"{token}""#)
    });
    let meta = format!(
        r#""_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{{}}{token_meta}}}"#
    );
    let params = if params.is_empty() {
        format!("{{{meta}}}")
    } else {
        format!("{{{params},{meta}}}")
    };
    let body = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{params}}}"#);
    let name = name.map_or_else(String::new, |name| format!("Mcp-Name: {name}\r\n"));
    let raw = format!(
        "POST /mcp HTTP/1.1\r\nHost: pep.local\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: {method}\r\n{name}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (status, payload) = raw_at(socket, raw.as_bytes());
    assert!(status.starts_with("HTTP/1.1 200"), "{status}: {payload}");
    jcs::parse_with(payload.as_bytes(), &ParseOptions::definition())
        .unwrap()
        .value
}

fn raw_at(socket: &Path, request: &[u8]) -> (String, String) {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.write_all(request).unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    (
        head.lines().next().unwrap_or_default().to_owned(),
        body.to_owned(),
    )
}

fn call_at(socket: &Path, id: u64, tool: &str, arguments: &str, token: &str) -> JcsValue {
    agent_at(
        socket,
        id,
        "tools/call",
        Some(tool),
        &format!(r#""name":"{tool}","arguments":{arguments}"#),
        Some(token),
    )
}

fn denied(reply: &JcsValue) -> bool {
    reply.pointer("/error/code").and_then(JcsValue::as_i64) == Some(-31403)
}

fn unavailable(reply: &JcsValue) -> bool {
    reply.pointer("/error/code").and_then(JcsValue::as_i64) == Some(-31503)
}

fn text(value: &JcsValue, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(JcsValue::as_str)
        .map(str::to_owned)
}

#[test]
fn reads_payments_a_step_up_and_every_broker_outcome() {
    let world = World::new(10_000, None).start();
    let token = world.start_episode("pay");
    // The pinned tools of every serving server (M1).
    let listed = world.agent(1, "tools/list", None, "", Some(&token));
    assert_eq!(
        listed
            .pointer("/result/tools")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        4
    );
    // A read, and the payment it funds.
    let invoice = world.call(2, "get_invoice", r#"{"invoice_id":"INV-1001"}"#, &token);
    assert_eq!(
        invoice
            .pointer("/result/structuredContent/amount_due_minor")
            .unwrap()
            .as_i64(),
        Some(30_000)
    );
    let paid = world.call(
        3,
        "pay_invoice",
        r#"{"invoice_id":"INV-1001","amount":30000,"currency":"USD"}"#,
        &token,
    );
    assert_eq!(
        text(&paid, "/result/structuredContent/status").as_deref(),
        Some("executed"),
        "{paid:?}"
    );
    // The tool server executed it once, under the F-07 key the broker injected.
    let executions = world.lines("logs/tool-a.jsonl");
    let payment = executions
        .iter()
        .find(|line| text(line, "/tool").as_deref() == Some("pay_invoice"))
        .unwrap();
    assert_eq!(payment.get("executed").unwrap().as_bool(), Some(true));
    let key = text(payment, "/idempotency_key").unwrap();
    assert!(key.starts_with("pep-"));
    let broker = world.lines("logs/broker.jsonl");
    let forwarded = broker
        .iter()
        .find(|line| {
            text(line, "/idempotency_key").as_deref() == Some(key.as_str())
                && text(line, "/verdict").as_deref() == Some("forwarded")
        })
        .unwrap();
    assert_eq!(text(forwarded, "/outcome").as_deref(), Some("executed"));
    assert!(text(forwarded, "/jti").is_some());
    // A step-up: the payment waits until the operator approves it.
    world.call(4, "get_invoice", r#"{"invoice_id":"INV-2002"}"#, &token);
    let waiting = {
        let socket = world.path("pep/agent.sock");
        let token = token.clone();
        thread::spawn(move || {
            call_at(
                &socket,
                5,
                "pay_invoice",
                r#"{"invoice_id":"INV-2002","amount":60000,"currency":"USD"}"#,
                &token,
            )
        })
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let approval = loop {
        let pending = world.operator(r#"{"call":"pending"}"#);
        if let Some(first) = pending.pointer("/result/approvals/0") {
            break first.clone();
        }
        assert!(
            Instant::now() < deadline,
            "the payment never awaited approval"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let approved = world.operator(&format!(
        r#"{{"call":"approve","eid":"{}","rid":{},"action_digest":"{}","amount_minor":60000}}"#,
        text(&approval, "/eid").unwrap(),
        approval.get("rid").unwrap().as_i64().unwrap(),
        text(&approval, "/action_digest").unwrap()
    ));
    assert!(approved.get("result").is_some(), "{approved:?}");
    let paid = waiting.join().unwrap();
    assert_eq!(
        text(&paid, "/result/structuredContent/status").as_deref(),
        Some("executed"),
        "{paid:?}"
    );
    // Declined at the tool: the agent sees the recorded refusal.
    world.call(6, "get_invoice", r#"{"invoice_id":"INV-3003"}"#, &token);
    let declined = world.call(
        7,
        "pay_invoice",
        r#"{"invoice_id":"INV-3003","amount":30000,"currency":"USD"}"#,
        &token,
    );
    assert_eq!(
        text(&declined, "/result/structuredContent/status").as_deref(),
        Some("declined"),
        "{declined:?}"
    );
    // Pending at the tool: unknown, so PEP_UNAVAILABLE, and the invoice stays blocked.
    world.call(8, "get_invoice", r#"{"invoice_id":"INV-4004"}"#, &token);
    let pending = world.call(
        9,
        "pay_invoice",
        r#"{"invoice_id":"INV-4004","amount":30000,"currency":"USD"}"#,
        &token,
    );
    assert!(unavailable(&pending), "{pending:?}");
    let journal = world.lines("state/journal.jsonl");
    let outcomes: Vec<String> = journal
        .iter()
        .filter_map(|line| text(line, "/result"))
        .collect();
    assert_eq!(outcomes, ["executed", "executed", "declined", "unknown"]);
    oracle_join(&world);
}

/// §2a's join, by the oracle Gate 1 runs: every execution in a tool log joins through the broker
/// log to a PEP `allow`, with the same `action_digest` and the F-07 key of its reservation.
fn oracle_join(world: &World) {
    let logs = world.layout().read_from(&[0, 0, 0, 0]).unwrap();
    let verdict = oracle::judge(&logs, Expect::Any);
    assert_eq!(verdict.findings, []);
    assert!(verdict.executions > 0);
    assert_eq!(verdict.open_legs, 0, "every allow has its outcome");
    // Nothing secret is logged: no token, no proof.
    let raw = fs::read_to_string(world.path("logs/decisions.jsonl")).unwrap();
    assert!(!raw.contains("eyJ"));
}

#[test]
fn a_restart_replays_spend_and_unresolved_payments() {
    let mut world = World::new(10_000, None).start();
    let token = world.start_episode("pay");
    world.call(1, "get_invoice", r#"{"invoice_id":"INV-1001"}"#, &token);
    world.call(
        2,
        "pay_invoice",
        r#"{"invoice_id":"INV-1001","amount":30000,"currency":"USD"}"#,
        &token,
    );
    world.call(3, "get_invoice", r#"{"invoice_id":"INV-4004"}"#, &token);
    assert!(unavailable(&world.call(
        4,
        "pay_invoice",
        r#"{"invoice_id":"INV-4004","amount":30000,"currency":"USD"}"#,
        &token
    )));
    let boot = world.start_pep();
    assert!(
        boot.iter()
            .any(|line| line.contains("1 unresolved entities")),
        "{boot:?}"
    );
    // The old token is void: the keys are per boot.
    assert!(denied(&world.call(
        5,
        "get_invoice",
        r#"{"invoice_id":"INV-1001"}"#,
        &token
    )));
    let token = world.start_episode("pay");
    // INV-1001 was paid, and INV-4004 is unresolved: neither can be paid again.
    world.call(6, "get_invoice", r#"{"invoice_id":"INV-1001"}"#, &token);
    assert!(denied(&world.call(
        7,
        "pay_invoice",
        r#"{"invoice_id":"INV-1001","amount":30000,"currency":"USD"}"#,
        &token
    )));
    world.call(8, "get_invoice", r#"{"invoice_id":"INV-4004"}"#, &token);
    assert!(denied(&world.call(
        9,
        "pay_invoice",
        r#"{"invoice_id":"INV-4004","amount":30000,"currency":"USD"}"#,
        &token
    )));
    let executed = world
        .lines("logs/tool-a.jsonl")
        .iter()
        .filter(|line| {
            text(line, "/tool").as_deref() == Some("pay_invoice")
                && line.get("executed").and_then(JcsValue::as_bool) == Some(true)
        })
        .count();
    assert_eq!(executed, 1);
}

#[test]
fn a_decline_and_a_step_up_timeout_send_nothing() {
    let world = World::new(1_000, None).start();
    let token = world.start_episode("pay");
    world.call(1, "get_invoice", r#"{"invoice_id":"INV-2002"}"#, &token);
    // Nobody approves: the wait times out (P1).
    assert!(denied(&world.call(
        2,
        "pay_invoice",
        r#"{"invoice_id":"INV-2002","amount":60000,"currency":"USD"}"#,
        &token
    )));
    assert!(
        !world
            .lines("logs/tool-a.jsonl")
            .iter()
            .any(|line| text(line, "/tool").as_deref() == Some("pay_invoice"))
    );
    let journal = world.lines("state/journal.jsonl");
    assert!(
        journal
            .iter()
            .any(|line| text(line, "/result").as_deref() == Some("released"))
    );
}

#[test]
fn the_wrong_credential_executes_nothing() {
    // C-CRED: the broker presents a credential that is not tool b's.
    let world = World::new(10_000, Some("credential-a")).start();
    let token = world.start_episode("notes");
    let reply = world.call(1, "save_note", r#"{"key":"k1","text":"hello"}"#, &token);
    assert!(denied(&reply) || unavailable(&reply), "{reply:?}");
    assert!(world.lines("logs/tool-b.jsonl").is_empty());
}

#[test]
fn the_router_answers_every_method_as_m1_says() {
    let world = World::new(10_000, None).start();
    let discover = world.agent(1, "server/discover", None, "", None);
    assert_eq!(
        text(&discover, "/result/supportedVersions/0").as_deref(),
        Some("2026-07-28")
    );
    let (status, body) = world.raw(b"GET /mcp HTTP/1.1\r\nHost: pep\r\n\r\n");
    assert!(status.starts_with("HTTP/1.1 405"), "{status}{body}");
    let ping = br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    let raw = format!(
        "POST /mcp HTTP/1.1\r\nHost: pep\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: ping\r\nContent-Length: {}\r\n\r\n",
        ping.len()
    );
    let (status, _) = world.raw(&[raw.as_bytes(), ping].concat());
    assert!(status.starts_with("HTTP/1.1 404"), "{status}");
    let cancelled =
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"x"}}"#;
    let raw = format!(
        "POST /mcp HTTP/1.1\r\nHost: pep\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        cancelled.len()
    );
    let (status, _) = world.raw(&[raw.as_bytes(), cancelled].concat());
    assert!(status.starts_with("HTTP/1.1 202"), "{status}");
    // tools/list and tools/call need a token.
    assert!(denied(&world.agent(2, "tools/list", None, "", None)));
    assert!(denied(&world.agent(
        3,
        "tools/call",
        Some("get_note"),
        r#""name":"get_note","arguments":{"key":"k"}"#,
        None
    )));
}

/// Waits for the one payment awaiting approval, and returns it.
fn awaiting(world: &World) -> JcsValue {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let pending = world.operator(r#"{"call":"pending"}"#);
        if let Some(first) = pending.pointer("/result/approvals/0") {
            return first.clone();
        }
        assert!(
            Instant::now() < deadline,
            "the payment never awaited approval"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn an_operator_decline_sends_nothing() {
    let world = World::new(10_000, None).start();
    let token = world.start_episode("pay");
    world.call(1, "get_invoice", r#"{"invoice_id":"INV-2002"}"#, &token);
    let waiting = {
        let socket = world.path("pep/agent.sock");
        let token = token.clone();
        thread::spawn(move || {
            call_at(
                &socket,
                2,
                "pay_invoice",
                r#"{"invoice_id":"INV-2002","amount":60000,"currency":"USD"}"#,
                &token,
            )
        })
    };
    let payment = awaiting(&world);
    let declined = world.operator(&format!(
        r#"{{"call":"decline","eid":"{}","rid":{},"action_digest":"{}","amount_minor":60000}}"#,
        text(&payment, "/eid").unwrap(),
        payment.get("rid").unwrap().as_i64().unwrap(),
        text(&payment, "/action_digest").unwrap()
    ));
    assert!(declined.get("result").is_some(), "{declined:?}");
    assert!(denied(&waiting.join().unwrap()));
    assert!(
        !world
            .lines("logs/tool-a.jsonl")
            .iter()
            .any(|line| text(line, "/tool").as_deref() == Some("pay_invoice"))
    );
    let journal = world.lines("state/journal.jsonl");
    assert!(
        journal
            .iter()
            .any(|line| text(line, "/result").as_deref() == Some("released"))
    );
}

#[test]
fn a_refused_call_proof_executes_nothing() {
    // P1: the broker rejects the proof, so the payment was never sent: refused, released.
    let world = World::new(10_000, None).start();
    let token = world.start_episode("pay");
    world.call(1, "get_invoice", r#"{"invoice_id":"INV-1001"}"#, &token);
    // The broker now reads a key the PEP never signed with.
    let stranger = pep_sidecar::tokens::Es256Signer::from_secret_bytes(&[9; 32]).unwrap();
    {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(stranger.verifier().to_sec1_uncompressed());
        fs::write(world.path("pub/call-proof.pub"), format!("{encoded}\n")).unwrap();
    }
    let reply = world.call(
        2,
        "pay_invoice",
        r#"{"invoice_id":"INV-1001","amount":30000,"currency":"USD"}"#,
        &token,
    );
    assert!(unavailable(&reply), "{reply:?}");
    assert!(
        !world
            .lines("logs/tool-a.jsonl")
            .iter()
            .any(|line| text(line, "/tool").as_deref() == Some("pay_invoice"))
    );
    let broker = world.lines("logs/broker.jsonl");
    assert!(
        broker
            .iter()
            .any(|line| text(line, "/reason").as_deref() == Some("call proof refused"))
    );
    let journal = world.lines("state/journal.jsonl");
    assert_eq!(
        text(journal.last().unwrap(), "/result").as_deref(),
        Some("refused")
    );
}

fn executed_payments(world: &World) -> usize {
    world
        .lines("logs/tool-a.jsonl")
        .iter()
        .filter(|line| {
            text(line, "/tool").as_deref() == Some("pay_invoice")
                && line.get("executed").and_then(JcsValue::as_bool) == Some(true)
        })
        .count()
}

/// RV5 D5: F-07's key differs per reservation, so only the second key can stop this.
#[test]
fn a_lost_journal_cannot_pay_an_invoice_twice() {
    const PAY: &str = r#"{"invoice_id":"INV-1001","amount":30000,"currency":"USD"}"#;
    let mut world = World::new(10_000, None).start();
    let token = world.start_episode("pay");
    world.call(1, "get_invoice", r#"{"invoice_id":"INV-1001"}"#, &token);
    world.call(2, "pay_invoice", PAY, &token);
    assert_eq!(executed_payments(&world), 1);
    // Every budget and invoice claim goes with the journal, so the PEP will pay it again.
    fs::remove_file(world.path("state/journal.jsonl")).unwrap();
    world.start_pep();
    let token = world.start_episode("pay");
    world.call(3, "get_invoice", r#"{"invoice_id":"INV-1001"}"#, &token);
    let replayed = world.call(4, "pay_invoice", PAY, &token);
    assert_eq!(
        text(&replayed, "/result/structuredContent/status").as_deref(),
        Some("executed"),
        "{replayed:?}"
    );
    assert_eq!(
        executed_payments(&world),
        1,
        "the provider executed it twice"
    );
    let keys: Vec<(String, String)> = world
        .lines("logs/tool-a.jsonl")
        .iter()
        .filter(|line| text(line, "/tool").as_deref() == Some("pay_invoice"))
        .map(|line| {
            (
                text(line, "/idempotency_key").unwrap(),
                text(line, "/entity_key").unwrap(),
            )
        })
        .collect();
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0].0, keys[1].0, "F-07's key differs per reservation");
    assert_eq!(keys[0].1, keys[1].1, "the invoice's does not");
    let broker = world.lines("logs/broker.jsonl");
    assert!(broker.iter().any(|line| {
        text(line, "/entity_key").as_deref() == Some(keys[0].1.as_str())
            && text(line, "/verdict").as_deref() == Some("forwarded")
    }));
    assert!(broker.iter().all(|line| line.get("broker_us").is_some()));
    let tool_log = world.lines("logs/tool-a.jsonl");
    assert!(tool_log.iter().all(|line| line.get("tool_us").is_some()));
}

/// RV5 D6: a tool's declines stop the intent, a restart does not reset them, and a decline does
/// not use the invoice up.
#[test]
fn a_tools_declines_stop_the_intent_across_a_restart() {
    const PAY: &str = r#"{"invoice_id":"INV-3003","amount":30000,"currency":"USD"}"#;
    let mut world = World::new(10_000, None).start();
    let token = world.start_episode("pay");
    world.call(1, "get_invoice", r#"{"invoice_id":"INV-3003"}"#, &token);
    for id in 2..5 {
        let reply = world.call(id, "pay_invoice", PAY, &token);
        assert_eq!(
            text(&reply, "/result/structuredContent/status").as_deref(),
            Some("declined"),
            "{reply:?}"
        );
    }
    assert!(denied(&world.call(5, "pay_invoice", PAY, &token)));
    let journal = world.lines("state/journal.jsonl");
    let declined = journal
        .iter()
        .filter(|line| text(line, "/result").as_deref() == Some("declined"))
        .count();
    assert_eq!(declined, 3);
    // A decline leaves the invoice's key unused, so a provider could still execute a retry.
    let dedupe = fs::read_to_string(world.path("state/dedupe-a.jsonl")).unwrap();
    assert_eq!(dedupe.lines().count(), 3);
    assert!(
        dedupe
            .lines()
            .all(|line| line.contains(r#""entity_key":null"#)),
        "{dedupe}"
    );
    world.start_pep();
    let token = world.start_episode("pay");
    world.call(6, "get_invoice", r#"{"invoice_id":"INV-1001"}"#, &token);
    assert!(denied(&world.call(
        7,
        "pay_invoice",
        r#"{"invoice_id":"INV-1001","amount":30000,"currency":"USD"}"#,
        &token
    )));
    assert_eq!(executed_payments(&world), 0);
}

/// The oracle must see a bypass. If it could not, every clean verdict would mean nothing: this
/// call skips the PEP and the broker, as a broken network boundary would let one.
#[test]
fn the_oracle_sees_a_call_that_skipped_the_pep() {
    let world = World::new(10_000, None).start();
    let mark = world.layout().mark().unwrap();
    let body = r#"{"jsonrpc":"2.0","id":"stray","method":"tools/call","params":{"name":"get_invoice","arguments":{"invoice_id":"INV-1001"}}}"#;
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer credential-a\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (status, _) = raw_at(&world.path("tool-a/tool.sock"), request.as_bytes());
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let logs = world.layout().read_from(&mark).unwrap();
    let verdict = oracle::judge(&logs, Expect::Deny);
    assert_eq!(verdict.executions, 1);
    let stray = "stray".to_owned();
    assert_eq!(
        verdict.findings,
        [
            Finding::ReachedTool {
                upstream_id: stray.clone()
            },
            Finding::NoBrokerHop { upstream_id: stray }
        ]
    );
}

/// G3's harness, end to end: what the capturing broker wrote down goes back through its socket.
/// Each proof is spent, so nothing runs a second time, and the oracle agrees.
#[test]
fn a_captured_proof_replays_to_nothing() {
    const PAY: &str = r#"{"invoice_id":"INV-1001","amount":30000,"currency":"USD"}"#;
    let mut world = World::new(10_000, None);
    world.capture = true;
    let world = world.start();
    let token = world.start_episode("pay");
    world.call(1, "get_invoice", r#"{"invoice_id":"INV-1001"}"#, &token);
    world.call(2, "pay_invoice", PAY, &token);
    let mark = world.layout().mark().unwrap();
    let (uid, gid) = ids();
    let injector = Command::new(env!("CARGO_BIN_EXE_stub-injector"))
        .arg("broker")
        .arg(world.path("broker/broker.sock"))
        .args([uid.to_string(), gid.to_string()])
        .arg(world.path("state/proofs.jsonl"))
        .output()
        .unwrap();
    let out = String::from_utf8(injector.stdout).unwrap();
    assert!(injector.status.success(), "{out}");
    assert!(out.ends_with("{\"accepted\":0,\"attempts\":2}\n"), "{out}");
    let logs = world.layout().read_from(&mark).unwrap();
    assert_eq!(oracle::judge(&logs, Expect::Deny).findings, []);
    // The replay cache refused each one, so the injector's requests reached it.
    assert_eq!(logs.broker.len(), 2);
    assert!(logs.broker.iter().all(|line| {
        text(line, "/reason").as_deref() == Some("call proof replayed")
            && text(line, "/verdict").as_deref() == Some("rejected")
    }));
}

fn outcomes(world: &World) -> Vec<String> {
    world
        .lines("state/journal.jsonl")
        .iter()
        .filter_map(|line| text(line, "/result"))
        .collect()
}

/// Every misbehaviour the tool server can be configured with (§2a). Whatever it answers, only an
/// explicit status settles a payment, and a forged outcome member is never believed.
#[test]
fn a_misbehaving_tool_cannot_settle_a_payment() {
    let mut world = World::new(10_000, None);
    world.upstream_ms = 1200;
    world.tool_a_extra = r#","misbehave":{"pay_invoice:INV-6001":"wrong_id","pay_invoice:INV-6002":"two_responses",
        "pay_invoice:INV-6003":"oversized","pay_invoice:INV-6004":"input_required","pay_invoice:INV-6005":"forged_outcome",
        "pay_invoice:INV-6006":"slow_drip","pay_invoice:INV-6007":"delay_ms:200"}"#
        .to_owned();
    let world = world.start();
    let token = world.start_episode("chaos");
    for (id, (invoice, expected)) in [
        ("INV-6001", "unknown"),
        ("INV-6002", "unknown"),
        ("INV-6003", "unknown"),
        ("INV-6004", "unknown"),
        ("INV-6005", "declined"),
        ("INV-6006", "unknown"),
        ("INV-6007", "executed"),
    ]
    .into_iter()
    .enumerate()
    {
        let id = u64::try_from(id).unwrap() * 2 + 1;
        world.call(
            id,
            "get_invoice",
            &format!(r#"{{"invoice_id":"{invoice}"}}"#),
            &token,
        );
        let reply = world.call(
            id + 1,
            "pay_invoice",
            &format!(r#"{{"invoice_id":"{invoice}","amount":1000,"currency":"USD"}}"#),
            &token,
        );
        assert_eq!(
            outcomes(&world).last().map(String::as_str),
            Some(expected),
            "{invoice}: {reply:?}"
        );
    }
    // The forged member never reached the PEP's books, and the tool logged what really happened.
    let journal = outcomes(&world);
    assert_eq!(
        journal.iter().filter(|o| *o == "executed").count(),
        1,
        "{journal:?}"
    );
    oracle_join(&world);
    // O1's residence leaves the upstream leg out, so INV-6007's 200 ms at the tool is in neither
    // hop's figure, and the slowest of all would show it if it were.
    let slowest = |log: &str, field: &str| {
        world
            .lines(log)
            .iter()
            .filter_map(|line| line.get(field).and_then(JcsValue::as_i64))
            .max()
            .unwrap()
    };
    assert!(slowest("logs/decisions.jsonl", "pep_us") > 0);
    assert!(slowest("logs/decisions.jsonl", "pep_us") < 150_000);
    assert!(slowest("logs/broker.jsonl", "broker_us") > 0);
    assert!(slowest("logs/broker.jsonl", "broker_us") < 150_000);
}

/// The drift modes, seen by the poll at boot. Step 10 runs the same poll on a timer.
#[test]
fn a_server_that_drifts_is_quarantined_at_the_next_poll() {
    for (change, page_size) in [
        ("description", ""),
        ("last_page", r#","page_size":1"#),
        ("x_mcp_header", ""),
    ] {
        let mut world = World::new(10_000, None);
        let flag = world.path("state/drift");
        world.tool_a_extra = format!(
            r#"{page_size},"drift":{{"flag":"{}","change":"{change}"}}"#,
            flag.display()
        );
        let mut world = world.start();
        let token = world.start_episode("pay");
        let read = world.call(1, "get_invoice", r#"{"invoice_id":"INV-1001"}"#, &token);
        assert!(read.get("result").is_some(), "{change}: {read:?}");
        fs::write(&flag, "").unwrap();
        world.start_pep();
        let token = world.start_episode("pay");
        let read = world.call(2, "get_invoice", r#"{"invoice_id":"INV-1001"}"#, &token);
        assert!(denied(&read), "{change}: {read:?}");
        let quarantined = world
            .lines("state/journal.jsonl")
            .iter()
            .any(|line| text(line, "/type").as_deref() == Some("quarantine"));
        assert!(quarantined, "{change}");
    }
}
