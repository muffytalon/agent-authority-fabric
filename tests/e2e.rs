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
    pins: JcsValue,
    children: Vec<Child>,
    pep: Option<Child>,
    step_up_ms: u64,
    broker_credential_b: String,
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
        let pins = jcs::parse_with(PINS.as_bytes(), &ParseOptions::definition())
            .unwrap()
            .value;
        let world = Self {
            base,
            pins,
            children: Vec::new(),
            pep: None,
            step_up_ms,
            broker_credential_b: credential_b
                .map_or_else(|| "credential-b".to_owned(), str::to_owned),
        };
        world.write_files();
        world
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
        fs::write(self.path("pins.json"), PINS).unwrap();
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
            "INV-4004":{"amount_due_minor":30000,"currency":"USD","status":"pending"}}"#;
        for server in ["a", "b"] {
            fs::write(
                self.path(&format!("tool-{server}.json")),
                format!(
                    r#"{{"server_id":"{server}","listen":"unix:{}","verifier":"{}","pins":"{}","store":"{}","log":"{}","invoices":{invoices}}}"#,
                    p(&format!("tool-{server}/tool.sock")),
                    p(&format!("secrets/verifier-{server}")),
                    p("pins.json"),
                    p(&format!("state/dedupe-{server}.jsonl")),
                    p(&format!("logs/tool-{server}.jsonl")),
                ),
            )
            .unwrap();
        }
        fs::write(
            self.path("broker.json"),
            format!(
                r#"{{"socket":"{}","pep":{{"uid":{uid},"gid":{gid}}},"pep_key":"{}","pins":"{}",
                "routes":{{"a":{{"endpoint":"unix:{}","credential":"{}"}},"b":{{"endpoint":"unix:{}","credential":"{}"}}}},
                "replay_cache_entries":1000,"clock_skew_ms":2000,"connections":16,"upstream_timeout_ms":5000,"log":"{}"}}"#,
                p("broker/broker.sock"),
                p("pub/call-proof.pub"),
                p("pins.json"),
                p("tool-a/tool.sock"),
                p("secrets/cred-a"),
                p("tool-b/tool.sock"),
                p("secrets/cred-b"),
                p("logs/broker.jsonl"),
            ),
        )
        .unwrap();
        let digest = jcs::digest_value(&self.pins);
        let intent = |kind: &str, ids: &str| {
            format!(
                r#"{{"release_epoch":7,"lockfile_digest":"{digest}","limits":{{"currency":"USD","per_call_max_minor":100000,"cumulative_max_minor":500000,"max_calls":5,"step_up_over_minor":50000}},
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
                  "upstream_timeout_ms":5000,"step_up_timeout_ms":{},"episode_idle_ms":600000,"episodes":4,"call_burst":50,"call_rate_per_s":50,
                  "clock_skew_ms":2000,"replay_cache_entries":1000}},
                "intents":{{"pay":{},"notes":{}}},"pins":{PINS}}}"#,
                p("pep/agent.sock"),
                p("ctl/ctl.sock"),
                p("broker/broker.sock"),
                p("pub"),
                p("state/journal.jsonl"),
                p("state/journal.lock"),
                p("logs/decisions.jsonl"),
                self.step_up_ms,
                intent("invoice", r#"["INV-1001","INV-2002","INV-3003","INV-4004"]"#),
                intent("recipient", r#"["rcpt_A"]"#),
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
        for server in ["a", "b"] {
            let mut child = Self::spawn(
                env!("CARGO_BIN_EXE_stub-tool"),
                &self.path(&format!("tool-{server}.json")),
            );
            wait_for_socket(&self.path(&format!("tool-{server}/tool.sock")), &mut child);
            self.children.push(child);
        }
        let mut broker = Self::spawn(env!("CARGO_BIN_EXE_stub-broker"), &self.path("broker.json"));
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
        fs::read_to_string(self.path(log))
            .unwrap_or_default()
            .lines()
            .map(|line| {
                jcs::parse_with(line.as_bytes(), &ParseOptions::definition())
                    .unwrap()
                    .value
            })
            .collect()
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
        .find(|line| text(line, "/idempotency_key").as_deref() == Some(key.as_str()))
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
    assert_eq!(outcomes, ["executed", "executed", "refused", "unknown"]);
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
