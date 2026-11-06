//! RV5: randomized checks with no external fuzzer. Parsers must never panic on hostile bytes, an
//! Episode Token or Call Proof must have exactly one accepted encoding, and the engine's books
//! must hold under any sequence of agent calls, upstream replies and settlements.
//!
//! `RV5_FUZZ_SECS` sets the budget per test (default 5). Run in debug, so overflow checks fire.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr,
    clippy::as_conversions,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    missing_docs
)]

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Barrier, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use pep_sidecar::engine::{
    AbortOutcome, AmountBinding, ArgRole, ArgSpec, Confidentiality, Decision, EffectClass,
    Entities, EntityClaims, EntityKind, EntitySet, HostAuthority, InMemoryLabelStore, Integrity,
    KeyPolicy, Label, Ledger, Limits, PepEngine, PepIntent, ResState, SeqPolicy, ServerStates,
    Settlement, Shared, ToolPins, ToolPolicy, UnresolvedEntities,
};
use pep_sidecar::http::{self, Deadlines, TimedRead};
use pep_sidecar::jcs::{self, ParseOptions};
use pep_sidecar::tokens::{
    CallProofClaims, CallProofExpectations, EpisodeClaims, Es256Signer, ReplayCache,
    issue_call_proof, mint_episode_token, verify_call_proof,
};
use pep_sidecar::{config, control, forward, journal, mcp};

fn budget() -> Duration {
    Duration::from_secs(
        std::env::var("RV5_FUZZ_SECS")
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(5),
    )
}

/// xorshift64*: deterministic, so a failure can be replayed from its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, limit: usize) -> usize {
        (self.next() % (limit.max(1) as u64)) as usize
    }
    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
}

const INTERESTING: &[&[u8]] = &[
    b"\"",
    b"\\",
    b"\\u",
    b"\\ud800",
    b"\\udc00",
    b"\\u0000",
    b"{",
    b"}",
    b"[",
    b"]",
    b":",
    b",",
    b"0",
    b"-0",
    b"00",
    b"1e400",
    b"-1e400",
    b"1E+2",
    b".5",
    b"9007199254740993",
    b"18446744073709551616",
    b"null",
    b"true",
    b"\xEF\xBB\xBF",
    b"\xC0\x80",
    b"\xED\xA0\x80",
    b"\xF4\x90\x80\x80",
    b"\r\n",
    b"\n",
    b"\r",
    b"\t",
    b" ",
    b"\x00",
    b"\x7f",
    b"\xFF",
    b"\xCC\x81",
    b"\xE2\x84\xAA",
    b"\xEF\xB7\x90",
    b"=?base64?",
    b"?=",
    b"~0",
    b"~1",
    b"/",
    b"Content-Length: 5\r\n",
    b"Content-Length: 99999999999999999999\r\n",
    b"Transfer-Encoding: chunked\r\n",
    b"Host: x\r\n",
    b"Host: y\r\n",
    b"Mcp-Param-X: 1\r\n",
    b"\r\n\r\n",
    b"HTTP/1.0",
    b"HTTP/2.0",
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
];

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut out = seed.to_vec();
    for _ in 0..=rng.below(6) {
        match rng.below(6) {
            0 if !out.is_empty() => {
                let at = rng.below(out.len());
                out[at] ^= 1 << rng.below(8);
            }
            1 if !out.is_empty() => {
                let at = rng.below(out.len());
                out[at] = rng.next() as u8;
            }
            2 if !out.is_empty() => {
                let from = rng.below(out.len());
                let to = (from + rng.below(32)).min(out.len());
                out.drain(from..to);
            }
            3 => {
                let at = rng.below(out.len() + 1);
                let piece = INTERESTING[rng.below(INTERESTING.len())];
                out.splice(at..at, piece.iter().copied());
            }
            4 if !out.is_empty() => {
                let from = rng.below(out.len());
                let to = (from + rng.below(64)).min(out.len());
                let chunk = out[from..to].to_vec();
                let at = rng.below(out.len() + 1);
                out.splice(at..at, chunk);
            }
            _ => {
                out.truncate(rng.below(out.len() + 1));
            }
        }
    }
    out
}

/// A stream over fixed bytes, for the HTTP reader.
struct Bytes<'a> {
    data: &'a [u8],
    chunk: usize,
}

impl io::Read for Bytes<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = buffer.len().min(self.data.len()).min(self.chunk);
        buffer[..count].copy_from_slice(&self.data[..count]);
        self.data = &self.data[count..];
        Ok(count)
    }
}

impl TimedRead for Bytes<'_> {
    fn set_read_timeout(&mut self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

const REQUEST: &[u8] = b"POST /mcp HTTP/1.1\r\nHost: pep.local\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: =?base64?Z2V0X25vdGU=?=\r\nPep-Episode: abc\r\nContent-Length: 192\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"method\":\"tools/call\",\"params\":{\"name\":\"get_note\",\"arguments\":{\"key\":\"a\"},\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}";

const JSON_SEEDS: &[&[u8]] = &[
    br#"{"a":[1,2.5,-0,1e3,"x\u00e9\ud83d\ude00",{"b":null,"c":true}],"\u00e9":"\u0065\u0301"}"#,
    br#"{"call":"approve","eid":"01JBAE0Z1TFCQ9Y41W9NF6YYMB","rid":1,"action_digest":"sha-256:x","amount_minor":5}"#,
    br#"{"call":"trusted_input","eid":"01JBAE0Z1TFCQ9Y41W9NF6YYMB","input_id":"i","value":{"entity":"x","amount_minor":5},"conf":"public"}"#,
    br#"{"type":"reserve","amount_minor":5,"action_digest":"d","currency":"USD","eid":"01JBAE0Z1TFCQ9Y41W9NF6YYMB","entity":"e","idempotency_key":"k","intent":"p","rid":1}"#,
    br#"{"type":"taint","writer":"01JBAE0Z1TFCQ9Y41W9NF6YYMB","label":{"conf":"secret","integ":"trusted"},"indexes":[{"location":{"uri":"n://a","key":"k"}},{"content":"sha-256:x"}]}"#,
    br#"{"id":"01JBAE0Z1TFCQ9Y41W9NF6YYMB","jsonrpc":"2.0","result":{"resultType":"complete","_meta":{"dev.pep-sidecar/outcome":"executed"},"content":[]}}"#,
];

#[test]
fn parsers_never_panic_on_hostile_bytes() {
    let until = Instant::now() + budget();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut runs = 0u64;
    while Instant::now() < until {
        let seed = JSON_SEEDS[rng.below(JSON_SEEDS.len())];
        let bytes = mutate(&mut rng, seed);
        drop(jcs::parse(&bytes));
        drop(jcs::parse_with(&bytes, &ParseOptions::definition()));
        drop(jcs::parse_with(&bytes, &ParseOptions::result(1024, 64)));
        drop(control::parse(&bytes));
        drop(journal::Record::parse(&bytes));
        drop(forward::read_upstream_reply(
            &bytes,
            "01JBAE0Z1TFCQ9Y41W9NF6YYMB",
        ));
        drop(config::load(&bytes));
        let wire = mutate(&mut rng, REQUEST);
        let at = Instant::now() + Duration::from_secs(1);
        let mut stream = Bytes {
            data: &wire,
            chunk: 1 + rng.below(4096),
        };
        if let Ok(request) =
            http::read_request(&mut stream, "/mcp", Deadlines { head: at, body: at })
            && let Ok(mcp::Inbound::Request(agent)) = mcp::check(&request.head, &request.body)
        {
            let _ = agent.episode_token();
            drop(agent.engine_request("01JBAE0Z1TFCQ9Y41W9NF6YYMB"));
        }
        let mut stream = Bytes {
            data: &wire,
            chunk: 1 + rng.below(4096),
        };
        drop(http::read_response(&mut stream, at, 1 << 20));
        runs += 1;
    }
    eprintln!("parsers: {runs} rounds, no panic");
}

/// A Call Proof is the one token the system verifies by signature: the PEP admits an Episode Token
/// by its exact bytes (T1). So it must have exactly one accepted encoding.
#[test]
fn a_call_proof_has_exactly_one_accepted_encoding() {
    let mut entropy = Rng(7);
    let mut bytes = [0u8; 32];
    for byte in &mut bytes {
        *byte = entropy.next() as u8;
    }
    let key = Es256Signer::from_secret_bytes(&bytes).unwrap();
    let digest = format!("sha-256:{}", "A".repeat(43));
    let episode = EpisodeClaims {
        eid: 5,
        intent_digest: digest.clone(),
        sub: "s".to_owned(),
        client_id: "c".to_owned(),
        peer_uid: 20001,
        release_epoch: 7,
        rar_digest: digest.clone(),
        iat: 1_000,
        exp: 2_000,
    };
    let token = mint_episode_token(&key, &episode).unwrap();
    let proof_claims = CallProofClaims {
        jti: "AAAA".to_owned(),
        iat: 1_500,
        exp: 1_560,
        eid: 5,
        server_id: "a".to_owned(),
        action_digest: digest.clone(),
        release_epoch: 7,
        tool_schema_digest: digest.clone(),
        payment: None,
    };
    let proof = issue_call_proof(&key, &proof_claims).unwrap();
    let expect = CallProofExpectations {
        server_id: "a",
        release_epoch: 7,
        tool_schema_digest: &digest,
        action_digest: &digest,
        payment: None,
    };
    let verifier = key.verifier();
    let cache = ReplayCache::new(16, 0, 2);
    let verify = |text: &str| verify_call_proof(text, &verifier, &expect, &cache, 1_500);
    // An Episode Token under the same key is still no proof.
    assert!(verify(&token).is_err());

    let until = Instant::now() + budget();
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    let mut runs = 0u64;
    let mut accepted_mutants = 0u64;
    while Instant::now() < until {
        let mutant = mutate(&mut rng, proof.as_bytes());
        if mutant == proof.as_bytes() {
            continue;
        }
        let Ok(text) = String::from_utf8(mutant) else {
            continue;
        };
        if verify(&text).is_ok() {
            accepted_mutants += 1;
            eprintln!("accepted mutant: {text}");
        }
        runs += 1;
    }
    // The signature's other encodings: padding, the standard alphabet, trailing bits.
    let (input, signature) = proof.rsplit_once('.').unwrap();
    let raw = URL_SAFE_NO_PAD.decode(signature).unwrap();
    for variant in [
        format!("{input}.{signature}="),
        format!("{input}.{}", signature.replace('-', "+").replace('_', "/")),
        format!("{proof}."),
        format!(".{proof}"),
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(&raw[..63])),
    ] {
        if variant != proof {
            assert!(verify(&variant).is_err(), "{variant}");
        }
    }
    eprintln!("proofs: {runs} mutants, {accepted_mutants} accepted");
    assert_eq!(accepted_mutants, 0);
    // The real one passes, once.
    assert!(verify(&proof).is_ok());
    assert!(verify(&proof).is_err());
}

fn tool(name: &str, effect: EffectClass, args: Vec<ArgSpec>) -> ToolPolicy {
    ToolPolicy {
        name: name.to_owned(),
        server_id: "a".to_owned(),
        schema_digest: format!("sha-256:{name}"),
        effect,
        args,
        store_uri: None,
        sink_clearance: Confidentiality::Secret,
        destinations: BTreeMap::new(),
        output_label: Label::new(Confidentiality::Internal, Integrity::UntrustedExternal),
        trusted_fields: BTreeSet::new(),
        amount_binding: None,
        max_result_bytes: 4096,
        max_result_nodes: 256,
    }
}

fn spec(pointer: &str, role: ArgRole) -> ArgSpec {
    ArgSpec {
        pointer: pointer.to_owned(),
        role,
    }
}

fn pins() -> ToolPins {
    let mut lookup = tool(
        "get_invoice",
        EffectClass::ReadOnly,
        vec![spec("/invoice_id", ArgRole::StoreKey)],
    );
    lookup.store_uri = Some("billing://invoices".to_owned());
    lookup.output_label = Label::new(Confidentiality::Internal, Integrity::Trusted);
    lookup.trusted_fields = [
        "/structuredContent/amount_due_minor".to_owned(),
        "/structuredContent/currency".to_owned(),
    ]
    .into();
    let mut pay = tool(
        "pay_invoice",
        EffectClass::Payment,
        vec![
            spec("/invoice_id", ArgRole::Entity(EntityKind::Invoice)),
            spec("/amount", ArgRole::Amount),
            spec("/currency", ArgRole::Currency),
            spec("/memo", ArgRole::Data),
        ],
    );
    pay.sink_clearance = Confidentiality::Internal;
    pay.amount_binding = Some(AmountBinding {
        lookup_tool: "get_invoice".to_owned(),
        entity_arg_pointer: "/invoice_id".to_owned(),
        lookup_entity_pointer: "/invoice_id".to_owned(),
        result_amount_pointer: "/structuredContent/amount_due_minor".to_owned(),
        result_currency_pointer: "/structuredContent/currency".to_owned(),
    });
    let mut write = tool(
        "update_invoice",
        EffectClass::MutatingInternal,
        vec![
            spec("/invoice_id", ArgRole::StoreKey),
            spec("/text", ArgRole::StoreWrite),
        ],
    );
    write.store_uri = Some("billing://invoices".to_owned());
    let mut secret = tool(
        "get_secret",
        EffectClass::ReadOnly,
        vec![spec("/id", ArgRole::Data)],
    );
    secret.output_label = Label::new(Confidentiality::Secret, Integrity::UntrustedExternal);
    let mut sink = tool(
        "post_public",
        EffectClass::MutatingExternal,
        vec![spec("/text", ArgRole::Data)],
    );
    sink.sink_clearance = Confidentiality::Public;
    ToolPins {
        release_epoch: 7,
        lockfile_digest: "sha-256:lock".to_owned(),
        stores: [(
            "billing://invoices".to_owned(),
            KeyPolicy {
                case_insensitive: true,
            },
        )]
        .into(),
        tools: [lookup, pay, write, secret, sink]
            .into_iter()
            .map(|tool| (tool.name.clone(), tool))
            .collect(),
    }
}

/// How many invoices the intent names; the model also tries one it does not.
const INVOICES: usize = 64;

/// The process's one capability, shared by the tests that need it.
fn host_authority() -> &'static HostAuthority {
    static HOST: OnceLock<HostAuthority> = OnceLock::new();
    HOST.get_or_init(|| HostAuthority::claim().unwrap())
}

/// One invoice, one payment, however many intents race for it (V1): four intents name the same
/// invoices, and each tries to pay every one at the same moment, on its own thread.
#[test]
fn intents_racing_for_every_invoice_pay_each_once() {
    const RACERS: usize = 4;
    for run in 0..8u128 {
        let shared = Shared {
            labels: Arc::new(InMemoryLabelStore::with_capacity(1 << 16)),
            servers: Arc::new(ServerStates::empty()),
            unresolved: Arc::new(UnresolvedEntities::empty()),
            claims: Arc::new(EntityClaims::empty()),
        };
        shared.servers.set_serving("a").unwrap();
        let barrier = Arc::new(Barrier::new(RACERS));
        let racers: Vec<_> = (0..RACERS as u128)
            .map(|racer| {
                let shared = shared.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let intent = PepIntent {
                        episode_id: run * 100 + racer + 1,
                        intent_digest: format!("sha-256:intent-{racer}"),
                        release_epoch: 7,
                        lockfile_digest: "sha-256:lock".to_owned(),
                        limits: Limits {
                            currency: "USD".to_owned(),
                            per_call_max_minor: 50_000,
                            cumulative_max_minor: 10_000_000,
                            max_calls: 1000,
                            step_up_over_minor: 50_000,
                            max_declines: 3,
                        },
                        entities: Entities {
                            ids: EntitySet::InvoiceIds(
                                (0..INVOICES).map(|index| format!("INV-{index}")).collect(),
                            ),
                            per_entity_max_uses: 1,
                        },
                    };
                    let mut engine = PepEngine::new(
                        host_authority(),
                        intent,
                        pins(),
                        SeqPolicy::Unconstrained,
                        shared,
                        Ledger::empty(),
                    )
                    .unwrap();
                    let mut paid = Vec::new();
                    for invoice in 0..INVOICES {
                        let lookup = format!(
                            r#"{{"id":"l{invoice}","jsonrpc":"2.0","method":"tools/call","params":{{"name":"get_invoice","arguments":{{"invoice_id":"INV-{invoice}"}}}}}}"#
                        );
                        let Ok(Decision::Allow(allowed)) = engine.evaluate_raw(lookup.as_bytes())
                        else {
                            panic!("a lookup of INV-{invoice} was refused");
                        };
                        let result = format!(
                            r#"{{"resultType":"complete","content":[],"structuredContent":{{"invoice_id":"INV-{invoice}","amount_due_minor":10000,"currency":"USD"}}}}"#
                        );
                        engine
                            .record_result_raw(&allowed.call_id, result.as_bytes())
                            .unwrap();
                        let pay = format!(
                            r#"{{"id":"p{invoice}","jsonrpc":"2.0","method":"tools/call","params":{{"name":"pay_invoice","arguments":{{"invoice_id":"INV-{invoice}","amount":10000,"currency":"USD"}}}}}}"#
                        );
                        barrier.wait();
                        if let Ok(Decision::Allow(_)) = engine.evaluate_raw(pay.as_bytes()) {
                            paid.push(invoice);
                        }
                    }
                    paid
                })
            })
            .collect();
        let mut uses = vec![0u32; INVOICES];
        let mut by_racer = Vec::new();
        for racer in racers {
            let paid = racer.join().unwrap();
            by_racer.push(paid.len());
            for invoice in paid {
                uses[invoice] += 1;
            }
        }
        assert!(
            uses.iter().all(|&count| count == 1),
            "uses per invoice {uses:?}"
        );
        if run == 0 {
            eprintln!("race: {INVOICES} invoices won per racer: {by_racer:?}");
        }
    }
}

/// The engine's books under any sequence of calls, replies and settlements (F-06, F-10, F-14,
/// F-15). Replies come from a hostile model of the tool servers.
#[test]
fn the_engines_books_hold_under_any_sequence() {
    let host = host_authority();
    let cumulative = 1_500_000u64;
    let per_call = 50_000u64;
    let max_calls = 150u32;
    let until = Instant::now() + budget();
    let mut rng = Rng(0x0123_4567_89AB_CDEF);
    let mut episodes = 0u64;
    let mut steps = 0u64;
    let mut allowed_payments = 0u64;
    let shared = Shared {
        labels: Arc::new(InMemoryLabelStore::with_capacity(1 << 20)),
        servers: Arc::new(ServerStates::empty()),
        unresolved: Arc::new(UnresolvedEntities::empty()),
        claims: Arc::new(EntityClaims::empty()),
    };
    shared.servers.set_serving("a").unwrap();
    while Instant::now() < until {
        episodes += 1;
        let mut shared_now = shared.clone();
        shared_now.unresolved = Arc::new(UnresolvedEntities::empty());
        shared_now.claims = Arc::new(EntityClaims::empty());
        shared_now.labels = Arc::new(InMemoryLabelStore::with_capacity(1 << 20));
        let intent = |eid: u128| PepIntent {
            episode_id: eid,
            intent_digest: "sha-256:i".to_owned(),
            release_epoch: 7,
            lockfile_digest: "sha-256:lock".to_owned(),
            limits: Limits {
                currency: "USD".to_owned(),
                per_call_max_minor: per_call,
                cumulative_max_minor: cumulative,
                max_calls,
                step_up_over_minor: 30_000,
                max_declines: 3,
            },
            entities: Entities {
                ids: EntitySet::InvoiceIds(
                    (0..INVOICES).map(|index| format!("INV-{index}")).collect(),
                ),
                per_entity_max_uses: 1,
            },
        };
        let mut ledger = Ledger::empty();
        // Several episodes of one intent, each from the last one's ledger (E1, R1).
        let mut committed_total = 0u64;
        for segment in 0..3u128 {
            let mut engine = PepEngine::new(
                host,
                intent(segment + 1),
                pins(),
                SeqPolicy::Unconstrained,
                shared_now.clone(),
                ledger.clone(),
            )
            .unwrap();
            let mut next_id = 0u64;
            let mut last_amounts: BTreeMap<String, i64> = BTreeMap::new();
            let mut tainted: BTreeSet<String> = BTreeSet::new();
            for _ in 0..400 {
                steps += 1;
                next_id += 1;
                let id = format!("\"c{next_id}\"");
                // One invoice in 16 is outside the intent (`INV-64`).
                let entity = format!("INV-{}", rng.below(INVOICES + INVOICES / 16));
                let entity = entity.as_str();
                let amount = [10_000i64, 25_000, 40_000, 60_000, 0, -5][rng.below(6)];
                let request = match rng.below(100) {
                    0..=47 => format!(
                        r#"{{"id":{id},"jsonrpc":"2.0","method":"tools/call","params":{{"name":"get_invoice","arguments":{{"invoice_id":"{entity}"}}}}}}"#
                    ),
                    48..=96 => {
                        let declared = last_amounts.get(entity).copied().filter(|_| !rng.chance(4));
                        let declared = declared.unwrap_or(amount);
                        format!(
                            r#"{{"id":{id},"jsonrpc":"2.0","method":"tools/call","params":{{"name":"pay_invoice","arguments":{{"invoice_id":"{entity}","amount":{declared},"currency":"USD"}}}}}}"#
                        )
                    }
                    97 | 98 => format!(
                        r#"{{"id":{id},"jsonrpc":"2.0","method":"tools/call","params":{{"name":"update_invoice","arguments":{{"invoice_id":"{entity}","text":"written by the agent"}}}}}}"#
                    ),
                    _ => format!(
                        r#"{{"id":{id},"jsonrpc":"2.0","method":"tools/call","params":{{"name":"get_secret","arguments":{{"id":"x"}}}}}}"#
                    ),
                };
                // Through the raw path, as the actor does.
                let decision = engine.evaluate_raw(request.as_bytes());
                let state = engine.state();
                let (call_id, rid, tool) = match decision {
                    Ok(Decision::Allow(allowed)) => (
                        allowed.call_id,
                        allowed.reservation.map(|ticket| ticket.reservation_id),
                        allowed.tool,
                    ),
                    Ok(Decision::StepUpRequired(pending)) => {
                        assert!(pending.amount_minor > 30_000, "F-15: step-up below the bar");
                        (pending.call_id, Some(pending.reservation_id), pending.tool)
                    }
                    Err(_) => {
                        check_books(&engine, cumulative, per_call, max_calls);
                        continue;
                    }
                };
                let _ = state;
                if tool == "update_invoice" {
                    tainted.insert(entity.to_ascii_lowercase());
                }
                if let Some(rid) = rid {
                    allowed_payments += 1;
                    // F-14: the amount is the latest lookup's, and the location was not tainted.
                    let reservation = engine.state().budget.reservations[&rid].clone();
                    assert_eq!(
                        last_amounts.get(&reservation.entity).copied(),
                        Some(i64::try_from(reservation.amount_minor).unwrap()),
                        "an amount with no matching lookup"
                    );
                    let index: usize = reservation
                        .entity
                        .strip_prefix("INV-")
                        .unwrap()
                        .parse()
                        .unwrap();
                    assert!(index < INVOICES, "an entity outside the intent");
                    if reservation.state == ResState::AwaitingStepUp {
                        // F-15: no forwarding before approval.
                        assert!(engine.mark_forwarded(rid).is_err());
                        if rng.chance(2) {
                            engine.approve_step_up(host, rid).unwrap();
                        } else {
                            engine.release_unforwarded(rid).unwrap();
                            check_books(&engine, cumulative, per_call, max_calls);
                            continue;
                        }
                    }
                    if rng.chance(8) {
                        engine.release_unforwarded(rid).unwrap();
                        check_books(&engine, cumulative, per_call, max_calls);
                        continue;
                    }
                    engine.mark_forwarded(rid).unwrap();
                    // Once forwarded, the agent's path can no longer end it (P1).
                    assert!(engine.release_unforwarded(rid).is_err());
                    let settlement = match rng.below(3) {
                        0 => Settlement::Executed,
                        1 => Settlement::Aborted(AbortOutcome::DefinitelyNotExecuted),
                        _ => Settlement::Aborted(AbortOutcome::Unknown),
                    };
                    engine.settle(host, rid, settlement).unwrap();
                    if settlement == Settlement::Executed {
                        committed_total += engine.state().budget.reservations[&rid].amount_minor;
                        drop(engine.record_result_raw(
                            &call_id,
                            br#"{"resultType":"complete","content":[]}"#,
                        ));
                        let _ = engine.abandon(&call_id);
                    }
                    check_books(&engine, cumulative, per_call, max_calls);
                    continue;
                }
                // A non-payment reply, sometimes hostile.
                let result = match (tool.as_str(), rng.below(8)) {
                    ("get_invoice", 0) => {
                        br#"{"resultType":"input_required","structuredContent":{"amount_due_minor":1,"currency":"USD"}}"#
                            .to_vec()
                    }
                    ("get_invoice", 1) => {
                        br#"{"isError":"true","resultType":"complete","structuredContent":{"amount_due_minor":1,"currency":"USD"}}"#
                            .to_vec()
                    }
                    ("get_invoice", 2) => b"{".to_vec(),
                    ("get_invoice", _) => {
                        let due = [10_000, 25_000, 40_000, 60_000][rng.below(4)];
                        format!(
                            r#"{{"resultType":"complete","structuredContent":{{"amount_due_minor":{due},"currency":"USD"}}}}"#
                        )
                        .into_bytes()
                    }
                    _ => br#"{"resultType":"complete","content":[{"type":"text","text":"ok"}]}"#.to_vec(),
                };
                let recorded = engine.record_result_raw(&call_id, &result);
                if tool == "get_invoice" {
                    if recorded.is_ok()
                        && result.windows(10).all(|window| window != br#""isError":"#)
                    {
                        let value = jcs::parse_with(&result, &ParseOptions::definition())
                            .unwrap()
                            .value;
                        if let Some(due) = value
                            .pointer("/structuredContent/amount_due_minor")
                            .and_then(jcs::JcsValue::as_i64)
                            && value.get("resultType").and_then(jcs::JcsValue::as_str)
                                == Some("complete")
                        {
                            if tainted.contains(&entity.to_ascii_lowercase()) {
                                last_amounts.remove(entity);
                            } else {
                                last_amounts.insert(entity.to_owned(), due);
                            }
                        }
                    } else if recorded.is_ok() {
                        last_amounts.remove(entity);
                    }
                }
                if recorded.is_err() {
                    let _ = engine.abandon(&call_id);
                }
                check_books(&engine, cumulative, per_call, max_calls);
            }
            ledger = engine.ledger();
            assert_eq!(
                ledger.committed_minor, committed_total,
                "the ledger lost or invented a commit"
            );
        }
    }
    eprintln!(
        "engine: {episodes} intents, {steps} steps, {allowed_payments} payments reserved; the books held"
    );
    // About one step in 200 reserves a payment. Any budget must keep that, or the model has
    // stopped testing the books.
    assert!(
        allowed_payments * 1000 > steps,
        "the model hardly paid: it tests nothing"
    );
}

fn check_books(engine: &PepEngine, cumulative: u64, per_call: u64, max_calls: u32) {
    let state = engine.state();
    let budget = &state.budget;
    let live: u64 = budget
        .reservations
        .values()
        .filter(|reservation| {
            matches!(
                reservation.state,
                ResState::Held
                    | ResState::AwaitingStepUp
                    | ResState::Forwarded
                    | ResState::NeedsReconcile
            )
        })
        .map(|reservation| reservation.amount_minor)
        .sum::<u64>()
        + budget
            .restored
            .values()
            .map(|restored| restored.amount_minor)
            .sum::<u64>();
    assert_eq!(
        budget.reserved, live,
        "reserved is not the sum of live reservations"
    );
    assert!(
        budget.reserved + budget.committed <= cumulative,
        "past the cumulative cap"
    );
    assert!(budget.calls <= max_calls, "past max_calls");
    for uses in budget.entity_uses.values() {
        assert!(*uses <= 1, "past per_entity_max_uses");
    }
    for reservation in budget.reservations.values() {
        assert!(reservation.amount_minor <= per_call, "past per_call_max");
    }
}
