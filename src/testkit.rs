//! A whole PEP for tests: pins, a journal in a temporary directory, a registry, and a
//! scripted broker.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::actor::{Services, Upstream, UpstreamFailure};
use crate::config::IntentConfig;
use crate::engine::{
    Entities, EntityClaims, EntitySet, HostAuthority, InMemoryLabelStore, Limits, PepIntent,
    SeqPolicy, ServerStates, Shared, UnresolvedEntities,
};
use crate::forward::UpstreamRequest;
use crate::jcs::{self, JcsValue, ParseOptions};
use crate::journal::{Journal, spawn_writer};
use crate::lockfile::{Lockfile, parse_payload};
use crate::registry::{Registry, RegistryConfig};
use crate::tokens::{Es256Signer, os_entropy, unix_now};

/// On server `a`: a read tool, `get_ticket`; a bound lookup, `get_invoice`; and a payment,
/// `pay_invoice`.
pub(crate) const PINS: &str = r#"{"lockfile_version":1,"release_epoch":7,
  "stores":{"billing://invoices":{"case_insensitive":true}},
  "servers":{"a":{"endpoint":"http://a/mcp","identity":"spiffe://a","protocol_version":"2026-07-28","discover":{},"tools":{
    "get_ticket":{"definition":{"name":"get_ticket","inputSchema":{"type":"object"}},"policy":{"effect":"read","args":[{"pointer":"/id","role":"data"}],
      "sink_clearance":"confidential","output_label":{"conf":"internal","integ":"untrusted_external"},"max_result_bytes":65536,"max_result_nodes":1024}},
    "get_invoice":{"definition":{"name":"get_invoice"},"policy":{"effect":"read","args":[{"pointer":"/invoice_id","role":"store_key"}],
      "store_uri":"billing://invoices","sink_clearance":"secret","output_label":{"conf":"internal","integ":"trusted"},
      "trusted_fields":["/structuredContent/amount_due_minor","/structuredContent/currency"],"max_result_bytes":65536,"max_result_nodes":1024}},
    "pay_invoice":{"definition":{"name":"pay_invoice"},"policy":{"effect":"mutating_financial",
      "args":[{"pointer":"/invoice_id","role":"entity","kind":"invoice"},{"pointer":"/amount","role":"amount"},{"pointer":"/currency","role":"currency"}],
      "sink_clearance":"internal","output_label":{"conf":"internal","integ":"untrusted_external"},
      "amount_binding":{"lookup_tool":"get_invoice","entity_arg_pointer":"/invoice_id","lookup_entity_pointer":"/invoice_id",
        "result_amount_pointer":"/structuredContent/amount_due_minor","result_currency_pointer":"/structuredContent/currency"},
      "max_result_bytes":65536,"max_result_nodes":1024}}}}}}"#;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A broker that keeps each request and answers: `get_invoice` with INV-1001 due 60,000 USD,
/// `pay_invoice` executed, and anything else with one text result.
#[derive(Default)]
pub(crate) struct Echo {
    pub(crate) requests: Mutex<Vec<JcsValue>>,
}

impl fmt::Debug for Echo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Echo")
    }
}

impl Upstream for Echo {
    fn call(&self, request: &UpstreamRequest, _: Duration) -> Result<Vec<u8>, UpstreamFailure> {
        let answer = || {
            let body = jcs::parse(&request.body).ok()?;
            let id = body.get("id")?.as_str()?.to_owned();
            let tool = body.pointer("/params/name")?.as_str()?.to_owned();
            self.requests.lock().ok()?.push(body);
            let result = match tool.as_str() {
                "get_invoice" => {
                    r#"{"resultType":"complete","content":[],"structuredContent":{"amount_due_minor":60000,"currency":"USD","invoice_id":"INV-1001"}}"#
                }
                "pay_invoice" => {
                    r#"{"resultType":"complete","content":[],"_meta":{"dev.pep-sidecar/outcome":"executed"}}"#
                }
                _ => r#"{"resultType":"complete","content":[{"type":"text","text":"ticket"}]}"#,
            };
            Some(format!(r#"{{"jsonrpc":"2.0","id":"{id}","result":{result}}}"#).into_bytes())
        };
        answer().ok_or(UpstreamFailure::Lost)
    }
}

/// The test PEP.
pub(crate) struct Kit {
    pub(crate) registry: Arc<Registry>,
    pub(crate) lockfile: Arc<Lockfile>,
    pub(crate) servers: Arc<ServerStates>,
    pub(crate) host: Arc<HostAuthority>,
    dir: PathBuf,
}

impl Drop for Kit {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

/// A PEP whose agent is `agent_uid`, with two intents, `notes` (recipients) and `pay`
/// (invoice INV-1001, step-up above 50,000), and `upstream` as its broker.
pub(crate) fn kit(upstream: Arc<dyn Upstream>, agent_uid: u32) -> Kit {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("pep-kit-{}-{n}", std::process::id()));
    std::fs::create_dir(&dir).expect("temp dir");
    let (journal, _) =
        Journal::open(&dir.join("journal.jsonl"), &dir.join("journal.lock")).expect("journal");
    let (handle, _writer) = spawn_writer(journal).expect("writer");
    let value = jcs::parse_with(PINS.as_bytes(), &ParseOptions::definition())
        .expect("pins")
        .value;
    let lockfile = parse_payload(&value, "pins").expect("pins");
    let servers = Arc::new(ServerStates::empty());
    servers.set_serving("a").expect("serving");
    let shared = Shared {
        labels: Arc::new(InMemoryLabelStore::with_capacity(100)),
        servers: servers.clone(),
        unresolved: Arc::new(UnresolvedEntities::empty()),
        claims: Arc::new(EntityClaims::empty()),
    };
    let host = Arc::new(HostAuthority::for_tests());
    let services = Arc::new(Services {
        host: host.clone(),
        journal: handle,
        proof_key: Es256Signer::from_secret_bytes(&[3; 32]).expect("key"),
        entropy: Mutex::new(Box::new(os_entropy().expect("entropy"))),
        upstream,
        pins: lockfile.pins.clone(),
        step_up_timeout: Duration::from_secs(5),
        upstream_timeout: Duration::from_secs(5),
        now: unix_now,
        log: Arc::new(crate::decision_log::DecisionLog::disabled()),
    });
    let intent = |name: &str, limit: u64, ids: EntitySet| IntentConfig {
        intent: PepIntent {
            episode_id: 0,
            intent_digest: format!("sha-256:{name}"),
            release_epoch: 7,
            lockfile_digest: lockfile.digest.clone(),
            limits: Limits {
                currency: "USD".to_owned(),
                per_call_max_minor: limit,
                cumulative_max_minor: limit,
                max_calls: 5,
                step_up_over_minor: 50_000,
                max_declines: 3,
            },
            entities: Entities {
                ids,
                per_entity_max_uses: 1,
            },
        },
        seq: SeqPolicy::Unconstrained,
    };
    let intents = BTreeMap::from([
        (
            "notes".to_owned(),
            intent(
                "notes",
                100,
                EntitySet::RecipientIds(["rcpt_A".to_owned()].into()),
            ),
        ),
        (
            "pay".to_owned(),
            intent(
                "pay",
                100_000,
                EntitySet::InvoiceIds(["INV-1001".to_owned()].into()),
            ),
        ),
    ]);
    let config = RegistryConfig {
        intents,
        pins: lockfile.pins.clone(),
        agent_uid,
        episodes: 2,
        connection_share: 8,
        call_burst: 10,
        call_rate_per_s: 10,
        idle_secs: 1800,
        lifetime_secs: crate::tokens::EPISODE_MAX_LIFETIME_SECS,
        skew_secs: 2,
    };
    let registry = Registry::new(
        config,
        Es256Signer::from_secret_bytes(&[4; 32]).expect("key"),
        BTreeMap::new(),
        shared,
        services,
    );
    Kit {
        registry,
        lockfile: Arc::new(lockfile),
        servers,
        host,
        dir,
    }
}
