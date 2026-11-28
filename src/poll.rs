//! One drift poll of one server (L1): its `server/discover` and every `tools/list` page,
//! fetched through the broker with no Call Proof, compared with the pins.
//!
//! The PEP runs one poll per server before the agent socket binds (RV4 #5), then one poller
//! thread per server repeats it every `drift_poll_ms`, ±20% (L1). A poll that matches the pins
//! leaves the server serving, one that differs quarantines it, and one that fails suspends it
//! (RV4 #9): an error, the deadline, more pages than [`MAX_PAGES`], a cursor seen twice, or a
//! page whose shape is wrong. `pep-sidecar lock-scan` uses [`fetch`] to write a payload.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use crate::actor::Upstream;
use crate::forward::{self, UpstreamRequest};
use crate::jcs::{self, JcsValue, ParseOptions};
use crate::lockfile::PinnedServer;

/// Most `tools/list` pages one poll fetches.
pub const MAX_PAGES: usize = 64;
/// Most reply bytes one poll reads, every page and the discover result together: the definition
/// profile's cap, which a whole lockfile payload must fit in, so nothing larger can match the
/// pins. Without it a server could make each poll hold 64 pages of 8 MiB.
pub const MAX_POLL_BYTES: usize = jcs::MAX_DEFINITION_BYTES;

/// What one poll found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    /// The server's discover result and tool definitions equal the pins.
    Matches,
    /// They differ: quarantine the server.
    Differs,
    /// The poll did not complete: suspend the server.
    Failed,
}

/// What one server serves now: its `server/discover` result, and every tool definition on every
/// `tools/list` page, in the order served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    /// The discover result.
    pub discover: JcsValue,
    /// The definitions.
    pub definitions: Vec<JcsValue>,
}

/// Why a fetch did not complete: the server is suspended (RV4 #9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchFailed;

/// Fetches what `server_id` serves, within `deadline`: its discover result and every
/// `tools/list` page, through `broker` with no Call Proof. Every result is parsed under the
/// definition profile (J1), so exact digits are kept and fractions are allowed. `next_id` gives
/// each request a fresh ULID.
///
/// # Errors
///
/// Returns [`FetchFailed`] for an error or a missed deadline, more than [`MAX_PAGES`] pages or
/// [`MAX_POLL_BYTES`] bytes, a cursor seen twice or not a string, a page whose `tools` is not an
/// array, or an id generator that runs dry.
pub fn fetch(
    broker: &dyn Upstream,
    server_id: &str,
    next_id: &mut dyn FnMut() -> Option<String>,
    deadline: Duration,
) -> Result<Served, FetchFailed> {
    let until = Instant::now().checked_add(deadline).ok_or(FetchFailed)?;
    let read = std::cell::Cell::new(0_usize);
    let get = |request: Option<UpstreamRequest>, id: &str| -> Result<JcsValue, FetchFailed> {
        let left = until
            .checked_duration_since(Instant::now())
            .ok_or(FetchFailed)?;
        let body = broker
            .call(&request.ok_or(FetchFailed)?, left)
            .map_err(|_| FetchFailed)?;
        let total = read
            .get()
            .checked_add(body.len())
            .filter(|total| *total <= MAX_POLL_BYTES)
            .ok_or(FetchFailed)?;
        read.set(total);
        let reply = forward::read_upstream_reply(&body, id).map_err(|_| FetchFailed)?;
        jcs::parse_with(
            &reply.result.ok_or(FetchFailed)?,
            &ParseOptions::definition(),
        )
        .map(|parsed| parsed.value)
        .map_err(|_| FetchFailed)
    };
    let id = next_id().ok_or(FetchFailed)?;
    let discover = get(forward::discover_request(&id, server_id).ok(), &id)?;
    let mut definitions = Vec::new();
    let mut cursors = BTreeSet::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let id = next_id().ok_or(FetchFailed)?;
        let request = forward::tools_list_request(&id, server_id, cursor.as_deref()).ok();
        let page = get(request, &id)?;
        let items = page
            .get("tools")
            .and_then(JcsValue::as_array)
            .ok_or(FetchFailed)?;
        definitions.extend(items.iter().cloned());
        match page.get("nextCursor") {
            None | Some(JcsValue::Null) => {
                return Ok(Served {
                    discover,
                    definitions,
                });
            }
            Some(next) => {
                let next = next.as_str().ok_or(FetchFailed)?;
                if !cursors.insert(next.to_owned()) {
                    return Err(FetchFailed);
                }
                cursor = Some(next.to_owned());
            }
        }
    }
    Err(FetchFailed)
}

/// `pep-sidecar lock-scan` (L1): `draft` is a lockfile payload whose policies are written and
/// reviewed by hand, and whose servers' `discover` and tools' `definition` may be missing or
/// stale. Each server's are replaced by what it serves now, from `scans`. Every served tool
/// must have a policy in the draft, since an unpinned tool would quarantine its server at the
/// first poll, and every drafted tool must be served. The result is canonical, and must load as
/// a payload ([`crate::lockfile::parse_payload`]): a name outside `[A-Za-z0-9_.-]`, such as a
/// homoglyph, is refused here (mutation #16).
///
/// # Errors
///
/// Returns a message naming the first server or tool that does not fit, or the payload's first
/// load error.
pub fn scanned_payload(
    draft: &JcsValue,
    scans: &std::collections::BTreeMap<String, Served>,
) -> Result<Vec<u8>, String> {
    use crate::jcs::{JcsObject, JcsString};
    let rebuild = |object: &JcsObject, key: &str, value: JcsValue| -> Result<JcsObject, String> {
        let mut entries: Vec<(JcsString, JcsValue)> = object
            .entries()
            .iter()
            .filter(|(name, _)| name.as_str() != key)
            .cloned()
            .collect();
        entries.push((JcsString::new(key), value));
        JcsObject::from_entries(entries).map_err(|error| error.to_string())
    };
    let root = draft.as_object().ok_or("the draft is not an object")?;
    let servers = root
        .get("servers")
        .and_then(JcsValue::as_object)
        .ok_or("the draft has no servers object")?;
    let mut filled_servers = Vec::new();
    for (server_id, server) in servers.entries() {
        let server_id = server_id.as_str();
        let now = scans
            .get(server_id)
            .ok_or_else(|| format!("server {server_id} was not scanned"))?;
        let server = server
            .as_object()
            .ok_or_else(|| format!("server {server_id} is not an object"))?;
        let tools = server
            .get("tools")
            .and_then(JcsValue::as_object)
            .ok_or_else(|| format!("server {server_id} has no tools object"))?;
        let mut filled_tools = Vec::new();
        let mut seen = BTreeSet::new();
        for definition in &now.definitions {
            let name = definition
                .get("name")
                .and_then(JcsValue::as_str)
                .ok_or_else(|| format!("server {server_id} serves a tool with no name"))?;
            if !seen.insert(name.to_owned()) {
                return Err(format!("server {server_id} serves {name} twice"));
            }
            let entry = tools
                .get(name)
                .and_then(JcsValue::as_object)
                .ok_or_else(|| {
                    format!("server {server_id} serves {name}, which the draft gives no policy")
                })?;
            filled_tools.push((
                JcsString::new(name),
                JcsValue::Object(rebuild(entry, "definition", definition.clone())?),
            ));
        }
        if let Some((name, _)) = tools
            .entries()
            .iter()
            .find(|(name, _)| !seen.contains(name.as_str()))
        {
            return Err(format!(
                "server {server_id} does not serve {}, which the draft pins",
                name.as_str()
            ));
        }
        let tools = JcsObject::from_entries(filled_tools).map_err(|error| error.to_string())?;
        let server = rebuild(server, "tools", JcsValue::Object(tools))?;
        let server = rebuild(&server, "discover", now.discover.clone())?;
        filled_servers.push((JcsString::new(server_id), JcsValue::Object(server)));
    }
    let servers = JcsObject::from_entries(filled_servers).map_err(|error| error.to_string())?;
    let payload = JcsValue::Object(rebuild(root, "servers", JcsValue::Object(servers))?);
    crate::lockfile::parse_payload(&payload, "payload").map_err(|error| error.to_string())?;
    Ok(payload.to_canonical_bytes())
}

/// Polls `server_id` once, within `deadline`, against `pinned`. `next_id` gives each request
/// a fresh ULID. The comparison is by canonical bytes under the definition profile, so key
/// order, whitespace, escapes, number spelling and how the list is split into pages never
/// count as drift; any other difference does, a definition served twice included.
pub fn poll(
    broker: &dyn Upstream,
    server_id: &str,
    pinned: &PinnedServer,
    next_id: &mut dyn FnMut() -> Option<String>,
    deadline: Duration,
) -> PollOutcome {
    let Ok(served) = fetch(broker, server_id, next_id, deadline) else {
        return PollOutcome::Failed;
    };
    if served.discover.to_canonical_bytes() != pinned.discover.to_canonical_bytes() {
        return PollOutcome::Differs;
    }
    let mut tools = BTreeSet::new();
    for tool in &served.definitions {
        if !tools.insert(tool.to_canonical_bytes()) {
            // The same definition twice: not what was pinned.
            return PollOutcome::Differs;
        }
    }
    let pinned: BTreeSet<Vec<u8>> = pinned
        .definitions
        .iter()
        .map(JcsValue::to_canonical_bytes)
        .collect();
    if tools == pinned {
        PollOutcome::Matches
    } else {
        PollOutcome::Differs
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::actor::UpstreamFailure;
    use crate::engine::encode_ulid;
    use std::fmt;
    use std::sync::Mutex;

    const DISCOVER: &str = r#"{"cacheScope":"public","capabilities":{"tools":{}},"resultType":"complete","supportedVersions":["2026-07-28"],"ttlMs":0}"#;

    /// Answers discover with `discover`, and tools/list pages from `pages` by cursor
    /// (`None` is the first page).
    struct Script {
        discover: Option<String>,
        pages: Vec<(Option<&'static str>, String)>,
        seen: Mutex<Vec<String>>,
    }

    impl fmt::Debug for Script {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("Script")
        }
    }

    impl Upstream for Script {
        fn call(&self, request: &UpstreamRequest, _: Duration) -> Result<Vec<u8>, UpstreamFailure> {
            let answer = || {
                let body = jcs::parse(&request.body).ok()?;
                let id = body.get("id")?.as_str()?.to_owned();
                let method = body.get("method")?.as_str()?.to_owned();
                self.seen.lock().ok()?.push(method.clone());
                assert!(
                    body.pointer("/params/_meta/dev.pep-sidecar~1call-proof")
                        .is_none(),
                    "polls carry no proof"
                );
                let result = match method.as_str() {
                    "server/discover" => self.discover.clone()?,
                    "tools/list" => {
                        let cursor = body.pointer("/params/cursor").and_then(JcsValue::as_str);
                        self.pages.iter().find(|(at, _)| *at == cursor)?.1.clone()
                    }
                    _ => return None,
                };
                Some(format!(r#"{{"jsonrpc":"2.0","id":"{id}","result":{result}}}"#).into_bytes())
            };
            answer().ok_or(UpstreamFailure::Lost)
        }
    }

    fn pinned(definitions: &[&str]) -> PinnedServer {
        PinnedServer {
            endpoint: "e".to_owned(),
            identity: "i".to_owned(),
            protocol_version: "2026-07-28".to_owned(),
            discover: jcs::parse(DISCOVER.as_bytes()).unwrap(),
            definitions: definitions
                .iter()
                .map(|text| {
                    jcs::parse_with(text.as_bytes(), &ParseOptions::definition())
                        .unwrap()
                        .value
                })
                .collect(),
        }
    }

    fn page(tools: &str, next: Option<&str>) -> String {
        let next = next.map_or_else(String::new, |cursor| format!(r#","nextCursor":"{cursor}""#));
        format!(r#"{{"resultType":"complete","tools":[{tools}]{next}}}"#)
    }

    fn run(script: &Script, pinned: &PinnedServer) -> PollOutcome {
        let mut n = 0u128;
        let mut next_id = || {
            n += 1;
            Some(encode_ulid(n))
        };
        poll(script, "a", pinned, &mut next_id, Duration::from_secs(2))
    }

    const A: &str = r#"{"name":"a","description":"A."}"#;
    const B: &str = r#"{"name":"b"}"#;

    fn script(discover: &str, pages: Vec<(Option<&'static str>, String)>) -> Script {
        Script {
            discover: Some(discover.to_owned()),
            pages,
            seen: Mutex::new(Vec::new()),
        }
    }

    #[test]
    fn a_server_that_matches_its_pins() {
        let pins = pinned(&[A, B]);
        let one_page = script(DISCOVER, vec![(None, page(&format!("{A},{B}"), None))]);
        assert_eq!(run(&one_page, &pins), PollOutcome::Matches);
        assert_eq!(
            *one_page.seen.lock().unwrap(),
            ["server/discover", "tools/list"]
        );
        // Every page is fetched (L1).
        let two_pages = script(
            DISCOVER,
            vec![(None, page(B, Some("p2"))), (Some("p2"), page(A, None))],
        );
        assert_eq!(run(&two_pages, &pins), PollOutcome::Matches);
    }

    #[test]
    fn any_difference_quarantines() {
        let pins = pinned(&[A, B]);
        for script in [
            // The discover result changed.
            script(
                &DISCOVER.replace("public", "private"),
                vec![(None, page(&format!("{A},{B}"), None))],
            ),
            // A tool changed, was removed, was added, or appears twice.
            script(
                DISCOVER,
                vec![(None, page(&format!("{},{B}", A.replace("A.", "A!")), None))],
            ),
            script(DISCOVER, vec![(None, page(A, None))]),
            script(
                DISCOVER,
                vec![(None, page(&format!(r#"{A},{B},{{"name":"c"}}"#), None))],
            ),
            script(DISCOVER, vec![(None, page(&format!("{A},{B},{A}"), None))]),
        ] {
            assert_eq!(run(&script, &pins), PollOutcome::Differs);
        }
    }

    #[test]
    fn equivalent_text_is_not_drift() {
        // L1's negatives: key order, whitespace, number spelling, a `\u` escape against the
        // literal code point, and the same list split across pages differently.
        let pins = pinned(&[
            r#"{"name":"a","description":"Café","inputSchema":{"type":"object","properties":{"x":{"type":"number","minimum":0.5}}}}"#,
            B,
        ]);
        let respelled = r#"{ "inputSchema" : {"properties":{"x":{"minimum":0.50,"type":"number"}},"type":"object"},
            "description":"Caf\u00e9", "name":"a" }"#;
        let split = script(
            r#"{"ttlMs":0,"supportedVersions":["2026-07-28"],"resultType":"complete","capabilities":{"tools":{}},"cacheScope":"public"}"#,
            vec![
                (None, page(B, Some("x"))),
                (Some("x"), page(respelled, None)),
            ],
        );
        assert_eq!(run(&split, &pins), PollOutcome::Matches);
        // A changed digit is drift, though.
        let changed = script(
            DISCOVER,
            vec![(
                None,
                page(&format!("{},{B}", respelled.replace("0.50", "0.51")), None),
            )],
        );
        assert_eq!(run(&changed, &pins), PollOutcome::Differs);
    }

    #[test]
    fn fetch_returns_every_page_in_order() {
        let two_pages = script(
            DISCOVER,
            vec![(None, page(B, Some("p2"))), (Some("p2"), page(A, None))],
        );
        let mut n = 0u128;
        let mut next_id = || {
            n += 1;
            Some(encode_ulid(n))
        };
        let served = fetch(&two_pages, "a", &mut next_id, Duration::from_secs(2)).unwrap();
        assert_eq!(served.discover, jcs::parse(DISCOVER.as_bytes()).unwrap());
        assert_eq!(
            served.definitions,
            [B, A].map(|text| jcs::parse(text.as_bytes()).unwrap())
        );
    }

    #[test]
    fn a_poll_that_does_not_complete_suspends() {
        let pins = pinned(&[A]);
        let no_reply = Script {
            discover: None,
            pages: Vec::new(),
            seen: Mutex::new(Vec::new()),
        };
        let looping = script(
            DISCOVER,
            vec![
                (None, page("", Some("p2"))),
                (Some("p2"), page("", Some("p2"))),
            ],
        );
        let endless: Vec<(Option<&'static str>, String)> =
            std::iter::once((None, page("", Some("c0"))))
                .chain((0..MAX_PAGES).map(|n| {
                    let at: &'static str = Box::leak(format!("c{n}").into_boxed_str());
                    (Some(at), page("", Some(&format!("c{}", n + 1))))
                }))
                .collect();
        // Pages that together pass MAX_POLL_BYTES, though each is under it.
        let filler = format!(
            r#"{{"name":"x","description":"{}"}}"#,
            "x".repeat(MAX_POLL_BYTES / 3)
        );
        let oversized: Vec<(Option<&'static str>, String)> = vec![
            (None, page(&filler, Some("p2"))),
            (
                Some("p2"),
                page(&filler.replace(r#""x""#, r#""y""#), Some("p3")),
            ),
            (
                Some("p3"),
                page(&filler.replace(r#""x""#, r#""z""#), Some("p4")),
            ),
            (Some("p4"), page("", None)),
        ];
        for script in [
            script(DISCOVER, oversized),
            no_reply,
            looping,
            script(DISCOVER, endless),
            script(
                DISCOVER,
                vec![(None, r#"{"resultType":"complete","tools":{}}"#.to_owned())],
            ),
            script(
                DISCOVER,
                vec![(
                    None,
                    r#"{"resultType":"complete","tools":[],"nextCursor":7}"#.to_owned(),
                )],
            ),
            script(DISCOVER, Vec::new()),
        ] {
            assert_eq!(run(&script, &pins), PollOutcome::Failed);
        }
        // So does one whose id generator runs dry.
        let mut none = || None;
        assert_eq!(
            poll(
                &script(DISCOVER, Vec::new()),
                "a",
                &pins,
                &mut none,
                Duration::from_secs(1)
            ),
            PollOutcome::Failed
        );
    }
}
