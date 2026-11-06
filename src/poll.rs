//! One drift poll of one server (L1): its `server/discover` and every `tools/list` page,
//! fetched through the broker with no Call Proof, compared with the pins.
//!
//! Step 7 runs one poll per server before the agent socket binds (RV4 #5); step 10 runs them
//! on a timer. A poll that matches the pins leaves the server serving, one that differs
//! quarantines it, and one that fails suspends it (RV4 #9): an error, the deadline, more pages
//! than [`MAX_PAGES`], a cursor seen twice, or a page whose shape is wrong.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use crate::actor::Upstream;
use crate::forward::{self, UpstreamRequest};
use crate::jcs::{self, JcsValue, ParseOptions};
use crate::lockfile::PinnedServer;

/// Most `tools/list` pages one poll fetches.
pub const MAX_PAGES: usize = 64;

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

/// Polls `server_id` once, within `deadline`, against `pinned`. `next_id` gives each request
/// a fresh ULID.
pub fn poll(
    broker: &dyn Upstream,
    server_id: &str,
    pinned: &PinnedServer,
    next_id: &mut dyn FnMut() -> Option<String>,
    deadline: Duration,
) -> PollOutcome {
    let Some(until) = Instant::now().checked_add(deadline) else {
        return PollOutcome::Failed;
    };
    let fetch = |request: Option<UpstreamRequest>, id: &str| -> Option<JcsValue> {
        let left = until.checked_duration_since(Instant::now())?;
        let body = broker.call(&request?, left).ok()?;
        let reply = forward::read_upstream_reply(&body, id).ok()?;
        jcs::parse_with(&reply.result?, &ParseOptions::definition())
            .ok()
            .map(|parsed| parsed.value)
    };
    // server/discover.
    let Some(id) = next_id() else {
        return PollOutcome::Failed;
    };
    let Some(discover) = fetch(forward::discover_request(&id, server_id).ok(), &id) else {
        return PollOutcome::Failed;
    };
    if jcs::digest_value(&discover) != jcs::digest_value(&pinned.discover) {
        return PollOutcome::Differs;
    }
    // Every tools/list page.
    let mut tools = BTreeSet::new();
    let mut cursors = BTreeSet::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let Some(id) = next_id() else {
            return PollOutcome::Failed;
        };
        let request = forward::tools_list_request(&id, server_id, cursor.as_deref()).ok();
        let Some(page) = fetch(request, &id) else {
            return PollOutcome::Failed;
        };
        let Some(items) = page.get("tools").and_then(JcsValue::as_array) else {
            return PollOutcome::Failed;
        };
        for tool in items {
            if !tools.insert(tool.to_canonical_bytes()) {
                // The same definition twice: not what was pinned.
                return PollOutcome::Differs;
            }
        }
        match page.get("nextCursor") {
            None | Some(JcsValue::Null) => {
                let pinned: BTreeSet<Vec<u8>> = pinned
                    .definitions
                    .iter()
                    .map(JcsValue::to_canonical_bytes)
                    .collect();
                return if tools == pinned {
                    PollOutcome::Matches
                } else {
                    PollOutcome::Differs
                };
            }
            Some(next) => {
                let Some(next) = next.as_str() else {
                    return PollOutcome::Failed;
                };
                if !cursors.insert(next.to_owned()) {
                    return PollOutcome::Failed;
                }
                cursor = Some(next.to_owned());
            }
        }
    }
    PollOutcome::Failed
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
                .map(|text| jcs::parse(text.as_bytes()).unwrap())
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
        for script in [
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
