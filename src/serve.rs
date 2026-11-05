//! The PEP's two listening sockets: one connection, one request (D2, H1, U1).
//!
//! [`serve_agent`] answers an agent connection in U1's order: the peer check (0a), framing
//! (1), the MCP checks (2 to 13, [`crate::mcp::check`]), then the router. `server/discover` and
//! `subscriptions/listen` need no token; `tools/list` and `tools/call` need one, admitted by the
//! [`Registry`] (14, 15). A `tools/call` goes to the episode's actor under a fresh PEP id, and a
//! watcher on the connection tells the actor if the agent goes before its reply (P1).
//!
//! [`serve_control`] answers the operator's connection: the peer check, framing, then one
//! control request ([`crate::control`]).
//!
//! [`accept_loop`] runs a listener with its own connection limit: past it, a connection is
//! closed at once with no reply (U1 step 0b), and the control socket's limit is its own (H1).

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::actor::{AgentMessage, CallReply, HostMessage};
use crate::config::Peer;
use crate::control::{self, ControlError, ControlRequest};
use crate::decision_log::{Decision, DecisionLog, Verdict, unix_ms};
use crate::engine::{HostAuthority, ServerState, ServerStates};
use crate::http::{self, Deadlines, HttpError, Status};
use crate::lockfile::Lockfile;
use crate::mcp::{self, AgentRequest, Inbound, Method, Reply};
use crate::peercred::require_peer;
use crate::registry::{Admission, Registry};
use crate::tokens::TokenError;

/// The agent socket's request target.
pub const AGENT_ENDPOINT: &str = "/mcp";
/// How long a host request waits for an actor's answer.
pub const HOST_TIMEOUT: Duration = Duration::from_secs(5);

/// What an agent connection needs.
#[derive(Debug, Clone)]
pub struct AgentContext {
    /// The episodes.
    pub registry: Arc<Registry>,
    /// The pins, for `tools/list` and `server/discover` (M1).
    pub lockfile: Arc<Lockfile>,
    /// The servers' states: `tools/list` hides every tool of a server that is not serving.
    pub servers: Arc<ServerStates>,
    /// The agent's uid and gid (Q1).
    pub peer: Peer,
    /// The deadline for a whole request.
    pub read_timeout: Duration,
    /// The longest the actor may take to answer a call: the step-up wait plus the upstream
    /// leg, plus a margin.
    pub call_timeout: Duration,
    /// Unix seconds, for token times.
    pub now: fn() -> Result<u64, TokenError>,
    /// The decision log, for the transport's own refusals.
    pub log: Arc<DecisionLog>,
}

/// What the control connection needs.
#[derive(Debug, Clone)]
pub struct ControlContext {
    /// The episodes.
    pub registry: Arc<Registry>,
    /// The host's authority, used only here and in the actors (A1).
    pub host: Arc<HostAuthority>,
    /// The operator's uid and gid (H1).
    pub peer: Peer,
    /// The deadline for a whole request.
    pub read_timeout: Duration,
}

/// Accepts connections on `listener` and serves each on its own thread with `serve`, at most
/// `limit` at once; one more is closed at once, unread. Returns when `accept` fails.
pub fn accept_loop<F>(listener: &UnixListener, limit: usize, serve: F)
where
    F: Fn(UnixStream) + Send + Sync + 'static,
{
    let serve = Arc::new(serve);
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            return;
        };
        let taken = active.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
            (count < limit).then(|| count.saturating_add(1))
        });
        if taken.is_err() {
            // U1 step 0b: closed at once, with no reply.
            drop(stream);
            continue;
        }
        let serve = Arc::clone(&serve);
        let release = Arc::clone(&active);
        let spawned = thread::Builder::new()
            .name("connection".to_owned())
            .spawn(move || {
                serve(stream);
                release.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn deadlines(timeout: Duration) -> Deadlines {
    // A timeout beyond the clock's range is no deadline at all: refuse at once.
    let at = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    Deadlines { head: at, body: at }
}

/// How long, and how much, `finish` drains of what the client sent after its reply.
const DRAIN_TIME: Duration = Duration::from_millis(50);
const DRAIN_BYTES: usize = 64 * 1024;

/// Writes `bytes`, half-closes, and drains what the client still sent (an unread body, say)
/// before closing: closing a Unix socket with unread data resets the peer, which could then
/// lose the reply. The close also ends a disconnect watcher.
fn finish(stream: &mut UnixStream, bytes: &[u8], timeout: Duration) {
    drop(stream.set_write_timeout(Some(timeout)));
    drop(stream.write_all(bytes));
    drop(stream.shutdown(Shutdown::Write));
    drop(stream.set_read_timeout(Some(DRAIN_TIME)));
    let mut drained = 0usize;
    let mut buffer = [0u8; 4096];
    while drained < DRAIN_BYTES {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => drained = drained.saturating_add(read),
        }
    }
    drop(stream.shutdown(Shutdown::Both));
}

/// Serves one agent connection.
pub fn serve_agent(mut stream: UnixStream, context: &AgentContext) {
    // 0a: the peer, before any byte is read.
    let Ok(peer) = require_peer(&stream, context.peer.uid, context.peer.gid) else {
        return;
    };
    // 1: framing.
    let request =
        match http::read_request(&mut stream, AGENT_ENDPOINT, deadlines(context.read_timeout)) {
            Ok(request) => request,
            Err(error) => {
                if let Some(status) = error.reply() {
                    finish(
                        &mut stream,
                        &http::response(status, None),
                        context.read_timeout,
                    );
                }
                return;
            }
        };
    // 2 to 13.
    let reply = match mcp::check(&request.head, &request.body) {
        Err(reply) => {
            context.log.decision(
                Verdict::ProtocolError,
                &Decision {
                    peer_uid: Some(peer.uid),
                    method: request.head.headers.get("mcp-method").unwrap_or("-"),
                    reason: Some(format!("HTTP {}", reply.status.code())),
                    ..Decision::default()
                },
                unix_ms(),
            );
            reply.to_http()
        }
        Ok(Inbound::Ignored) => mcp::accepted().to_http(),
        Ok(Inbound::Request(agent_request)) => {
            route(&mut stream, peer.uid, &agent_request, context)
        }
    };
    finish(&mut stream, &reply, context.read_timeout);
}

fn route(
    stream: &mut UnixStream,
    peer_uid: u32,
    request: &AgentRequest,
    context: &AgentContext,
) -> Vec<u8> {
    let id = &request.id;
    match request.method {
        Method::Discover => mcp::result_reply(
            id,
            &mcp::discover_result(context.lockfile.instructions.as_deref()),
        )
        .to_http(),
        Method::Listen => mcp::listen_reply(id),
        Method::ToolsList | Method::ToolsCall => {
            // 14, 15: the token, then the rate limit.
            let Ok(now) = (context.now)() else {
                return mcp::unavailable(id).to_http();
            };
            let method = if request.method == Method::ToolsList {
                "tools/list"
            } else {
                "tools/call"
            };
            let refuse = |verdict, reason: &str| {
                context.log.decision(
                    verdict,
                    &Decision {
                        peer_uid: Some(peer_uid),
                        method,
                        reason: Some(reason.to_owned()),
                        ..Decision::default()
                    },
                    unix_ms(),
                );
            };
            let Some(token) = request.episode_token() else {
                refuse(Verdict::Deny, "no episode token");
                return mcp::denied(id).to_http();
            };
            let agent = match context.registry.admit(token, peer_uid, now) {
                Ok(agent) => agent,
                Err(Admission::Denied) => {
                    refuse(Verdict::Deny, "episode token refused");
                    return mcp::denied(id).to_http();
                }
                Err(Admission::Unavailable) => {
                    refuse(Verdict::Unavailable, "rate limit");
                    return mcp::unavailable(id).to_http();
                }
            };
            if request.method == Method::ToolsList {
                let tools = context
                    .lockfile
                    .tools_list(|server| context.servers.state(server) == ServerState::Serving);
                return mcp::result_reply(id, &mcp::tools_list_result(&tools)).to_http();
            }
            call(stream, peer_uid, request, &agent, context).to_http()
        }
    }
}

/// Sends a `tools/call` to its episode's actor and waits for the answer, with a watcher that
/// reports the agent's disconnect (P1).
fn call(
    stream: &UnixStream,
    peer_uid: u32,
    request: &AgentRequest,
    agent: &crate::actor::AgentSender,
    context: &AgentContext,
) -> Reply {
    let id = &request.id;
    let Ok(pep_id) = context.registry.call_id() else {
        return mcp::unavailable(id);
    };
    let (reply, answer) = mpsc::sync_channel(1);
    let message = AgentMessage::Call {
        pep_id: pep_id.clone(),
        request: request.engine_request(&pep_id),
        peer_uid,
        reply,
    };
    if agent.send(message).is_err() {
        // The episode's actor has stopped: the episode ended.
        return mcp::denied(id);
    }
    let answered = Arc::new(AtomicBool::new(false));
    watch(stream, agent.clone(), pep_id, Arc::clone(&answered));
    let outcome = answer.recv_timeout(context.call_timeout);
    answered.store(true, Ordering::SeqCst);
    match outcome {
        Ok(CallReply::Result(result)) => mcp::result_reply(id, &result),
        Ok(CallReply::Denied) | Err(mpsc::RecvTimeoutError::Disconnected) => mcp::denied(id),
        Ok(CallReply::Unavailable) | Err(mpsc::RecvTimeoutError::Timeout) => mcp::unavailable(id),
    }
}

/// Watches the connection until the reply is written: a read of 0 bytes (the agent closed or
/// half-closed) or of any byte (a second request, which one request per connection forbids)
/// is a disconnect, and the actor releases the call if it has not reached its point of
/// forwarding (P1, RV4 #17). `UnixStream::peek` is unstable, so the watcher reads a clone.
fn watch(
    stream: &UnixStream,
    agent: crate::actor::AgentSender,
    pep_id: String,
    answered: Arc<AtomicBool>,
) {
    let Ok(mut clone) = stream.try_clone() else {
        return;
    };
    drop(clone.set_read_timeout(None));
    let spawned = thread::Builder::new()
        .name("disconnect-watcher".to_owned())
        .spawn(move || {
            let mut byte = [0u8; 1];
            // Any outcome of the read ends the watch; only one before the answer counts.
            drop(clone.read(&mut byte));
            if !answered.load(Ordering::SeqCst) {
                // An actor that stopped has nothing left to release.
                let _ = agent.send(AgentMessage::Disconnected { pep_id });
            }
        });
    // Without a watcher, a disconnect goes unseen; the call still ends on its own terms.
    drop(spawned);
}

/// Serves one control connection.
pub fn serve_control(mut stream: UnixStream, context: &ControlContext) {
    if require_peer(&stream, context.peer.uid, context.peer.gid).is_err() {
        return;
    }
    let request = match http::read_request(
        &mut stream,
        control::CONTROL_ENDPOINT,
        deadlines(context.read_timeout),
    ) {
        Ok(request) => request,
        Err(HttpError::Malformed(_)) => {
            finish(
                &mut stream,
                &http::response(Status::BadRequest, None),
                context.read_timeout,
            );
            return;
        }
        Err(_) => return,
    };
    let reply = if request.head.is_post() {
        answer_control(&request.body, context).to_http()
    } else {
        http::response(Status::MethodNotAllowed, None)
    };
    finish(&mut stream, &reply, context.read_timeout);
}

fn answer_control(body: &[u8], context: &ControlContext) -> control::ControlReply {
    let host = &*context.host;
    let registry = &context.registry;
    let outcome = control::parse(body).and_then(|request| match request {
        ControlRequest::StartEpisode { intent } => registry
            .start(host, &intent)
            .and_then(|started| control::started(started.eid, &started.token, started.exp)),
        ControlRequest::EndEpisode { eid } => registry.end(host, eid).map(|()| control::done()),
        ControlRequest::Pending => control::pending(&registry.pending()),
        ControlRequest::TrustedInput {
            eid,
            input_id,
            value,
            conf,
        } => ask(registry, eid, |reply| HostMessage::TrustedInput {
            input_id,
            value,
            conf,
            reply,
        }),
        ControlRequest::Approve(approval) => ask(registry, approval.eid, |reply| {
            HostMessage::Approve { approval, reply }
        }),
        ControlRequest::Decline(approval) => ask(registry, approval.eid, |reply| {
            HostMessage::Decline { approval, reply }
        }),
    });
    outcome.unwrap_or_else(|error| control::error(&error))
}

/// Sends a host message to the episode's actor and waits for its answer.
fn ask(
    registry: &Registry,
    eid: u128,
    message: impl FnOnce(mpsc::SyncSender<Result<(), ControlError>>) -> HostMessage,
) -> Result<control::ControlReply, ControlError> {
    let sender = registry.host(eid)?;
    let (reply, answer) = mpsc::sync_channel(1);
    sender
        .send(message(reply))
        .map_err(|_| ControlError::UnknownEpisode)?;
    answer
        .recv_timeout(HOST_TIMEOUT)
        .map_err(|_| ControlError::Unavailable)?
        .map(|()| control::done())
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
    use crate::jcs::{self, JcsValue};
    use crate::testkit::{Echo, Kit, kit};
    use crate::tokens::unix_now;
    use std::path::PathBuf;

    fn me() -> Peer {
        Peer {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
            socket: PathBuf::from("/unused"),
        }
    }

    fn agent_context(kit: &Kit, peer: Peer) -> AgentContext {
        AgentContext {
            registry: kit.registry.clone(),
            lockfile: kit.lockfile.clone(),
            servers: kit.servers.clone(),
            peer,
            read_timeout: Duration::from_secs(2),
            call_timeout: Duration::from_secs(5),
            now: unix_now,
            log: Arc::new(DecisionLog::disabled()),
        }
    }

    fn control_context(kit: &Kit, peer: Peer) -> ControlContext {
        ControlContext {
            registry: kit.registry.clone(),
            host: kit.host.clone(),
            peer,
            read_timeout: Duration::from_secs(2),
        }
    }

    /// Sends `raw` on a fresh connection served by `serve`, and returns everything it wrote.
    fn exchange(raw: &[u8], serve: impl FnOnce(UnixStream) + Send + 'static) -> Vec<u8> {
        let (mut client, server) = UnixStream::pair().unwrap();
        let thread = thread::spawn(move || serve(server));
        // A server that closes unread (U1 step 0a) may do so before the request is written.
        if let Err(error) = client.write_all(raw) {
            assert!(matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ));
        }
        let mut out = Vec::new();
        // A connection closed unread (U1 step 0a) may reset rather than end.
        if let Err(error) = client.read_to_end(&mut out) {
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        }
        thread.join().unwrap();
        out
    }

    fn agent(context: &AgentContext, raw: &[u8]) -> Vec<u8> {
        let context = context.clone();
        exchange(raw, move |stream| serve_agent(stream, &context))
    }

    fn control(context: &ControlContext, raw: &[u8]) -> Vec<u8> {
        let context = context.clone();
        exchange(raw, move |stream| serve_control(stream, &context))
    }

    /// An SDK-shaped request for `method`, with `extra` headers.
    fn mcp_request(method: &str, name: Option<&str>, extra: &str, body: &str) -> Vec<u8> {
        let name = name.map_or_else(String::new, |name| format!("Mcp-Name: {name}\r\n"));
        format!(
            "POST /mcp HTTP/1.1\r\nHost: pep.local\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: {method}\r\n{name}{extra}Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    const META: &str = r#""io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}"#;

    fn control_request(body: &str) -> Vec<u8> {
        format!(
            "POST /control HTTP/1.1\r\nHost: pep\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// The JSON body of an HTTP response.
    fn json(response: &[u8]) -> JcsValue {
        let text = String::from_utf8(response.to_vec()).unwrap();
        let (_, body) = text.split_once("\r\n\r\n").unwrap();
        jcs::parse(body.as_bytes()).unwrap()
    }

    fn start(kit: &Kit) -> (String, String) {
        let reply = control(
            &control_context(kit, me()),
            &control_request(r#"{"call":"start_episode","intent":"notes"}"#),
        );
        let result = json(&reply);
        (
            result
                .pointer("/result/episode_token")
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned(),
            result
                .pointer("/result/eid")
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned(),
        )
    }

    #[test]
    fn discover_and_listen_need_no_token() {
        let kit = kit(Arc::new(Echo::default()), me().uid);
        let context = agent_context(&kit, me());
        let reply = agent(
            &context,
            &mcp_request(
                "server/discover",
                None,
                "",
                &format!(
                    r#"{{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{{"_meta":{{{META}}}}}}}"#
                ),
            ),
        );
        assert_eq!(
            json(&reply).pointer("/result/supportedVersions"),
            Some(&jcs::parse(br#"["2026-07-28"]"#).unwrap())
        );
        let reply = agent(
            &context,
            &mcp_request(
                "subscriptions/listen",
                None,
                "",
                &format!(
                    r#"{{"jsonrpc":"2.0","id":"listen-1","method":"subscriptions/listen","params":{{"_meta":{{{META}}}}}}}"#
                ),
            ),
        );
        let text = String::from_utf8(reply).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream"));
        assert!(text.contains("notifications/subscriptions/acknowledged"));
    }

    #[test]
    fn tools_list_needs_a_token_and_hides_servers_that_do_not_serve() {
        let kit = kit(Arc::new(Echo::default()), me().uid);
        let context = agent_context(&kit, me());
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{"_meta":{{{META}}}}}}}"#
        );
        let denied = json(&agent(
            &context,
            &mcp_request("tools/list", None, "", &body),
        ));
        assert_eq!(
            denied.pointer("/error/code").unwrap().as_i64(),
            Some(mcp::PEP_DENIED_CODE)
        );
        let (token, _) = start(&kit);
        let header = format!("Pep-Episode: {token}\r\n");
        let listed = json(&agent(
            &context,
            &mcp_request("tools/list", None, &header, &body),
        ));
        let names: Vec<&str> = listed
            .pointer("/result/tools")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool.get("name").unwrap().as_str().unwrap())
            .collect();
        assert_eq!(names, ["get_invoice", "get_ticket", "pay_invoice"]);
        kit.servers.quarantine("a").unwrap();
        let hidden = json(&agent(
            &context,
            &mcp_request("tools/list", None, &header, &body),
        ));
        assert_eq!(
            hidden
                .pointer("/result/tools")
                .unwrap()
                .as_array()
                .map(<[JcsValue]>::len),
            Some(0)
        );
    }

    #[test]
    fn a_call_goes_upstream_under_the_peps_id_and_back_under_the_agents() {
        let echo = Arc::new(Echo::default());
        let kit = kit(echo.clone(), me().uid);
        let context = agent_context(&kit, me());
        let (token, _) = start(&kit);
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{{"name":"get_ticket","arguments":{{"id":"T-1"}},"_meta":{{{META},"dev.pep-sidecar/episode":"{token}"}}}}}}"#
        );
        let reply = json(&agent(
            &context,
            &mcp_request("tools/call", Some("get_ticket"), "", &body),
        ));
        assert_eq!(reply.get("id").unwrap().as_str(), Some("c1"));
        assert_eq!(
            reply.pointer("/result/content/0/text").unwrap().as_str(),
            Some("ticket")
        );
        let upstream = echo.requests.lock().unwrap()[0].clone();
        let upstream_id = upstream.get("id").unwrap().as_str().unwrap();
        assert_ne!(upstream_id, "c1");
        assert_eq!(upstream_id.len(), 26);
        assert!(
            !String::from_utf8(upstream.to_canonical_bytes())
                .unwrap()
                .contains(&token)
        );
    }

    #[test]
    fn the_peer_and_the_framing_come_first() {
        let kit = kit(Arc::new(Echo::default()), me().uid);
        let stranger = Peer {
            uid: me().uid + 1,
            ..me()
        };
        assert!(
            agent(
                &agent_context(&kit, stranger.clone()),
                b"GET /mcp HTTP/1.1\r\nHost: x\r\n\r\n"
            )
            .is_empty()
        );
        assert!(
            control(
                &control_context(&kit, stranger),
                &control_request(r#"{"call":"pending"}"#)
            )
            .is_empty()
        );
        let context = agent_context(&kit, me());
        assert!(
            agent(&context, b"POST /mcp HTTP/1.0\r\nHost: x\r\n\r\n").starts_with(b"HTTP/1.1 400 ")
        );
        assert!(
            agent(&context, b"GET /mcp HTTP/1.1\r\nHost: x\r\n\r\n").starts_with(b"HTTP/1.1 405 ")
        );
    }

    #[test]
    fn the_control_socket_starts_and_ends_episodes() {
        let kit = kit(Arc::new(Echo::default()), me().uid);
        let context = control_context(&kit, me());
        let (token, eid) = start(&kit);
        let busy = json(&control(
            &context,
            &control_request(r#"{"call":"start_episode","intent":"notes"}"#),
        ));
        assert_eq!(busy.get("error").unwrap().as_str(), Some("intent_busy"));
        let pending = json(&control(
            &context,
            &control_request(r#"{"call":"pending"}"#),
        ));
        assert_eq!(
            pending
                .pointer("/result/approvals")
                .unwrap()
                .as_array()
                .map(<[JcsValue]>::len),
            Some(0)
        );
        let ended = json(&control(
            &context,
            &control_request(&format!(r#"{{"call":"end_episode","eid":"{eid}"}}"#)),
        ));
        assert_eq!(ended.get("result"), Some(&jcs::parse(b"{}").unwrap()));
        // The ended episode's token is refused.
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"get_ticket","arguments":{{"id":"T-1"}},"_meta":{{{META},"dev.pep-sidecar/episode":"{token}"}}}}}}"#
        );
        let denied = json(&agent(
            &agent_context(&kit, me()),
            &mcp_request("tools/call", Some("get_ticket"), "", &body),
        ));
        assert_eq!(
            denied.pointer("/error/code").unwrap().as_i64(),
            Some(mcp::PEP_DENIED_CODE)
        );
        assert!(
            control(&context, &control_request(r#"{"call":"reboot"}"#))
                .starts_with(b"HTTP/1.1 400 ")
        );
        assert!(
            control(&context, b"GET /control HTTP/1.1\r\nHost: x\r\n\r\n")
                .starts_with(b"HTTP/1.1 405 ")
        );
    }

    fn call_body(id: u32, tool: &str, arguments: &str, token: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments},"_meta":{{{META},"dev.pep-sidecar/episode":"{token}"}}}}}}"#
        )
    }

    #[test]
    fn a_disconnect_during_step_up_releases_the_payment() {
        // P1, RV4 #17: the watcher sees the agent go, and the actor releases the payment.
        let kit = kit(Arc::new(Echo::default()), me().uid);
        let context = agent_context(&kit, me());
        let reply = control(
            &control_context(&kit, me()),
            &control_request(r#"{"call":"start_episode","intent":"pay"}"#),
        );
        let token = json(&reply)
            .pointer("/result/episode_token")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let lookup = call_body(1, "get_invoice", r#"{"invoice_id":"INV-1001"}"#, &token);
        let looked_up = json(&agent(
            &context,
            &mcp_request("tools/call", Some("get_invoice"), "", &lookup),
        ));
        assert!(looked_up.get("result").is_some(), "{looked_up:?}");
        // The payment needs a step-up; the agent sends it, then goes.
        let pay = call_body(
            2,
            "pay_invoice",
            r#"{"amount":60000,"currency":"USD","invoice_id":"INV-1001"}"#,
            &token,
        );
        let (mut client, server) = UnixStream::pair().unwrap();
        let serving = {
            let context = context.clone();
            thread::spawn(move || serve_agent(server, &context))
        };
        client
            .write_all(&mcp_request("tools/call", Some("pay_invoice"), "", &pay))
            .unwrap();
        let pending = || kit.registry.pending();
        let deadline = Instant::now() + Duration::from_secs(2);
        while pending().is_empty() {
            assert!(
                Instant::now() < deadline,
                "the payment never awaited approval"
            );
            thread::sleep(Duration::from_millis(5));
        }
        drop(client);
        while !pending().is_empty() {
            assert!(
                Instant::now() < deadline + Duration::from_secs(1),
                "the disconnect never released the payment"
            );
            thread::sleep(Duration::from_millis(5));
        }
        serving.join().unwrap();
    }

    #[test]
    fn a_full_pool_closes_new_connections_at_once() {
        let n = std::process::id();
        let path = std::env::temp_dir().join(format!("pep-serve-pool-{n}.sock"));
        drop(std::fs::remove_file(&path));
        let listener = UnixListener::bind(&path).unwrap();
        let (release, held) = mpsc::channel::<()>();
        let held = Arc::new(std::sync::Mutex::new(held));
        thread::spawn(move || {
            accept_loop(&listener, 1, move |mut stream| {
                let _ = held.lock().unwrap().recv_timeout(Duration::from_secs(5));
                drop(stream.write_all(b"served"));
            });
        });
        let mut first = UnixStream::connect(&path).unwrap();
        thread::sleep(Duration::from_millis(100));
        let mut second = UnixStream::connect(&path).unwrap();
        let mut out = Vec::new();
        second
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        second.read_to_end(&mut out).unwrap();
        assert!(out.is_empty(), "the second connection is closed unread");
        release.send(()).unwrap();
        let mut served = Vec::new();
        first.read_to_end(&mut served).unwrap();
        assert_eq!(served, b"served");
        drop(std::fs::remove_file(&path));
    }
}
