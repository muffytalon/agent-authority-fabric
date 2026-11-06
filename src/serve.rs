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
//! [`accept_agents`] runs the agent socket the same way, except that a full pool first ends the
//! connection that has been sending its request the longest, so connections that send nothing
//! cannot lock out an agent that does (RV5 V7). A failed `accept` is not fatal unless the
//! listener itself is broken: running out of file descriptors must not stop the PEP (RV5 V10,
//! V11).

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Read};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::actor::{AgentMessage, CallReply, HostMessage};
use crate::config::Peer;
use crate::control::{self, ControlError, ControlRequest};
use crate::decision_log::{Decision, DecisionLog, Verdict, unix_ms};
use crate::engine::{HostAuthority, ServerState, ServerStates};
use crate::http::{self, Caps, Deadlines, HttpError, Status, time_left, write_by};
use crate::lockfile::Lockfile;
use crate::mcp::{self, AgentRequest, Inbound, Method, Reply};
use crate::peercred::require_peer;
use crate::registry::{Admission, Registry};
use crate::tokens::TokenError;
use crate::upstream::{LegTimer, residence_us};

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
    /// The limits on a request (`limits.header_bytes`, `limits.body_bytes`).
    pub caps: Caps,
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
    /// The decision log, for refused peers.
    pub log: Arc<DecisionLog>,
}

/// Accepts connections on `listener` and serves each on its own thread with `serve`, at most
/// `limit` at once; one more is closed at once, unread. Returns when `accept` fails.
pub fn accept_loop<F>(listener: &UnixListener, limit: usize, serve: F)
where
    F: Fn(UnixStream) + Send + Sync + 'static,
{
    // U1 step 0b: closed at once, with no reply.
    accept_loop_with(listener, limit, serve, drop);
}

/// [`accept_loop`], with `overflow` given each connection past the limit, on the accept thread.
pub fn accept_loop_with<F, O>(listener: &UnixListener, limit: usize, serve: F, overflow: O)
where
    F: Fn(UnixStream) + Send + Sync + 'static,
    O: Fn(UnixStream),
{
    let serve = Arc::new(serve);
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) if listener_is_broken(&error) => return,
            Err(_) => {
                thread::sleep(ACCEPT_BACKOFF);
                continue;
            }
        };
        let taken = active.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
            (count < limit).then(|| count.saturating_add(1))
        });
        if taken.is_err() {
            overflow(stream);
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

/// How long the accept thread waits after a failed `accept`, so running out of file descriptors
/// is no busy loop: the connection stays in the backlog until one is free.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
/// How long a connection has to send its request, or be answered, before a full pool may end it.
/// Long enough for a handler to get the CPU on a loaded machine; a client that sends at once
/// needs a fraction of it.
const EVICT_GRACE: Duration = Duration::from_millis(5);
/// How often the accept thread looks again while it waits for a slot.
const EXIT_WAIT: Duration = Duration::from_micros(200);
/// The longest it waits for one.
const EXIT_WAIT_MAX: Duration = Duration::from_secs(1);

/// Whether a failed `accept` means the listener itself is broken. Anything else (`EMFILE`,
/// `ENFILE`, `ENOMEM`, `ENOBUFS`, `ECONNABORTED`, `EINTR`) passes.
fn listener_is_broken(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(nix::libc::EBADF | nix::libc::EINVAL | nix::libc::ENOTSOCK | nix::libc::EOPNOTSUPP)
    )
}

/// How far a connection has got, for the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Progress {
    /// Its token was admitted, so what it asked for is about to run.
    Admitted,
    /// It has its answer, and only the close is left.
    Answered,
}

/// One connection that may still be ended.
#[derive(Debug)]
struct Evictable {
    ticket: usize,
    stream: UnixStream,
    accepted: Instant,
    answered: bool,
}

/// What a full pool could do for a new connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Eviction {
    /// It ended a connection.
    Ended,
    /// Every connection it may end is younger than [`EVICT_GRACE`]: look again soon.
    TooYoung,
    /// There is none to end.
    Nothing,
}

/// The connections a full pool may end, oldest first, each by a clone that can end it.
#[derive(Debug, Default)]
struct Readers {
    next: AtomicUsize,
    open: Mutex<VecDeque<Evictable>>,
}

impl Readers {
    /// Tracks `stream`, and returns its ticket. A connection that cannot be tracked (no file
    /// descriptor for the clone) cannot be evicted, so it holds its slot until its deadline, and
    /// [`Readers::progress`] refuses it admission (fail closed).
    fn add(&self, stream: &UnixStream) -> usize {
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        if let (Ok(clone), Ok(mut open)) = (stream.try_clone(), self.open.lock()) {
            open.push_back(Evictable {
                ticket,
                stream: clone,
                accepted: Instant::now(),
                answered: false,
            });
        }
        ticket
    }

    /// The connection `ticket` has got as far as `progress`. `false` if it has been ended, or
    /// could not be tracked.
    fn progress(&self, ticket: usize, progress: Progress) -> bool {
        let Ok(mut open) = self.open.lock() else {
            return false;
        };
        let Some(index) = open.iter().position(|entry| entry.ticket == ticket) else {
            return false;
        };
        match progress {
            Progress::Admitted => drop(open.remove(index)),
            Progress::Answered => {
                if let Some(entry) = open.get_mut(index) {
                    entry.answered = true;
                }
            }
        }
        true
    }

    /// The connection `ticket` is gone, or may no longer be ended.
    fn done(&self, ticket: usize) {
        if let Ok(mut open) = self.open.lock() {
            open.retain(|entry| entry.ticket != ticket);
        }
    }

    /// Ends one connection: one that has its answer if there is any, else the oldest, once it
    /// has had [`EVICT_GRACE`] to send its request.
    fn evict(&self) -> Eviction {
        let Ok(mut open) = self.open.lock() else {
            return Eviction::Nothing;
        };
        let answered = open.iter().position(|entry| entry.answered);
        let index = answered.or_else(|| {
            open.front()
                .filter(|oldest| oldest.accepted.elapsed() >= EVICT_GRACE)
                .map(|_| 0)
        });
        match index.and_then(|index| open.remove(index)) {
            Some(entry) => {
                // Its handler's read now returns 0, and it closes with no reply.
                drop(entry.stream.shutdown(Shutdown::Both));
                Eviction::Ended
            }
            None if open.is_empty() => Eviction::Nothing,
            None => Eviction::TooYoung,
        }
    }
}

/// Accepts agent connections and serves each on its own thread, at most `limit` at once, as U1
/// says, with one difference: a full pool first ends a connection that has its answer, then the
/// oldest whose token has not been admitted, once it has had [`EVICT_GRACE`]. So holding a slot
/// takes a live token: one that has been admitted (a call in progress, a step-up wait included)
/// is never ended, because ending it would release an honest payment, and with nothing to end, a
/// new connection is closed unread (U1 step 0b). While a pool of young connections gets through
/// its work the loop waits, so a flood slows to the rate handlers finish, in the backlog with
/// everyone else, instead of an honest connection being ended for it. Ended handlers take a
/// moment to exit, so the count may pass `limit` for that moment, by at most `limit` again.
/// Returns only when the listener is broken.
pub fn accept_agents(listener: &UnixListener, limit: usize, context: AgentContext) {
    let context = Arc::new(context);
    let readers = Arc::new(Readers::default());
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) if listener_is_broken(&error) => return,
            Err(_) => {
                thread::sleep(ACCEPT_BACKOFF);
                continue;
            }
        };
        if !wait_for_slot(&active, &readers, limit) {
            drop(stream);
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let ticket = readers.add(&stream);
        let context = Arc::clone(&context);
        let tracked = Arc::clone(&readers);
        let release = Arc::clone(&active);
        let spawned = thread::Builder::new()
            .name("connection".to_owned())
            .spawn(move || {
                serve_agent_tracked(stream, &context, &|progress| {
                    tracked.progress(ticket, progress)
                });
                tracked.done(ticket);
                release.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            readers.done(ticket);
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Whether a new connection can have a slot, once this returns. `false` if nothing can be ended,
/// or ended handlers took longer than [`EXIT_WAIT_MAX`] to exit.
fn wait_for_slot(active: &AtomicUsize, readers: &Readers, limit: usize) -> bool {
    let hard_limit = limit.saturating_mul(2);
    let started = Instant::now();
    let mut slot_made = false;
    loop {
        let count = active.load(Ordering::SeqCst);
        if count < limit || (slot_made && count < hard_limit) {
            return true;
        }
        if !slot_made && count < hard_limit {
            match readers.evict() {
                Eviction::Ended => {
                    slot_made = true;
                    continue;
                }
                Eviction::Nothing => return false,
                Eviction::TooYoung => {}
            }
        }
        if started.elapsed() >= EXIT_WAIT_MAX {
            return false;
        }
        thread::sleep(EXIT_WAIT);
    }
}

fn deadlines(timeout: Duration) -> Deadlines {
    // A timeout beyond the clock's range is no deadline at all: refuse at once.
    let at = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    Deadlines { head: at, body: at }
}

/// A call's id and its upstream leg, for the residence record once the reply has gone (O1).
type CallTiming = RefCell<Option<(String, Arc<LegTimer>)>>;

/// How long in total, and how much, `finish` drains of what the client sent after its reply.
const DRAIN_TIME: Duration = Duration::from_millis(50);
const DRAIN_BYTES: usize = 64 * 1024;

/// Writes `bytes`, half-closes, and drains what the client still sent (an unread body, say)
/// before closing: closing a Unix socket with unread data resets the peer, which could then
/// lose the reply. The close also ends a disconnect watcher. A connection here cannot be
/// evicted, so both steps have a deadline in total, not per read or write: a client that takes
/// or sends one byte at a time cannot keep its slot (RV5 V7c).
fn finish(stream: &mut UnixStream, bytes: &[u8], timeout: Duration) {
    finish_then(stream, bytes, timeout, &|| {});
}

/// [`finish`], calling `written` once the reply has gone.
fn finish_then(stream: &mut UnixStream, bytes: &[u8], timeout: Duration, written: &dyn Fn()) {
    drop(write_by(stream, bytes, deadlines(timeout).head));
    written();
    drop(stream.shutdown(Shutdown::Write));
    let deadline = deadlines(DRAIN_TIME).head;
    let mut drained = 0usize;
    let mut buffer = [0u8; 4096];
    while drained < DRAIN_BYTES {
        let Some(left) = time_left(deadline) else {
            break;
        };
        drop(stream.set_read_timeout(Some(left)));
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => drained = drained.saturating_add(read),
        }
    }
    drop(stream.shutdown(Shutdown::Both));
}

/// Serves one agent connection.
pub fn serve_agent(stream: UnixStream, context: &AgentContext) {
    serve_agent_tracked(stream, context, &|_| true);
}

/// [`serve_agent`], telling `track` how far the connection gets.
fn serve_agent_tracked(
    mut stream: UnixStream,
    context: &AgentContext,
    track: &dyn Fn(Progress) -> bool,
) {
    // 0a: the peer, before any byte is read.
    let peer = match require_peer(&stream, context.peer.uid, context.peer.gid) {
        Ok(peer) => peer,
        Err(error) => {
            // No reply, but a wrong peer at the door is what the log is for.
            refused_at_door(&context.log, &error.to_string());
            return;
        }
    };
    // 1: framing.
    let request = match http::read_request_capped(
        &mut stream,
        AGENT_ENDPOINT,
        deadlines(context.read_timeout),
        context.caps,
    ) {
        Ok(request) => request,
        Err(error) => {
            if let Some(status) = error.reply() {
                refused_at_door(&context.log, &error.to_string());
                finish_then(
                    &mut stream,
                    &http::response(status, None),
                    context.read_timeout,
                    &|| {
                        let _ = track(Progress::Answered);
                    },
                );
            }
            return;
        }
    };
    // 2 to 13.
    let timing = RefCell::new(None);
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
        Ok(Inbound::Request(agent_request)) => route(
            &mut stream,
            peer.uid,
            &agent_request,
            context,
            track,
            &timing,
        ),
    };
    finish_then(&mut stream, &reply, context.read_timeout, &|| {
        let _ = track(Progress::Answered);
        // O1: only a call that went upstream has a residence, and step-up waits are in it, which
        // the latency harness leaves out.
        if let Some((pep_id, leg)) = timing.borrow().as_ref()
            && let Some(leg) = leg.duration()
        {
            let pep_us = residence_us(request.first_byte, Some(leg));
            context.log.residence(pep_id, pep_us, unix_ms());
        }
    });
}

/// A connection refused before it named a method: its peer or its framing.
fn refused_at_door(log: &DecisionLog, reason: &str) {
    log.decision(
        Verdict::ProtocolError,
        &Decision {
            method: "-",
            reason: Some(reason.to_owned()),
            ..Decision::default()
        },
        unix_ms(),
    );
}

fn route(
    stream: &mut UnixStream,
    peer_uid: u32,
    request: &AgentRequest,
    context: &AgentContext,
    track: &dyn Fn(Progress) -> bool,
    timing: &CallTiming,
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
            let admitted = match context.registry.admit(token, peer_uid, now) {
                Ok(admitted) => admitted,
                Err(Admission::Denied) => {
                    refuse(Verdict::Deny, "episode token refused");
                    return mcp::denied(id).to_http();
                }
                Err(Admission::Unavailable) => {
                    refuse(Verdict::Unavailable, "rate limit");
                    return mcp::unavailable(id).to_http();
                }
                Err(Admission::OverShare) => {
                    refuse(Verdict::Unavailable, "connection share");
                    return mcp::unavailable(id).to_http();
                }
            };
            // A connection the pool has ended starts nothing: there is no one to answer.
            if !track(Progress::Admitted) {
                return mcp::unavailable(id).to_http();
            }
            if request.method == Method::ToolsList {
                let tools = context
                    .lockfile
                    .tools_list(|server| context.servers.state(server) == ServerState::Serving);
                return mcp::result_reply(id, &mcp::tools_list_result(&tools)).to_http();
            }
            call(stream, peer_uid, request, admitted.agent(), context, timing).to_http()
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
    timing: &CallTiming,
) -> Reply {
    let id = &request.id;
    let Ok(pep_id) = context.registry.call_id() else {
        return mcp::unavailable(id);
    };
    let (reply, answer) = mpsc::sync_channel(1);
    let leg = Arc::new(LegTimer::default());
    timing.replace(Some((pep_id.clone(), Arc::clone(&leg))));
    let message = AgentMessage::Call {
        pep_id: pep_id.clone(),
        request: request.engine_request(&pep_id),
        peer_uid,
        reply,
        leg,
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
    if let Err(error) = require_peer(&stream, context.peer.uid, context.peer.gid) {
        refused_at_door(&context.log, &error.to_string());
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
        ControlRequest::Pending => control::pending(&registry.pending(host)),
        ControlRequest::TrustedInput {
            eid,
            input_id,
            value,
            conf,
        } => ask(registry, host, eid, |reply| HostMessage::TrustedInput {
            input_id,
            value,
            conf,
            reply,
        }),
        ControlRequest::Approve(approval) => {
            ask(registry, host, approval.eid, |reply| HostMessage::Approve {
                approval,
                until: answer_by(),
                reply,
            })
        }
        ControlRequest::Decline(approval) => {
            ask(registry, host, approval.eid, |reply| HostMessage::Decline {
                approval,
                until: answer_by(),
                reply,
            })
        }
    });
    outcome.unwrap_or_else(|error| control::error(&error))
}

/// When an approval or a decline stops counting: before [`ask`] gives up on it, so one the
/// operator was told failed does not land later. A time past the clock's range is now (fail
/// closed).
fn answer_by() -> Instant {
    let margin = Duration::from_millis(100);
    Instant::now()
        .checked_add(HOST_TIMEOUT.saturating_sub(margin))
        .unwrap_or_else(Instant::now)
}

/// Sends a host message to the episode's actor and waits for its answer.
fn ask(
    registry: &Registry,
    host: &HostAuthority,
    eid: u128,
    message: impl FnOnce(mpsc::SyncSender<Result<(), ControlError>>) -> HostMessage,
) -> Result<control::ControlReply, ControlError> {
    let sender = registry.host(host, eid)?;
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
    use std::io::Write as _;
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
            caps: Caps::MAX,
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
            log: Arc::new(DecisionLog::disabled()),
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
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ));
        }
        let mut out = Vec::new();
        // A connection closed unread (U1 step 0a) may reset rather than end.
        if let Err(error) = client.read_to_end(&mut out) {
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
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
    fn a_connection_the_pool_has_ended_starts_nothing() {
        let echo = Arc::new(Echo::default());
        let kit = kit(echo.clone(), me().uid);
        let context = agent_context(&kit, me());
        let (token, _) = start(&kit);
        let body = call_body(1, "get_ticket", r#"{"id":"T-1"}"#, &token);
        let raw = mcp_request("tools/call", Some("get_ticket"), "", &body);
        let reply = json(&exchange(&raw, move |stream| {
            serve_agent_tracked(stream, &context, &|_| false);
        }));
        assert_eq!(
            reply.pointer("/error/message").unwrap().as_str(),
            Some("PEP_UNAVAILABLE")
        );
        assert!(echo.requests.lock().unwrap().is_empty());
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
        let pending = || kit.registry.pending(&kit.host);
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
    fn a_reply_has_a_deadline_in_total() {
        // Nobody reads, and the reply is larger than the socket buffer.
        let (client, mut server) = UnixStream::pair().unwrap();
        let reply = vec![b'x'; 8 << 20];
        let started = Instant::now();
        let error = write_by(
            &mut server,
            &reply,
            deadlines(Duration::from_millis(50)).head,
        )
        .unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(client);
        // A reader that keeps taking a little cannot stretch it either: at this rate the whole
        // reply takes over half a second, and each write makes progress within its own timer.
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let reader = thread::spawn(move || {
            let mut buffer = vec![0u8; 64 * 1024];
            while matches!(client.read(&mut buffer), Ok(read) if read > 0) {
                thread::sleep(Duration::from_millis(5));
            }
        });
        let started = Instant::now();
        assert!(
            write_by(
                &mut server,
                &reply,
                deadlines(Duration::from_millis(50)).head
            )
            .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(server);
        reader.join().unwrap();
        // One that reads gets it all.
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let reader = thread::spawn(move || {
            let mut out = Vec::new();
            client.read_to_end(&mut out).unwrap();
            out.len()
        });
        write_by(&mut server, &reply, deadlines(Duration::from_secs(10)).head).unwrap();
        drop(server);
        assert_eq!(reader.join().unwrap(), reply.len());
    }

    #[test]
    fn a_trickling_client_cannot_stretch_the_drain() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let writer = thread::spawn(move || {
            while client.write_all(b" ").is_ok() {
                thread::sleep(Duration::from_millis(5));
            }
        });
        let started = Instant::now();
        finish(&mut server, b"reply", Duration::from_secs(1));
        assert!(
            started.elapsed() < DRAIN_TIME * 4,
            "held for {:?}",
            started.elapsed()
        );
        writer.join().unwrap();
    }

    #[test]
    fn only_a_broken_listener_ends_an_accept_loop() {
        use nix::libc;
        for code in [
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOMEM,
            libc::ENOBUFS,
            libc::ECONNABORTED,
            libc::EINTR,
        ] {
            assert!(!listener_is_broken(&io::Error::from_raw_os_error(code)));
        }
        for code in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK, libc::EOPNOTSUPP] {
            assert!(listener_is_broken(&io::Error::from_raw_os_error(code)));
        }
    }

    #[test]
    fn eviction_prefers_the_answered_then_the_oldest_and_spares_the_admitted() {
        let readers = Readers::default();
        assert_eq!(readers.evict(), Eviction::Nothing);
        let pairs: Vec<(UnixStream, UnixStream)> =
            (0..4).map(|_| UnixStream::pair().unwrap()).collect();
        let tickets: Vec<usize> = pairs
            .iter()
            .map(|(_, server)| readers.add(server))
            .collect();
        let ended = |index: usize| {
            let (client, _) = &pairs[index];
            client
                .set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            let mut client = client;
            matches!(client.read(&mut [0u8; 1]), Ok(0))
        };
        // The first is admitted: safe, however old. The third has its answer.
        assert!(readers.progress(tickets[0], Progress::Admitted));
        assert!(readers.progress(tickets[2], Progress::Answered));
        assert_eq!(readers.evict(), Eviction::Ended);
        assert!(ended(2), "the one with its answer goes first");
        assert!(!ended(0) && !ended(1) && !ended(3));
        thread::sleep(EVICT_GRACE);
        assert_eq!(readers.evict(), Eviction::Ended);
        assert!(ended(1), "then the oldest not yet admitted");
        assert!(!ended(0) && !ended(3));
        assert!(
            !readers.progress(tickets[1], Progress::Admitted),
            "an ended connection starts nothing"
        );
        assert_eq!(readers.evict(), Eviction::Ended);
        assert!(ended(3));
        assert_eq!(
            readers.evict(),
            Eviction::Nothing,
            "the admitted one is never ended"
        );
        assert!(!ended(0));
    }

    #[test]
    fn a_new_connection_gets_its_grace_unless_it_has_its_answer() {
        let readers = Readers::default();
        let (_young_client, young) = UnixStream::pair().unwrap();
        readers.add(&young);
        assert_eq!(readers.evict(), Eviction::TooYoung);
        let (_answered_client, answered) = UnixStream::pair().unwrap();
        let ticket = readers.add(&answered);
        assert!(readers.progress(ticket, Progress::Answered));
        assert_eq!(readers.evict(), Eviction::Ended);
        assert_eq!(readers.evict(), Eviction::TooYoung);
        thread::sleep(EVICT_GRACE);
        assert_eq!(readers.evict(), Eviction::Ended);
    }

    #[test]
    fn a_slot_is_waited_for_until_nothing_can_be_ended() {
        let readers = Readers::default();
        let active = AtomicUsize::new(0);
        assert!(wait_for_slot(&active, &readers, 1), "room to spare");
        active.store(1, Ordering::SeqCst);
        assert!(!wait_for_slot(&active, &readers, 1), "nothing to end");
        // One that has just arrived gets its grace, then goes.
        let (_client, server) = UnixStream::pair().unwrap();
        readers.add(&server);
        let started = Instant::now();
        assert!(wait_for_slot(&active, &readers, 1));
        assert!(started.elapsed() >= EVICT_GRACE);
    }

    #[test]
    fn a_full_pool_ends_the_oldest_sender_for_a_new_connection() {
        let kit = kit(Arc::new(Echo::default()), me().uid);
        let dir = std::env::temp_dir().join(format!("pep-evict-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let context = agent_context(&kit, me());
        thread::spawn(move || accept_agents(&listener, 2, context));
        // Two connections that never finish their requests hold the pool.
        let mut held: Vec<UnixStream> = (0..2)
            .map(|_| {
                let mut stream = UnixStream::connect(&path).unwrap();
                stream.write_all(b"POST /mcp HTTP/1.1\r\n").unwrap();
                thread::sleep(Duration::from_millis(50));
                stream
            })
            .collect();
        // The new one is served, and the oldest gets its close.
        let mut honest = UnixStream::connect(&path).unwrap();
        let raw = b"GET /mcp HTTP/1.1\r\nHost: pep.local\r\n\r\n";
        honest.write_all(raw).unwrap();
        let mut reply = Vec::new();
        honest.read_to_end(&mut reply).unwrap();
        assert!(String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 "));
        held[0]
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(held[0].read(&mut [0u8; 1]).unwrap(), 0);
        held.clear();
        drop(std::fs::remove_dir_all(dir));
    }

    #[test]
    fn a_full_pool_closes_new_connections_at_once() {
        let n = std::process::id();
        let path = std::env::temp_dir().join(format!("pep-serve-pool-{n}.sock"));
        drop(std::fs::remove_file(&path));
        let listener = UnixListener::bind(&path).unwrap();
        let (release, held) = mpsc::channel::<()>();
        let held = Arc::new(Mutex::new(held));
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
