//! One episode's actor (A1): the thread that owns the episode's [`PepEngine`].
//!
//! Each actor has two channels: an agent channel, whose [`AgentMessage`] cannot express
//! approve, trusted input, end or settle (F-13), and a host channel ([`HostMessage`]), held by
//! the control thread and by the actor's own upstream workers. It drains the host channel
//! before each agent message, so a flooding agent cannot delay the operator (H1). Only the
//! host handler takes `&HostAuthority`.
//!
//! A call's path (P1):
//! 1. `evaluate_raw`. A payment's reservation is journaled (`reserve`) at once.
//! 2. A step-up waits, with no reply, until the operator approves or declines, the wait times
//!    out, the agent disconnects or the episode ends.
//! 3. Just before forwarding: `recheck_before_forward`, the episode still live, and the Call
//!    Proof and request built while the reservation is still `Held`.
//! 4. The point of forwarding: for a payment, the fsync of its `forwarded` record; then a
//!    worker thread, started beforehand, gets the request. A failure before this point
//!    releases the reservation with `release_unforwarded`, which needs no `HostAuthority`.
//! 5. The worker's reply comes back on the host channel, and the broker's explicit outcome
//!    settles a payment (`settle`). Nothing on the agent's side changes it any more.
//!
//! A rise of the episode's F-09 ratchet is fsynced (`ratchet`) before the reply that depends
//! on it; if that fails, the reply is `PEP_UNAVAILABLE` (RV4 #4).

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::control::{Approval, ControlError, PendingPayment};
use crate::decision_log::{Decision as LogDecision, DecisionLog, Ending, Verdict, unix_ms};
use crate::engine::{
    AbortOutcome, Confidentiality, Decision, HostAuthority, Ledger, PEP_DENIED, PepEngine,
    ResState, Settlement, ToolPins, idempotency_key,
};
use crate::forward::{self, BrokerOutcome, UpstreamReply, UpstreamRequest};
use crate::jcs::JcsValue;
use crate::journal::{JournalHandle, OutcomeKind, Record};
use crate::tokens::{
    CALL_PROOF_TTL_SECS, CallProofClaims, Es256Signer, PaymentClaims, TokenError, issue_call_proof,
    new_jti,
};

/// What the actor answers a call. The connection thread puts the agent's own id on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallReply {
    /// The recorded result's canonical bytes.
    Result(Vec<u8>),
    /// `PEP_DENIED`.
    Denied,
    /// `PEP_UNAVAILABLE`.
    Unavailable,
}

/// The PEP's client to the broker.
pub trait Upstream: Send + Sync + fmt::Debug {
    /// Sends `request` and returns the reply body, within `timeout`. `None` when there is no
    /// usable reply: a timeout, a dropped connection, a peer that is not the broker, a status
    /// other than 200, or a content type other than JSON.
    fn call(&self, request: &UpstreamRequest, timeout: Duration) -> Option<Vec<u8>>;
}

/// What every actor shares (A1). No connection thread holds it.
pub struct Services {
    /// Claimed once in `main`.
    pub host: Arc<HostAuthority>,
    /// The journal (R1).
    pub journal: JournalHandle,
    /// The per-boot Call Proof key.
    pub proof_key: Es256Signer,
    /// Randomness for each proof's `jti`.
    pub entropy: Mutex<Box<dyn Read + Send>>,
    /// The broker.
    pub upstream: Arc<dyn Upstream>,
    /// The pins, for each proof's `server_id` and `tool_schema_digest`.
    pub pins: ToolPins,
    /// The longest step-up wait (P1).
    pub step_up_timeout: Duration,
    /// The longest upstream leg (P1).
    pub upstream_timeout: Duration,
    /// Unix seconds, for proof times.
    pub now: fn() -> Result<u64, TokenError>,
    /// The decision log (§2a).
    pub log: Arc<DecisionLog>,
}

impl fmt::Debug for Services {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Services")
            .field("journal", &self.journal)
            .field("upstream", &self.upstream)
            .field("step_up_timeout", &self.step_up_timeout)
            .field("upstream_timeout", &self.upstream_timeout)
            .finish_non_exhaustive()
    }
}

/// What an agent connection may ask of its episode's actor.
#[derive(Debug)]
pub enum AgentMessage {
    /// A `tools/call` that passed the transport, under its PEP-assigned id (M1).
    Call {
        /// The PEP's ULID for the call.
        pep_id: String,
        /// [`crate::mcp::AgentRequest::engine_request`] of it.
        request: Vec<u8>,
        /// The connection's peer uid, for the decision log.
        peer_uid: u32,
        /// Where to answer.
        reply: SyncSender<CallReply>,
    },
    /// The agent's connection closed before its reply (P1).
    Disconnected {
        /// The call's PEP-assigned id.
        pep_id: String,
    },
}

/// What the host may ask of an episode's actor.
#[derive(Debug)]
pub enum HostMessage {
    /// Approve a payment awaiting step-up (H1, F-15).
    Approve {
        /// Matched against the reservation.
        approval: Approval,
        /// Where to answer.
        reply: SyncSender<Result<(), ControlError>>,
    },
    /// Decline it.
    Decline {
        /// Matched against the reservation.
        approval: Approval,
        /// Where to answer.
        reply: SyncSender<Result<(), ControlError>>,
    },
    /// Record a trusted input (F-13).
    TrustedInput {
        /// Its id.
        input_id: String,
        /// Its canonical JSON.
        value: Vec<u8>,
        /// Its confidentiality.
        conf: Confidentiality,
        /// Where to answer.
        reply: SyncSender<Result<(), ControlError>>,
    },
    /// List the payments awaiting approval.
    Pending {
        /// Where to answer.
        reply: SyncSender<Vec<PendingPayment>>,
    },
    /// End the episode (E1).
    End {
        /// Answered once every waiting payment is released.
        reply: SyncSender<()>,
    },
}

enum HostEvent {
    Control(HostMessage),
    Upstream {
        pep_id: String,
        body: Option<Vec<u8>>,
    },
}

/// The actor has stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("episode actor stopped")]
pub struct ActorGone;

/// The agent side of an actor: all a connection thread holds. A reply channel that closes
/// with no answer means the episode ended before the call was taken: the call was never
/// evaluated, and the agent gets `PEP_DENIED`.
#[derive(Debug, Clone)]
pub struct AgentSender {
    agent: Sender<AgentMessage>,
    wake: SyncSender<()>,
}

impl AgentSender {
    /// Sends `message` to the actor.
    ///
    /// # Errors
    ///
    /// Returns [`ActorGone`] if the actor has stopped.
    pub fn send(&self, message: AgentMessage) -> Result<(), ActorGone> {
        self.agent.send(message).map_err(|_| ActorGone)?;
        ring(&self.wake);
        Ok(())
    }
}

/// The host side of an actor: held by the control thread and the actor's workers.
#[derive(Debug, Clone)]
pub struct HostSender {
    host: Sender<HostEvent>,
    wake: SyncSender<()>,
}

impl fmt::Debug for HostEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Control(message) => message.fmt(formatter),
            Self::Upstream { pep_id, .. } => formatter
                .debug_struct("Upstream")
                .field("pep_id", pep_id)
                .finish_non_exhaustive(),
        }
    }
}

impl HostSender {
    /// Sends `message` to the actor.
    ///
    /// # Errors
    ///
    /// Returns [`ActorGone`] if the actor has stopped.
    pub fn send(&self, message: HostMessage) -> Result<(), ActorGone> {
        self.event(HostEvent::Control(message))
    }

    fn event(&self, event: HostEvent) -> Result<(), ActorGone> {
        self.host.send(event).map_err(|_| ActorGone)?;
        ring(&self.wake);
        Ok(())
    }
}

/// Wakes the actor. A full doorbell already holds a wake-up the actor has yet to take.
fn ring(wake: &SyncSender<()>) {
    let _ = wake.try_send(());
}

/// A call the actor holds: waiting for step-up, or upstream.
struct Call {
    pep_id: String,
    /// The engine's id for the call: [`crate::mcp::engine_call_id`] of `pep_id`.
    engine_id: String,
    tool: String,
    arguments: JcsValue,
    action_digest: String,
    rid: Option<u64>,
    prov: Vec<String>,
    reply: SyncSender<CallReply>,
    peer_uid: u32,
    /// When the engine decided it, for the outcome record's `pep_us`.
    decided: Instant,
    /// Its Call Proof's `jti`, once built.
    jti: Option<String>,
}

struct Actor {
    engine: PepEngine,
    intent: String,
    services: Arc<Services>,
    events: HostSender,
    waiting: BTreeMap<String, (Call, Instant)>,
    legs: BTreeMap<String, Call>,
    ended: bool,
    journaled_conf: Confidentiality,
}

/// Starts the actor of the episode `engine` runs, an episode of the intent named `intent`.
/// `on_exit` runs when the actor stops, with the intent's ledger as the episode leaves it
/// ([`PepEngine::ledger`]): after `end`, once its last upstream leg is done, so the episode
/// counts as live until then (E1).
///
/// # Errors
///
/// Returns the error of spawning the thread.
pub fn spawn(
    engine: PepEngine,
    intent: String,
    services: Arc<Services>,
    on_exit: Box<dyn FnOnce(Ledger) + Send>,
) -> io::Result<(AgentSender, HostSender, JoinHandle<()>)> {
    let (agent, agent_rx) = mpsc::channel();
    let (host, host_rx) = mpsc::channel();
    let (wake, wake_rx) = mpsc::sync_channel(1);
    let agent_sender = AgentSender {
        agent,
        wake: wake.clone(),
    };
    let host_sender = HostSender { host, wake };
    let journaled_conf = engine.state().context_conf;
    let actor = Actor {
        engine,
        intent,
        services,
        events: host_sender.clone(),
        waiting: BTreeMap::new(),
        legs: BTreeMap::new(),
        ended: false,
        journaled_conf,
    };
    let thread = thread::Builder::new()
        .name("episode".to_owned())
        .spawn(move || on_exit(actor.run(&host_rx, &agent_rx, &wake_rx)))?;
    Ok((agent_sender, host_sender, thread))
}

fn answer(reply: &SyncSender<CallReply>, value: CallReply) {
    // An agent that stopped waiting has nothing to learn.
    drop(reply.try_send(value));
}

impl Actor {
    fn eid(&self) -> u128 {
        self.engine.state().intent.episode_id
    }

    fn run(
        mut self,
        host_rx: &Receiver<HostEvent>,
        agent_rx: &Receiver<AgentMessage>,
        wake_rx: &Receiver<()>,
    ) -> Ledger {
        let host = Arc::clone(&self.services.host);
        loop {
            // H1: the host channel first.
            while let Ok(event) = host_rx.try_recv() {
                self.on_host(&host, event);
            }
            if self.ended && self.legs.is_empty() {
                return self.engine.ledger();
            }
            match agent_rx.try_recv() {
                Ok(message) => {
                    self.on_agent(message);
                    continue;
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
            }
            let deadline = self.waiting.values().map(|(_, deadline)| *deadline).min();
            match deadline {
                Some(deadline) => {
                    // A wake-up or the deadline: either way, look again.
                    let _ =
                        wake_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
                }
                None => {
                    if wake_rx.recv().is_err() {
                        return self.engine.ledger();
                    }
                }
            }
            self.expire(Instant::now());
        }
    }

    /// The agent path: no `&HostAuthority` (A1, F-13).
    fn on_agent(&mut self, message: AgentMessage) {
        match message {
            AgentMessage::Call {
                pep_id,
                request,
                peer_uid,
                reply,
            } => self.on_call(pep_id, peer_uid, &request, reply),
            AgentMessage::Disconnected { pep_id } => {
                // Before its point of forwarding a call is released; after it, the upstream
                // leg decides (P1).
                if let Some((call, _)) = self.waiting.remove(&pep_id) {
                    self.unforward(&call);
                }
            }
        }
    }

    fn on_call(
        &mut self,
        pep_id: String,
        peer_uid: u32,
        request: &[u8],
        reply: SyncSender<CallReply>,
    ) {
        if self.ended {
            answer(&reply, CallReply::Denied);
            return;
        }
        match self.engine.evaluate_raw(request) {
            Err(error) => {
                let (refusal, verdict) = if error.to_agent_code() == PEP_DENIED {
                    (CallReply::Denied, Verdict::Deny)
                } else {
                    (CallReply::Unavailable, Verdict::Unavailable)
                };
                let tool = crate::jcs::parse(request).ok().and_then(|value| {
                    value
                        .pointer("/params/name")
                        .and_then(JcsValue::as_str)
                        .map(str::to_owned)
                });
                self.services.log.decision(
                    verdict,
                    &LogDecision {
                        eid: Some(self.eid()),
                        peer_uid: Some(peer_uid),
                        method: "tools/call",
                        tool: tool.as_deref(),
                        reason: Some(format!("{error:?}")),
                        upstream_id: Some(&pep_id),
                        ..LogDecision::default()
                    },
                    unix_ms(),
                );
                let refusal = self.ratchet(refusal);
                answer(&reply, refusal);
            }
            Ok(Decision::Allow(allowed)) => {
                let call = Call {
                    pep_id,
                    engine_id: allowed.call_id,
                    tool: allowed.tool,
                    arguments: allowed.arguments,
                    action_digest: allowed.action_digest,
                    rid: allowed.reservation.map(|ticket| ticket.reservation_id),
                    prov: allowed.prov,
                    reply,
                    peer_uid,
                    decided: Instant::now(),
                    jti: None,
                };
                if self.journal_reserve(&call) {
                    self.forward(call);
                }
            }
            Ok(Decision::StepUpRequired(pending)) => {
                let call = Call {
                    pep_id,
                    engine_id: pending.call_id,
                    tool: pending.tool,
                    arguments: pending.arguments,
                    action_digest: pending.action_digest,
                    rid: Some(pending.reservation_id),
                    prov: pending.prov,
                    reply,
                    peer_uid,
                    decided: Instant::now(),
                    jti: None,
                };
                if self.journal_reserve(&call) {
                    self.log_decision(Verdict::StepUp, &call, None);
                    // A deadline beyond the clock's range fails closed: it expires now.
                    let deadline = Instant::now()
                        .checked_add(self.services.step_up_timeout)
                        .unwrap_or_else(Instant::now);
                    self.waiting.insert(call.pep_id.clone(), (call, deadline));
                }
            }
        }
    }

    /// Appends a payment's `reserve` record. On failure the reservation is released and the
    /// agent gets `PEP_UNAVAILABLE` (R1).
    fn journal_reserve(&mut self, call: &Call) -> bool {
        let Some(rid) = call.rid else {
            return true;
        };
        let eid = self.eid();
        let state = self.engine.state();
        let record = state
            .budget
            .reservations
            .get(&rid)
            .map(|reservation| Record::Reserve {
                intent: self.intent.clone(),
                eid,
                rid,
                entity: reservation.entity.clone(),
                amount_minor: reservation.amount_minor,
                currency: state.intent.limits.currency.clone(),
                action_digest: reservation.action_digest.clone(),
                idempotency_key: idempotency_key(eid, rid, &reservation.action_digest),
            });
        let journaled =
            record.is_some_and(|record| self.services.journal.append(&[record]).is_ok());
        if !journaled {
            // The reservation was just made, so it is releasable.
            let _ = self.engine.release_unforwarded(rid);
            answer(&call.reply, CallReply::Unavailable);
        }
        journaled
    }

    /// Steps 3 and 4: the re-check, the request, the point of forwarding and the worker.
    fn forward(&mut self, call: Call) {
        if self.ended {
            self.unforward(&call);
            answer(&call.reply, CallReply::Denied);
            return;
        }
        if let Err(error) = self.engine.recheck_before_forward(&call.engine_id) {
            self.log_decision(Verdict::Deny, &call, Some(format!("recheck: {error:?}")));
            self.unforward(&call);
            let refusal = self.ratchet(CallReply::Denied);
            answer(&call.reply, refusal);
            return;
        }
        let Some((request, jti)) = self.build_request(&call) else {
            self.log_decision(
                Verdict::Unavailable,
                &call,
                Some("proof or request".to_owned()),
            );
            self.unforward(&call);
            answer(&call.reply, CallReply::Unavailable);
            return;
        };
        let mut call = call;
        call.jti = Some(jti);
        // The worker exists before the point of forwarding, and gets the request only after
        // it: if its thread cannot start, nothing has been sent.
        let (go, ready) = mpsc::sync_channel::<UpstreamRequest>(1);
        let events = self.events.clone();
        let upstream = Arc::clone(&self.services.upstream);
        let timeout = self.services.upstream_timeout;
        let pep_id = call.pep_id.clone();
        let worker = thread::Builder::new()
            .name("upstream".to_owned())
            .spawn(move || {
                let Ok(request) = ready.recv() else {
                    return;
                };
                let body = upstream.call(&request, timeout);
                // An actor that stopped has no one to tell.
                let _ = events.event(HostEvent::Upstream { pep_id, body });
            });
        if worker.is_err() {
            self.unforward(&call);
            answer(&call.reply, CallReply::Unavailable);
            return;
        }
        if let Some(rid) = call.rid {
            // P1: a payment's point of forwarding is the fsync of its forwarded record.
            let eid = self.eid();
            if self
                .services
                .journal
                .commit(&[Record::Forwarded { eid, rid }])
                .is_err()
            {
                self.unforward(&call);
                answer(&call.reply, CallReply::Unavailable);
                return;
            }
            if self.engine.mark_forwarded(rid).is_err() {
                // Unreachable after the re-check; the journal says forwarded, so the
                // reservation stays counted, and replay restores it as unresolved.
                answer(&call.reply, CallReply::Unavailable);
                return;
            }
        }
        // RV3 A6: the allow record is flushed before the upstream write.
        self.log_decision(Verdict::Allow, &call, None);
        let pep_id = call.pep_id.clone();
        self.legs.insert(pep_id.clone(), call);
        if go.send(request).is_err() {
            // The worker is gone: the leg ends as a failure, settled on the host path.
            // The actor holds its own sender, so this cannot fail.
            let _ = self
                .events
                .event(HostEvent::Upstream { pep_id, body: None });
        }
    }

    /// The Call Proof and the upstream request, built while a payment is still `Held`.
    fn build_request(&self, call: &Call) -> Option<(UpstreamRequest, String)> {
        let services = &self.services;
        let tool = services.pins.tools.get(&call.tool)?;
        let iat = (services.now)().ok()?;
        let jti = {
            let mut entropy = services.entropy.lock().ok()?;
            new_jti(&mut *entropy).ok()?
        };
        let payment = match call.rid {
            Some(rid) => {
                let state = self.engine.state();
                let reservation = state.budget.reservations.get(&rid)?;
                Some(
                    PaymentClaims::for_held(
                        reservation,
                        &state.budget,
                        &state.intent.limits.currency,
                        call.prov.clone(),
                    )
                    .ok()?,
                )
            }
            None => None,
        };
        let claims = CallProofClaims {
            jti: jti.clone(),
            iat,
            exp: iat.checked_add(CALL_PROOF_TTL_SECS)?,
            eid: self.eid(),
            server_id: tool.server_id.clone(),
            action_digest: call.action_digest.clone(),
            release_epoch: services.pins.release_epoch,
            tool_schema_digest: tool.schema_digest.clone(),
            payment,
        };
        let proof = issue_call_proof(&services.proof_key, &claims).ok()?;
        forward::tools_call_request(
            &call.pep_id,
            &tool.server_id,
            &call.tool,
            &call.arguments,
            &proof,
        )
        .ok()
        .map(|request| (request, jti))
    }

    /// Writes a decision record for `call`, with its payment's fields when it has one.
    fn log_decision(&self, verdict: Verdict, call: &Call, reason: Option<String>) {
        let eid = self.eid();
        let state = self.engine.state();
        let reservation = call.rid.and_then(|rid| state.budget.reservations.get(&rid));
        let key = reservation
            .map(|reservation| idempotency_key(eid, reservation.id, &reservation.action_digest));
        self.services.log.decision(
            verdict,
            &LogDecision {
                eid: Some(eid),
                peer_uid: Some(call.peer_uid),
                method: "tools/call",
                tool: Some(&call.tool),
                action_digest: Some(&call.action_digest),
                reason,
                rid: call.rid,
                amount_minor: reservation.map(|reservation| reservation.amount_minor),
                currency: reservation.map(|_| state.intent.limits.currency.as_str()),
                entity: reservation.map(|reservation| reservation.entity.as_str()),
                jti: call.jti.as_deref(),
                idempotency_key: key.as_deref(),
                upstream_id: Some(&call.pep_id),
            },
            unix_ms(),
        );
    }

    /// Writes the outcome record of `call`.
    fn log_outcome(&self, call: &Call, ending: Ending) {
        let pep_us = u64::try_from(call.decided.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.services.log.outcome(
            self.eid(),
            &call.pep_id,
            call.jti.as_deref(),
            ending,
            pep_us,
            unix_ms(),
        );
    }

    /// Ends a call before its point of forwarding: releases a payment's reservation (no
    /// `HostAuthority` needed), or drops a non-payment call.
    fn unforward(&mut self, call: &Call) {
        self.log_outcome(
            call,
            if call.rid.is_some() {
                Ending::Released
            } else {
                Ending::NotForwarded
            },
        );
        match call.rid {
            Some(rid) => {
                if self.engine.release_unforwarded(rid).is_ok() {
                    // Losing this record is safe: replay treats a reservation that was never
                    // forwarded as released (R1).
                    let eid = self.eid();
                    drop(self.services.journal.append(&[Record::Outcome {
                        eid,
                        rid,
                        result: OutcomeKind::Released,
                    }]));
                }
            }
            None => self.drop_call(&call.engine_id),
        }
    }

    /// Fsyncs a rise of the ratchet before `reply` goes out; `PEP_UNAVAILABLE` if it cannot.
    fn ratchet(&mut self, reply: CallReply) -> CallReply {
        if self.journal_ratchet() {
            reply
        } else {
            CallReply::Unavailable
        }
    }

    /// Fsyncs the episode's ratchet level if it rose since the last record. `false` if the
    /// journal refused it.
    fn journal_ratchet(&mut self) -> bool {
        let level = self.engine.state().context_conf;
        if level > self.journaled_conf {
            let record = Record::Ratchet {
                intent: self.intent.clone(),
                conf: level,
            };
            if self.services.journal.commit(&[record]).is_err() {
                return false;
            }
            self.journaled_conf = level;
        }
        true
    }

    fn expire(&mut self, now: Instant) {
        let expired: Vec<String> = self
            .waiting
            .iter()
            .filter(|(_, (_, deadline))| *deadline <= now)
            .map(|(pep_id, _)| pep_id.clone())
            .collect();
        for pep_id in expired {
            if let Some((call, _)) = self.waiting.remove(&pep_id) {
                self.unforward(&call);
                answer(&call.reply, CallReply::Denied);
            }
        }
    }

    /// The host path: the only handler that takes `&HostAuthority`.
    fn on_host(&mut self, host: &HostAuthority, event: HostEvent) {
        match event {
            HostEvent::Upstream { pep_id, body } => {
                self.on_upstream(host, &pep_id, body.as_deref());
            }
            HostEvent::Control(HostMessage::Approve { approval, reply }) => {
                drop(reply.try_send(self.approve(host, &approval)));
            }
            HostEvent::Control(HostMessage::Decline { approval, reply }) => {
                drop(reply.try_send(self.decline(&approval)));
            }
            HostEvent::Control(HostMessage::TrustedInput {
                input_id,
                value,
                conf,
                reply,
            }) => {
                // A trusted input raises the episode's level too, so the rise is made durable
                // now, as any other is (R1, RV3 A3).
                let result = self
                    .engine
                    .record_trusted_input(host, &input_id, &value, conf)
                    .map_err(|_| ControlError::Refused)
                    .and_then(|()| {
                        if self.journal_ratchet() {
                            Ok(())
                        } else {
                            Err(ControlError::Unavailable)
                        }
                    });
                drop(reply.try_send(result));
            }
            HostEvent::Control(HostMessage::Pending { reply }) => {
                drop(reply.try_send(self.pending()));
            }
            HostEvent::Control(HostMessage::End { reply }) => {
                self.ended = true;
                for (_, (call, _)) in std::mem::take(&mut self.waiting) {
                    self.unforward(&call);
                    answer(&call.reply, CallReply::Denied);
                }
                let _ = reply.try_send(());
            }
        }
    }

    /// The waiting call `approval` names, if its digest and amount match (H1).
    fn matching(&self, approval: &Approval) -> Result<String, ControlError> {
        if approval.eid != self.eid() {
            return Err(ControlError::UnknownEpisode);
        }
        let pep_id = self
            .waiting
            .iter()
            .find(|(_, (call, _))| call.rid == Some(approval.rid))
            .map(|(pep_id, _)| pep_id.clone())
            .ok_or(ControlError::NotAwaiting)?;
        let reservation = self
            .engine
            .state()
            .budget
            .reservations
            .get(&approval.rid)
            .filter(|reservation| reservation.state == ResState::AwaitingStepUp)
            .ok_or(ControlError::NotAwaiting)?;
        if reservation.action_digest != approval.action_digest
            || reservation.amount_minor != approval.amount_minor
        {
            return Err(ControlError::Mismatch);
        }
        Ok(pep_id)
    }

    fn approve(&mut self, host: &HostAuthority, approval: &Approval) -> Result<(), ControlError> {
        let pep_id = self.matching(approval)?;
        self.engine
            .approve_step_up(host, approval.rid)
            .map_err(|_| ControlError::Refused)?;
        let (call, _) = self
            .waiting
            .remove(&pep_id)
            .ok_or(ControlError::NotAwaiting)?;
        self.forward(call);
        Ok(())
    }

    fn decline(&mut self, approval: &Approval) -> Result<(), ControlError> {
        let pep_id = self.matching(approval)?;
        let (call, _) = self
            .waiting
            .remove(&pep_id)
            .ok_or(ControlError::NotAwaiting)?;
        self.unforward(&call);
        answer(&call.reply, CallReply::Denied);
        Ok(())
    }

    fn pending(&self) -> Vec<PendingPayment> {
        let eid = self.eid();
        let reservations = &self.engine.state().budget.reservations;
        self.waiting
            .values()
            .filter_map(|(call, _)| {
                let rid = call.rid?;
                Some(PendingPayment {
                    eid,
                    rid,
                    tool: call.tool.clone(),
                    arguments: call.arguments.clone(),
                    action_digest: call.action_digest.clone(),
                    amount_minor: reservations.get(&rid)?.amount_minor,
                })
            })
            .collect()
    }

    /// Step 5: the broker's reply. A payment ends only through its explicit outcome (P1).
    fn on_upstream(&mut self, host: &HostAuthority, pep_id: &str, body: Option<&[u8]>) {
        let Some(call) = self.legs.remove(pep_id) else {
            return;
        };
        let reply = body.and_then(|body| forward::read_upstream_reply(body, pep_id).ok());
        let (outcome, ending) = match call.rid {
            Some(rid) => self.settle_payment(host, &call, rid, reply),
            None => {
                if let Some(result) = reply.and_then(|reply| reply.result) {
                    (self.record(&call.engine_id, &result), Ending::Executed)
                } else {
                    self.drop_call(&call.engine_id);
                    (CallReply::Unavailable, Ending::Abandoned)
                }
            }
        };
        self.log_outcome(&call, ending);
        answer(&call.reply, outcome);
    }

    fn settle_payment(
        &mut self,
        host: &HostAuthority,
        call: &Call,
        rid: u64,
        reply: Option<UpstreamReply>,
    ) -> (CallReply, Ending) {
        let outcome = reply
            .as_ref()
            .and_then(|reply| reply.outcome)
            .unwrap_or(BrokerOutcome::Unknown);
        let result = reply.and_then(|reply| reply.result);
        match (outcome, result) {
            (BrokerOutcome::Executed, result) => {
                if self.engine.settle(host, rid, Settlement::Executed).is_err() {
                    return (CallReply::Unavailable, Ending::Executed);
                }
                self.journal_outcome(rid, OutcomeKind::Executed);
                let reply = if let Some(result) = result {
                    self.record(&call.engine_id, &result)
                } else {
                    self.drop_call(&call.engine_id);
                    CallReply::Unavailable
                };
                (reply, Ending::Executed)
            }
            (BrokerOutcome::Refused, Some(result)) => {
                // P1: record first, because the release drops the call from `in_flight`.
                let recorded = self.record(&call.engine_id, &result);
                let refused = Settlement::Aborted(AbortOutcome::DefinitelyNotExecuted);
                // A leg's reservation is Forwarded, so settle cannot refuse it.
                let _ = self.engine.settle(host, rid, refused);
                self.journal_outcome(rid, OutcomeKind::Refused);
                (recorded, Ending::Refused)
            }
            (BrokerOutcome::Refused, None) => {
                let refused = Settlement::Aborted(AbortOutcome::DefinitelyNotExecuted);
                let _ = self.engine.settle(host, rid, refused);
                self.journal_outcome(rid, OutcomeKind::Refused);
                (CallReply::Unavailable, Ending::Refused)
            }
            (BrokerOutcome::Unknown, _) => {
                let _ = self
                    .engine
                    .settle(host, rid, Settlement::Aborted(AbortOutcome::Unknown));
                self.journal_outcome(rid, OutcomeKind::Unknown);
                (CallReply::Unavailable, Ending::Unknown)
            }
        }
    }

    /// Appends an `outcome` record. It needs no fsync: losing it replays the reservation as
    /// unresolved, which fails closed (R1).
    fn journal_outcome(&self, rid: u64, result: OutcomeKind) {
        let eid = self.eid();
        drop(
            self.services
                .journal
                .append(&[Record::Outcome { eid, rid, result }]),
        );
    }

    /// Records a result and answers with its canonical bytes, after any ratchet rise is
    /// durable.
    fn record(&mut self, call_id: &str, result: &[u8]) -> CallReply {
        if let Ok(canonical) = self.engine.record_result_raw(call_id, result) {
            self.ratchet(CallReply::Result(canonical))
        } else {
            self.drop_call(call_id);
            CallReply::Unavailable
        }
    }

    /// Drops a call whose result will never be recorded. A call that is no longer in flight
    /// has nothing to drop.
    fn drop_call(&mut self, engine_id: &str) {
        let _ = self.engine.abandon(engine_id);
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
    use crate::engine::{
        Entities, EntitySet, InMemoryLabelStore, Ledger, Limits, PepIntent, SeqPolicy,
        ServerStates, Shared, UnresolvedEntities, encode_ulid,
    };
    use crate::jcs::{self, ParseOptions};
    use crate::journal::{Journal, spawn_writer};
    use crate::lockfile::{Lockfile, parse_payload};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const EID: u128 = 0x0192_7a3c_0000_0000_0000_0000_0000_0001;
    const PINS: &str = r#"{"lockfile_version":1,"release_epoch":7,
      "stores":{"billing://invoices":{"case_insensitive":true}},
      "servers":{"a":{"endpoint":"http://a/mcp","identity":"spiffe://a","protocol_version":"2026-07-28","discover":{},"tools":{
        "get_invoice":{"definition":{"name":"get_invoice"},"policy":{"effect":"read","args":[{"pointer":"/invoice_id","role":"store_key"}],
          "store_uri":"billing://invoices","sink_clearance":"secret","output_label":{"conf":"internal","integ":"trusted"},
          "trusted_fields":["/structuredContent/amount_due_minor","/structuredContent/currency"],"max_result_bytes":65536,"max_result_nodes":1024}},
        "pay_invoice":{"definition":{"name":"pay_invoice"},"policy":{"effect":"mutating_financial",
          "args":[{"pointer":"/invoice_id","role":"entity","kind":"invoice"},{"pointer":"/amount","role":"amount"},{"pointer":"/currency","role":"currency"}],
          "sink_clearance":"internal","output_label":{"conf":"internal","integ":"untrusted_external"},
          "amount_binding":{"lookup_tool":"get_invoice","entity_arg_pointer":"/invoice_id","lookup_entity_pointer":"/invoice_id",
            "result_amount_pointer":"/structuredContent/amount_due_minor","result_currency_pointer":"/structuredContent/currency"},
          "max_result_bytes":65536,"max_result_nodes":1024}},
        "get_secret":{"definition":{"name":"get_secret"},"policy":{"effect":"read","args":[{"pointer":"/id","role":"data"}],
          "sink_clearance":"secret","output_label":{"conf":"secret","integ":"untrusted_external"},"max_result_bytes":65536,"max_result_nodes":1024}}}}}}"#;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// What the fake broker answers a `tools/call` for `tool` with id `id`: a body, or none.
    type Script = dyn Fn(&str, &str) -> Option<String> + Send + Sync;

    struct FakeBroker {
        script: Box<Script>,
        requests: Mutex<Vec<JcsValue>>,
    }

    impl fmt::Debug for FakeBroker {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeBroker")
        }
    }

    impl Upstream for FakeBroker {
        fn call(&self, request: &UpstreamRequest, _timeout: Duration) -> Option<Vec<u8>> {
            let body = jcs::parse(&request.body).ok()?;
            let id = body.get("id")?.as_str()?.to_owned();
            let tool = body.pointer("/params/name")?.as_str()?.to_owned();
            self.requests.lock().unwrap().push(body);
            (self.script)(&tool, &id).map(String::into_bytes)
        }
    }

    fn result(id: &str, structured: &str, outcome: Option<&str>) -> String {
        let meta = outcome.map_or_else(String::new, |outcome| {
            format!(r#","_meta":{{"dev.pep-sidecar/outcome":"{outcome}"}}"#)
        });
        format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"resultType":"complete","content":[],"structuredContent":{structured}{meta}}}}}"#
        )
    }

    /// A broker whose invoices are due `amount`, and whose payments end with `outcome`.
    fn broker(amount: u64, outcome: Option<&'static str>) -> FakeBroker {
        FakeBroker {
            script: Box::new(move |tool, id| match tool {
                "get_invoice" => Some(result(
                    id,
                    &format!(
                        r#"{{"amount_due_minor":{amount},"currency":"USD","invoice_id":"INV-1001"}}"#
                    ),
                    None,
                )),
                "get_secret" => Some(result(id, r#"{"secret":"s"}"#, None)),
                "pay_invoice" => {
                    outcome.map(|outcome| result(id, r#"{"status":"done"}"#, Some(outcome)))
                }
                _ => None,
            }),
            requests: Mutex::new(Vec::new()),
        }
    }

    struct Harness {
        dir: PathBuf,
        agent: AgentSender,
        host: HostSender,
        servers: Arc<ServerStates>,
        broker: Arc<FakeBroker>,
        /// The ledger the actor hands back when it stops.
        exited: Arc<Mutex<Option<Ledger>>>,
        actor: Option<JoinHandle<()>>,
        next: u128,
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.dir));
        }
    }

    fn start(broker: FakeBroker, step_up_timeout: Duration) -> Harness {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("pep-actor-{}-{n}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let (journal, _) =
            Journal::open(&dir.join("journal.jsonl"), &dir.join("journal.lock")).unwrap();
        let (handle, _writer) = spawn_writer(journal).unwrap();
        let value = jcs::parse_with(PINS.as_bytes(), &ParseOptions::definition())
            .unwrap()
            .value;
        let lockfile: Lockfile = parse_payload(&value, "pins").unwrap();
        let servers = Arc::new(ServerStates::empty());
        servers.set_serving("a").unwrap();
        let shared = Shared {
            labels: Arc::new(InMemoryLabelStore::with_capacity(1000)),
            servers: servers.clone(),
            unresolved: Arc::new(UnresolvedEntities::empty()),
        };
        let intent = PepIntent {
            episode_id: EID,
            intent_digest: "sha-256:intent".to_owned(),
            release_epoch: 7,
            lockfile_digest: lockfile.digest.clone(),
            limits: Limits {
                currency: "USD".to_owned(),
                per_call_max_minor: 100_000,
                cumulative_max_minor: 500_000,
                max_calls: 5,
                step_up_over_minor: 50_000,
            },
            entities: Entities {
                ids: EntitySet::InvoiceIds(["INV-1001".to_owned()].into()),
                per_entity_max_uses: 1,
            },
        };
        let host = Arc::new(HostAuthority::for_tests());
        let engine = PepEngine::new(
            &host,
            intent,
            lockfile.pins.clone(),
            SeqPolicy::Unconstrained,
            shared,
            Ledger::empty(),
        )
        .unwrap();
        let broker = Arc::new(broker);
        let services = Arc::new(Services {
            host,
            journal: handle,
            proof_key: Es256Signer::from_secret_bytes(&[7; 32]).unwrap(),
            entropy: Mutex::new(Box::new(io::repeat(0x5a))),
            upstream: broker.clone(),
            pins: lockfile.pins,
            step_up_timeout,
            upstream_timeout: Duration::from_secs(5),
            now: || Ok(1_800_000_000),
            log: Arc::new(DecisionLog::disabled()),
        });
        let exited = Arc::new(Mutex::new(None));
        let slot = exited.clone();
        let (agent, host, actor) = spawn(
            engine,
            "pay".to_owned(),
            services,
            Box::new(move |ledger| *slot.lock().unwrap() = Some(ledger)),
        )
        .unwrap();
        Harness {
            dir,
            agent,
            host,
            servers,
            broker,
            exited,
            actor: Some(actor),
            next: 1,
        }
    }

    impl Harness {
        /// Sends a `tools/call` of `tool` with `arguments`; returns its PEP id and reply.
        fn call(&mut self, tool: &str, arguments: &str) -> (String, Receiver<CallReply>) {
            let pep_id = encode_ulid(self.next);
            self.next += 1;
            let request = format!(
                r#"{{"id":"{pep_id}","jsonrpc":"2.0","method":"tools/call","params":{{"arguments":{arguments},"name":"{tool}"}}}}"#
            );
            let (reply, answer) = mpsc::sync_channel(1);
            self.agent
                .send(AgentMessage::Call {
                    pep_id: pep_id.clone(),
                    request: request.into_bytes(),
                    peer_uid: 0,
                    reply,
                })
                .unwrap();
            (pep_id, answer)
        }

        fn lookup(&mut self) -> CallReply {
            let (_, answer) = self.call("get_invoice", r#"{"invoice_id":"INV-1001"}"#);
            answer.recv_timeout(Duration::from_secs(5)).unwrap()
        }

        fn pay(&mut self, amount: u64) -> (String, Receiver<CallReply>) {
            self.call(
                "pay_invoice",
                &format!(r#"{{"amount":{amount},"currency":"USD","invoice_id":"INV-1001"}}"#),
            )
        }

        fn host<T>(&self, message: impl FnOnce(SyncSender<T>) -> HostMessage) -> T {
            let (reply, answer) = mpsc::sync_channel(1);
            self.host.send(message(reply)).unwrap();
            answer.recv_timeout(Duration::from_secs(5)).unwrap()
        }

        /// Waits until payment `rid` awaits approval. The actor drains its host channel before
        /// each agent message (H1), so a `pending` sent right after a call may come first.
        fn wait_pending(&self, rid: u64) -> PendingPayment {
            let deadline = Instant::now() + WAIT;
            loop {
                let pending = self.host(|reply| HostMessage::Pending { reply });
                if let Some(payment) = pending.into_iter().find(|payment| payment.rid == rid) {
                    return payment;
                }
                assert!(
                    Instant::now() < deadline,
                    "payment {rid} never awaited approval"
                );
                thread::sleep(Duration::from_millis(5));
            }
        }

        fn approval(&self, rid: u64, amount_minor: u64) -> Approval {
            let payment = self.wait_pending(rid);
            Approval {
                eid: EID,
                rid,
                action_digest: payment.action_digest.clone(),
                amount_minor,
            }
        }

        /// The journal's records, read back from the file.
        fn records(&self) -> Vec<Record> {
            fs::read(self.dir.join("journal.jsonl"))
                .unwrap()
                .split(|&byte| byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| Record::parse(line).unwrap())
                .collect()
        }

        /// The payment records only.
        fn payments(&self) -> Vec<Record> {
            self.records()
                .into_iter()
                .filter(|record| !matches!(record, Record::Ratchet { .. }))
                .map(|record| match record {
                    Record::Reserve {
                        intent,
                        eid,
                        rid,
                        entity,
                        amount_minor,
                        currency,
                        action_digest,
                        ..
                    } => Record::Reserve {
                        intent,
                        eid,
                        rid,
                        entity,
                        amount_minor,
                        currency,
                        action_digest,
                        idempotency_key: String::new(),
                    },
                    other => other,
                })
                .collect()
        }

        fn end(mut self) {
            self.host(|reply| HostMessage::End { reply });
            self.actor.take().unwrap().join().unwrap();
            // The in-memory ledger the next episode starts from is the one a restart would
            // rebuild from the journal (R1).
            let ledger = self
                .exited
                .lock()
                .unwrap()
                .take()
                .expect("the actor handed back its ledger");
            let replayed = crate::journal::replay(&self.records()).unwrap();
            let journaled = replayed
                .ledgers
                .get("pay")
                .cloned()
                .unwrap_or_else(Ledger::empty);
            assert_eq!(ledger, journaled);
        }
    }

    fn reserve(rid: u64, amount_minor: u64) -> Record {
        Record::Reserve {
            intent: "pay".to_owned(),
            eid: EID,
            rid,
            entity: "INV-1001".to_owned(),
            amount_minor,
            currency: "USD".to_owned(),
            action_digest: String::new(),
            idempotency_key: String::new(),
        }
    }

    fn strip_digests(records: Vec<Record>) -> Vec<Record> {
        records
            .into_iter()
            .map(|record| match record {
                Record::Reserve {
                    intent,
                    eid,
                    rid,
                    entity,
                    amount_minor,
                    currency,
                    ..
                } => Record::Reserve {
                    intent,
                    eid,
                    rid,
                    entity,
                    amount_minor,
                    currency,
                    action_digest: String::new(),
                    idempotency_key: String::new(),
                },
                other => other,
            })
            .collect()
    }

    const fn outcome(rid: u64, result: OutcomeKind) -> Record {
        Record::Outcome {
            eid: EID,
            rid,
            result,
        }
    }

    const WAIT: Duration = Duration::from_secs(5);

    #[test]
    fn a_read_is_forwarded_with_a_call_proof_and_recorded() {
        let mut harness = start(broker(30_000, None), WAIT);
        let CallReply::Result(bytes) = harness.lookup() else {
            panic!("expected a result")
        };
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .contains(r#""amount_due_minor":30000"#)
        );
        let request = harness.broker.requests.lock().unwrap()[0].clone();
        let meta = request.pointer("/params/_meta").unwrap();
        assert!(
            meta.get("dev.pep-sidecar/call-proof")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("eyJ")
        );
        // The lookup's Internal result raised the ratchet, durably, before the reply.
        assert_eq!(
            harness.records(),
            vec![Record::Ratchet {
                intent: "pay".to_owned(),
                conf: Confidentiality::Internal
            }]
        );
        harness.end();
    }

    #[test]
    fn a_payment_is_reserved_forwarded_and_settled() {
        let mut harness = start(broker(30_000, Some("executed")), WAIT);
        harness.lookup();
        let (_, answer) = harness.pay(30_000);
        assert!(matches!(
            answer.recv_timeout(WAIT).unwrap(),
            CallReply::Result(_)
        ));
        assert_eq!(
            strip_digests(harness.payments()),
            vec![
                reserve(1, 30_000),
                Record::Forwarded { eid: EID, rid: 1 },
                outcome(1, OutcomeKind::Executed)
            ]
        );
        let request = harness.broker.requests.lock().unwrap()[1].clone();
        assert_eq!(
            request.pointer("/params/name").unwrap().as_str(),
            Some("pay_invoice")
        );
        harness.end();
    }

    #[test]
    fn broker_outcomes_settle_the_payment() {
        for (outcome_text, expected, reply_is_result) in [
            (Some("refused"), OutcomeKind::Refused, true),
            (Some("pending"), OutcomeKind::Unknown, false),
            (None, OutcomeKind::Unknown, false),
        ] {
            let mut harness = start(broker(30_000, outcome_text), WAIT);
            harness.lookup();
            let (_, answer) = harness.pay(30_000);
            let reply = answer.recv_timeout(WAIT).unwrap();
            assert_eq!(
                matches!(reply, CallReply::Result(_)),
                reply_is_result,
                "{outcome_text:?}"
            );
            if !reply_is_result {
                assert_eq!(reply, CallReply::Unavailable);
            }
            assert_eq!(
                strip_digests(harness.payments()),
                vec![
                    reserve(1, 30_000),
                    Record::Forwarded { eid: EID, rid: 1 },
                    outcome(1, expected)
                ],
                "{outcome_text:?}"
            );
            harness.end();
        }
    }

    #[test]
    fn step_up_waits_for_a_matching_approval() {
        let mut harness = start(broker(60_000, Some("executed")), WAIT);
        harness.lookup();
        let (_, answer) = harness.pay(60_000);
        assert!(
            answer.recv_timeout(Duration::from_millis(200)).is_err(),
            "no reply before approval"
        );
        let pending = harness.host(|reply| HostMessage::Pending { reply });
        assert_eq!(pending.len(), 1);
        assert_eq!(
            (
                pending[0].rid,
                pending[0].amount_minor,
                pending[0].tool.as_str()
            ),
            (1, 60_000, "pay_invoice")
        );
        // Every field is matched (H1).
        let wrong_amount = harness.approval(1, 59_999);
        assert_eq!(
            harness.host(|reply| HostMessage::Approve {
                approval: wrong_amount,
                reply
            }),
            Err(ControlError::Mismatch)
        );
        let mut wrong_digest = harness.approval(1, 60_000);
        wrong_digest.action_digest.push('x');
        assert_eq!(
            harness.host(|reply| HostMessage::Approve {
                approval: wrong_digest,
                reply
            }),
            Err(ControlError::Mismatch)
        );
        let mut wrong_episode = harness.approval(1, 60_000);
        wrong_episode.eid += 1;
        assert_eq!(
            harness.host(|reply| HostMessage::Approve {
                approval: wrong_episode,
                reply
            }),
            Err(ControlError::UnknownEpisode)
        );
        let other_rid = Approval {
            rid: 9,
            ..harness.approval(1, 60_000)
        };
        assert_eq!(
            harness.host(|reply| HostMessage::Approve {
                approval: other_rid,
                reply
            }),
            Err(ControlError::NotAwaiting)
        );
        let approval = harness.approval(1, 60_000);
        assert_eq!(
            harness.host(|reply| HostMessage::Approve { approval, reply }),
            Ok(())
        );
        assert!(matches!(
            answer.recv_timeout(WAIT).unwrap(),
            CallReply::Result(_)
        ));
        assert_eq!(
            strip_digests(harness.payments()),
            vec![
                reserve(1, 60_000),
                Record::Forwarded { eid: EID, rid: 1 },
                outcome(1, OutcomeKind::Executed)
            ]
        );
        harness.end();
    }

    #[test]
    fn a_decline_a_timeout_or_a_disconnect_releases_the_payment() {
        let released = vec![reserve(1, 60_000), outcome(1, OutcomeKind::Released)];
        // Declined.
        let mut harness = start(broker(60_000, Some("executed")), WAIT);
        harness.lookup();
        let (_, answer) = harness.pay(60_000);
        let approval = harness.approval(1, 60_000);
        assert_eq!(
            harness.host(|reply| HostMessage::Decline {
                approval: approval.clone(),
                reply
            }),
            Ok(())
        );
        assert_eq!(answer.recv_timeout(WAIT).unwrap(), CallReply::Denied);
        assert_eq!(strip_digests(harness.payments()), released);
        // A late approval finds nothing waiting (C-CTL).
        assert_eq!(
            harness.host(|reply| HostMessage::Approve { approval, reply }),
            Err(ControlError::NotAwaiting)
        );
        harness.end();
        // Timed out.
        let mut harness = start(broker(60_000, Some("executed")), Duration::from_millis(100));
        harness.lookup();
        let (_, answer) = harness.pay(60_000);
        assert_eq!(answer.recv_timeout(WAIT).unwrap(), CallReply::Denied);
        assert_eq!(strip_digests(harness.payments()), released);
        harness.end();
        // The agent disconnected before the point of forwarding (P1). The step-up wait is
        // long, so only the disconnect can release the payment in time.
        let mut harness = start(broker(60_000, Some("executed")), Duration::from_mins(10));
        harness.lookup();
        let (pep_id, _answer) = harness.pay(60_000);
        let approval = harness.approval(1, 60_000);
        harness
            .agent
            .send(AgentMessage::Disconnected { pep_id })
            .unwrap();
        // Agent messages queue behind host ones (H1): wait until the disconnect is taken.
        let deadline = Instant::now() + WAIT;
        while !harness
            .host(|reply| HostMessage::Pending { reply })
            .is_empty()
        {
            assert!(Instant::now() < deadline, "the disconnect was never taken");
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            harness.host(|reply| HostMessage::Approve { approval, reply }),
            Err(ControlError::NotAwaiting)
        );
        assert_eq!(strip_digests(harness.payments()), released);
        assert_eq!(
            harness.broker.requests.lock().unwrap().len(),
            1,
            "only the lookup went upstream"
        );
        harness.end();
    }

    #[test]
    fn a_quarantine_during_step_up_stops_the_forward() {
        // P1, RV3 A4: the re-check runs after the approval, just before forwarding.
        let mut harness = start(broker(60_000, Some("executed")), WAIT);
        harness.lookup();
        let (_, answer) = harness.pay(60_000);
        let approval = harness.approval(1, 60_000);
        harness.servers.quarantine("a").unwrap();
        assert_eq!(
            harness.host(|reply| HostMessage::Approve { approval, reply }),
            Ok(())
        );
        assert_eq!(answer.recv_timeout(WAIT).unwrap(), CallReply::Denied);
        assert_eq!(
            strip_digests(harness.payments()),
            vec![reserve(1, 60_000), outcome(1, OutcomeKind::Released)]
        );
        assert_eq!(harness.broker.requests.lock().unwrap().len(), 1);
        harness.end();
    }

    #[test]
    fn end_releases_waiting_payments_and_refuses_new_calls() {
        let mut harness = start(broker(60_000, Some("executed")), WAIT);
        harness.lookup();
        let (_, waiting) = harness.pay(60_000);
        harness.wait_pending(1);
        harness.host(|reply| HostMessage::End { reply });
        assert_eq!(waiting.recv_timeout(WAIT).unwrap(), CallReply::Denied);
        harness.actor.take().unwrap().join().unwrap();
        assert!(harness.exited.lock().unwrap().is_some());
        assert_eq!(
            strip_digests(harness.payments()),
            vec![reserve(1, 60_000), outcome(1, OutcomeKind::Released)]
        );
        let (reply, _answer) = mpsc::sync_channel(1);
        assert_eq!(
            harness.agent.send(AgentMessage::Call {
                pep_id: encode_ulid(99),
                request: Vec::new(),
                peer_uid: 0,
                reply
            }),
            Err(ActorGone)
        );
    }

    #[test]
    fn a_secret_result_is_ratcheted_before_it_is_returned() {
        let mut harness = start(broker(30_000, None), WAIT);
        let (_, answer) = harness.call("get_secret", r#"{"id":"s1"}"#);
        assert!(matches!(
            answer.recv_timeout(WAIT).unwrap(),
            CallReply::Result(_)
        ));
        assert_eq!(
            harness.records(),
            vec![Record::Ratchet {
                intent: "pay".to_owned(),
                conf: Confidentiality::Secret
            }]
        );
        // A denial reveals nothing more, and the level is already durable.
        let (_, denied) = harness.call("no_such_tool", "{}");
        assert_eq!(denied.recv_timeout(WAIT).unwrap(), CallReply::Denied);
        assert_eq!(harness.records().len(), 1);
        harness.end();
    }

    #[test]
    fn trusted_input_goes_through_the_host_path() {
        let harness = start(broker(30_000, None), WAIT);
        let accepted = harness.host(|reply| HostMessage::TrustedInput {
            input_id: "u1".to_owned(),
            value: br#"{"entity":"INV-1001","amount_minor":100}"#.to_vec(),
            conf: Confidentiality::Internal,
            reply,
        });
        assert_eq!(accepted, Ok(()));
        let repeated = harness.host(|reply| HostMessage::TrustedInput {
            input_id: "u1".to_owned(),
            value: b"{}".to_vec(),
            conf: Confidentiality::Internal,
            reply,
        });
        assert_eq!(repeated, Err(ControlError::Refused));
        harness.end();
    }
}
