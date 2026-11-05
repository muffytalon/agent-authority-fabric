//! `pep-sidecar`: an OS-isolated, stateful Policy Enforcement Point (PEP) for AI agent
//! payments and tool execution.
//!
//! - [`jcs`] parses wire bytes with the JCS-strict-NFC profile and computes digests.
//! - [`engine`] runs the nine-guard pipeline, the two-phase budget and the taint labels.
//! - [`forward`] builds the only bytes the PEP sends upstream (F-16).
//! - `peercred` (Linux and macOS) checks peer credentials and binds the socket safely.
//! - [`tokens`] signs and verifies the Episode Token and the Call Proof, and keeps the replay
//!   cache.
//!
//! The architecture is specified in `SPEC.md`; the Week 1 design is in `WEEK1_PLAN.md`.
#![forbid(unsafe_code)]

pub mod config;
pub mod engine;
pub mod forward;
pub mod http;
pub mod jcs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod journal;
pub mod lockfile;
pub mod mcp;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod peercred;
pub mod tokens;
