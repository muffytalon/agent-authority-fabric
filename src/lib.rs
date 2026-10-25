//! `pep-sidecar`: an OS-isolated, stateful Policy Enforcement Point (PEP) for AI agent
//! payments and tool execution.
//!
//! - [`jcs`] parses wire bytes with the JCS-strict-NFC profile and computes digests.
//! - [`engine`] runs the nine-guard pipeline, the two-phase budget and the taint labels.
//! - `peercred` (Linux and macOS) checks peer credentials and binds the socket safely.
//!
//! The architecture is specified in `SPEC.md`; the Week 1 design is in `WEEK1_PLAN.md`.
#![forbid(unsafe_code)]

pub mod engine;
pub mod jcs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod peercred;
