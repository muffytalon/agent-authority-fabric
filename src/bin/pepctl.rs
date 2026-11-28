//! `pepctl`: the operator's tool for the lockfile (L1). It runs on the host, with the signer
//! keys, never inside the PEP.
//!
//! - `pepctl keygen KEY`: makes a P-256 signer key from `/dev/urandom`, writes its secret to the
//!   new file `KEY` (mode 0600, unpadded base64url of the 32-byte scalar), and prints its public
//!   key, unpadded base64url of the uncompressed SEC1 point, for a config's `lockfile.signers`.
//! - `pepctl pubkey KEY`: prints that public key again.
//! - `pepctl lock sign KEY IN OUT`: signs `IN`, a JCS-canonical lockfile payload or a signed
//!   lockfile, and writes the envelope to `OUT`. Each signer runs it once, on the previous
//!   signer's output, so no key ever leaves its holder.
//! - `pepctl lock verify CONFIG`: loads a PEP config and the signed lockfile it names, exactly
//!   as the PEP does, and prints the lockfile's digest and release epoch.
//!
//! A key file must be a regular file owned by the caller with no permissions for group or
//! others, or it is refused, as ssh refuses a private key. Secrets are never printed or logged.
//! Exits 0 on success, 1 on a refusal, 2 on a usage error.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use pep_sidecar::config;
use pep_sidecar::lockfile::{self, MAX_ENVELOPE_BYTES};
use pep_sidecar::tokens::{Es256Signer, os_entropy};

/// The largest file `pepctl` reads.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

fn log(message: &str) {
    let stderr = io::stderr();
    drop(writeln!(stderr.lock(), "pepctl: {message}"));
}

fn print(line: &str) -> Result<(), String> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{line}").map_err(|error| format!("stdout: {error}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match words.as_slice() {
        ["keygen", key] => keygen(Path::new(key)),
        ["pubkey", key] => read_key(Path::new(key)).and_then(|signer| print(&public(&signer))),
        ["lock", "sign", key, input, output] => {
            sign(Path::new(key), Path::new(input), Path::new(output))
        }
        ["lock", "verify", config] => verify(Path::new(config)),
        _ => {
            log(
                "usage: pepctl keygen KEY | pepctl pubkey KEY | pepctl lock sign KEY IN OUT | pepctl lock verify CONFIG",
            );
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(&error);
            ExitCode::FAILURE
        }
    }
}

fn public(signer: &Es256Signer) -> String {
    URL_SAFE_NO_PAD.encode(signer.verifier().to_sec1_uncompressed())
}

fn read_capped(path: &Path) -> Result<Vec<u8>, String> {
    let size = fs::metadata(path)
        .map_err(|error| format!("{}: {error}", path.display()))?
        .len();
    if size > MAX_FILE_BYTES {
        return Err(format!("{}: larger than 16 MiB", path.display()));
    }
    fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn keygen(path: &Path) -> Result<(), String> {
    let mut entropy = os_entropy().map_err(|error| format!("entropy: {error}"))?;
    let signer = Es256Signer::generate(&mut entropy).map_err(|error| format!("keygen: {error}"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let secret = URL_SAFE_NO_PAD.encode(signer.secret_bytes());
    file.write_all(format!("{secret}\n").as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", path.display()))?;
    print(&public(&signer))
}

/// A signer key file: a regular file the caller owns, with no group or other permissions.
fn read_key(path: &Path) -> Result<Es256Signer, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let euid = nix::unistd::geteuid().as_raw();
    if !metadata.file_type().is_file() || metadata.uid() != euid || metadata.mode() & 0o077 != 0 {
        return Err(format!(
            "{}: a key must be a regular file you own, mode 0600 or 0400",
            path.display()
        ));
    }
    let text = String::from_utf8(read_capped(path)?)
        .map_err(|_| format!("{}: not a key file", path.display()))?;
    let secret = URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('\n'))
        .map_err(|_| format!("{}: not a key file", path.display()))?;
    Es256Signer::from_secret_bytes(&secret)
        .map_err(|_| format!("{}: not a key file", path.display()))
}

fn sign(key: &Path, input: &Path, output: &Path) -> Result<(), String> {
    let signer = read_key(key)?;
    let bytes = read_capped(input)?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(format!("{}: larger than 12 MiB", input.display()));
    }
    // A payload written by a text editor or `make-config.py` may end with one newline; the
    // signed bytes never do.
    let trimmed = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let envelope = lockfile::sign(trimmed, &signer)
        .map_err(|error| format!("{}: {error}", input.display()))?;
    let mut text = envelope;
    text.push(b'\n');
    fs::write(output, &text).map_err(|error| format!("{}: {error}", output.display()))?;
    print(&format!("signed by {}", signer.kid()))
}

fn verify(path: &Path) -> Result<(), String> {
    let bytes = read_capped(path)?;
    let config = config::load(&bytes, &|lockfile| read_capped(lockfile).ok())
        .map_err(|error| format!("{}: {error}", path.display()))?;
    print(&format!(
        "{} release_epoch {}",
        config.pins.digest, config.pins.release_epoch
    ))
}
