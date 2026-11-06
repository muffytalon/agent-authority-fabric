//! `stub-oracle`: the bypass oracle ([`pep_sidecar::stubs::oracle`]) over its read-only mounts.
//!
//! With no arguments it parks, so the `pep-log` tmpfs it mounts survives a restart or kill of
//! the PEP (RV4 #10). The kit runs the rest through `docker compose exec`:
//! - `stub-oracle mark` prints every log's offset, the start of a test's window;
//! - `stub-oracle judge OFFSETS EXPECT` joins the logs since `OFFSETS` against `EXPECT` (`deny`,
//!   `allow:N` or `any`) and prints the verdict. Exits 0 for no finding, 1 for a finding, 2 for
//!   a usage error or a log it cannot read.

use std::io::{self, Write};
use std::process::ExitCode;
use std::thread;

use pep_sidecar::stubs::oracle::{Expect, Layout, judge};

fn log(message: &str) {
    let stderr = io::stderr();
    drop(writeln!(stderr.lock(), "stub-oracle: {message}"));
}

fn print(line: &str) {
    let stdout = io::stdout();
    drop(writeln!(stdout.lock(), "{line}"));
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let layout = Layout::compose();
    match refs.as_slice() {
        [] => loop {
            thread::park();
        },
        ["mark"] => match layout.mark() {
            Ok(offsets) => {
                let offsets: Vec<String> = offsets.iter().map(u64::to_string).collect();
                print(&offsets.join(","));
                ExitCode::SUCCESS
            }
            Err(error) => {
                log(&error);
                ExitCode::from(2)
            }
        },
        ["judge", offsets, expect] => judge_window(&layout, offsets, expect),
        _ => {
            log("usage: stub-oracle [mark | judge OFFSETS EXPECT]");
            ExitCode::from(2)
        }
    }
}

fn judge_window(layout: &Layout, offsets: &str, expect: &str) -> ExitCode {
    let offsets: Result<Vec<u64>, _> = offsets.split(',').map(str::parse).collect();
    let (Ok(offsets), Some(expect)) = (offsets, Expect::parse(expect)) else {
        log("usage: stub-oracle judge OFFSETS EXPECT");
        return ExitCode::from(2);
    };
    match layout.read_from(&offsets) {
        Ok(logs) => {
            let verdict = judge(&logs, expect);
            print(&verdict.to_line());
            if verdict.findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(error) => {
            log(&error);
            ExitCode::from(2)
        }
    }
}
