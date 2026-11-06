//! `stub-oracle`: the oracle's placeholder in step 8. It only stays up, so the `pep-log` tmpfs
//! it mounts survives a restart or kill of the PEP (RV4 #10). Step 9 makes it read every log
//! and join them (§2a).

use std::process::ExitCode;
use std::thread;

fn main() -> ExitCode {
    loop {
        thread::park();
    }
}
