//! `stub-load SOCKET CAP [DIRECTORY]`: the open-loop load generator for G4 (O1). Test images only.
//!
//! It reads a plan from stdin, one JSON line per call, `{"at_ms":N,"request":TEXT}`, in time order,
//! and sends each at its time, on its own connection, whatever the calls before it are doing: a
//! closed loop would slow down with the PEP and hide its queueing. At most `CAP` calls are in
//! flight, and a call that has to wait for one counts that wait, because latency runs from the
//! time the plan says it should have gone.
//!
//! One line per call on stdout, in plan order: `{"i":N,"latency_us":N,"reply":KIND}`, then one
//! line of `{"late":[[AT_MS,US],...],"sync":[...],"append":[...]}`, from threads that touch no PEP
//! code, so they say how much of a stall is the machine's: how late a 1 ms sleep woke, and, on a
//! disk at `DIRECTORY` if there is one, how long a journal's sort of write and a log line's took.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use pep_sidecar::jcs::{self, JcsValue, ParseOptions};
use pep_sidecar::stubs::raw_call;

/// How often a call waiting for a slot looks again.
const SLOT_WAIT: Duration = Duration::from_micros(200);
/// How long the jitter thread sleeps each time.
const JITTER_SLEEP: Duration = Duration::from_millis(1);
/// How long the disk probe rests between writes.
const DISK_REST: Duration = Duration::from_millis(10);
/// What the disk probe writes each time: about one journal record.
const DISK_RECORD: [u8; 256] = [b'x'; 256];
/// The size of the file it rewrites in place, as the journal does.
const DISK_FILE_BYTES: u64 = 1024 * 1024;

/// One reading of a probe: milliseconds into the run, and microseconds it took.
type Sample = (u128, u128);

/// How late each 1 ms sleep woke, until `stop`.
fn jitter(start: Instant, stop: &AtomicBool) -> Vec<Sample> {
    let mut late = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        let at = start.elapsed().as_millis();
        let before = Instant::now();
        thread::sleep(JITTER_SLEEP);
        late.push((
            at,
            before.elapsed().saturating_sub(JITTER_SLEEP).as_micros(),
        ));
    }
    late
}

/// Until `stop`: how long rewriting a preallocated file in place with `sync_data` took, the
/// journal's path, and how long appending to another took with no sync, the path of a log line.
fn disk(
    directory: &Path,
    start: Instant,
    stop: &AtomicBool,
) -> io::Result<(Vec<Sample>, Vec<Sample>)> {
    let rewritten = File::options()
        .create(true)
        .truncate(true)
        .write(true)
        .open(directory.join("rewrite"))?;
    let zeros = vec![0u8; usize::try_from(DISK_FILE_BYTES).map_err(|_| io::ErrorKind::Other)?];
    rewritten.write_all_at(&zeros, 0)?;
    rewritten.sync_all()?;
    let mut appended = File::options()
        .create(true)
        .append(true)
        .open(directory.join("append"))?;
    let (mut syncs, mut appends) = (Vec::new(), Vec::new());
    let mut offset = 0u64;
    let record = u64::try_from(DISK_RECORD.len()).map_err(|_| io::ErrorKind::Other)?;
    while !stop.load(Ordering::Relaxed) {
        let at = start.elapsed().as_millis();
        let before = Instant::now();
        rewritten.write_all_at(&DISK_RECORD, offset)?;
        rewritten.sync_data()?;
        syncs.push((at, before.elapsed().as_micros()));
        // Only where a test probe writes next.
        offset = offset
            .saturating_add(record)
            .checked_rem(DISK_FILE_BYTES.saturating_sub(record))
            .unwrap_or(0);
        let before = Instant::now();
        appended.write_all(&DISK_RECORD)?;
        appends.push((at, before.elapsed().as_micros()));
        thread::sleep(DISK_REST);
    }
    Ok((syncs, appends))
}

/// `samples` as a JSON array of `[at, us]`.
fn samples_json(samples: &[Sample]) -> String {
    let items: Vec<String> = samples
        .iter()
        .map(|(at, us)| format!("[{at},{us}]"))
        .collect();
    format!("[{}]", items.join(","))
}

fn log(message: &str) {
    let stderr = io::stderr();
    drop(writeln!(stderr.lock(), "stub-load: {message}"));
}

struct Planned {
    at: Duration,
    request: Arc<str>,
}

fn plan(text: &str) -> Option<Vec<Planned>> {
    text.lines()
        .map(|line| {
            let item = jcs::parse_with(line.as_bytes(), &ParseOptions::definition())
                .ok()?
                .value;
            Some(Planned {
                at: Duration::from_millis(u64::try_from(item.get("at_ms")?.as_i64()?).ok()?),
                request: Arc::from(item.get("request")?.as_str()?),
            })
        })
        .collect()
}

fn run(socket: &str, cap: usize, planned: Vec<Planned>, directory: Option<String>) {
    let socket: Arc<str> = Arc::from(socket);
    let in_flight = Arc::new(AtomicUsize::new(0));
    let (done, results) = mpsc::channel();
    let count = planned.len();
    let stop = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    let jitter_stop = Arc::clone(&stop);
    let late = thread::spawn(move || jitter(start, &jitter_stop));
    let disk_stop = Arc::clone(&stop);
    let on_disk = thread::spawn(move || {
        directory.map_or_else(
            || Ok(Default::default()),
            |directory| disk(Path::new(&directory), start, &disk_stop),
        )
    });
    for (index, call) in planned.into_iter().enumerate() {
        thread::sleep(call.at.saturating_sub(start.elapsed()));
        let socket = Arc::clone(&socket);
        let in_flight = Arc::clone(&in_flight);
        let done = done.clone();
        let spawned = thread::Builder::new().spawn(move || {
            while in_flight
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                    (held < cap).then(|| held.saturating_add(1))
                })
                .is_err()
            {
                thread::sleep(SLOT_WAIT);
            }
            let reply = raw_call(&socket, &call.request, None);
            in_flight.fetch_sub(1, Ordering::SeqCst);
            let latency = start.elapsed().saturating_sub(call.at);
            let _ = done.send((index, latency, reply));
        });
        if spawned.is_err() {
            log("a thread would not start");
        }
    }
    drop(done);
    let mut rows: Vec<Option<(Duration, &str)>> = vec![None; count];
    for (index, latency, reply) in results {
        if let Some(row) = rows.get_mut(index) {
            *row = Some((latency, reply));
        }
    }
    stop.store(true, Ordering::Relaxed);
    let late = late.join().unwrap_or_default();
    let (syncs, appends) = match on_disk.join() {
        Ok(Ok(readings)) => readings,
        Ok(Err(error)) => {
            log(&format!("the disk probe stopped: {error}"));
            Default::default()
        }
        Err(_) => Default::default(),
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for (index, row) in rows.iter().enumerate() {
        let (latency, reply) = row.unwrap_or((Duration::ZERO, "lost"));
        drop(writeln!(
            out,
            r#"{{"i":{index},"latency_us":{},"reply":{}}}"#,
            latency.as_micros(),
            JcsValue::string(reply).to_canonical_string()
        ));
    }
    drop(writeln!(
        out,
        r#"{{"append":{},"late":{},"sync":{}}}"#,
        samples_json(&appends),
        samples_json(&late),
        samples_json(&syncs)
    ));
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (socket, cap, directory) = match args.as_slice() {
        [socket, cap] => (socket, cap, None),
        [socket, cap, directory] => (socket, cap, Some(directory.clone())),
        _ => {
            log("usage: stub-load SOCKET CAP [DIRECTORY]");
            return ExitCode::from(2);
        }
    };
    let Ok(cap) = cap.parse() else {
        log("CAP is a number");
        return ExitCode::from(2);
    };
    let mut text = String::new();
    if io::stdin().read_to_string(&mut text).is_err() {
        log("stdin cannot be read");
        return ExitCode::from(2);
    }
    let Some(planned) = plan(&text) else {
        log("a plan line cannot be read");
        return ExitCode::from(2);
    };
    run(socket, cap, planned, directory);
    ExitCode::SUCCESS
}
