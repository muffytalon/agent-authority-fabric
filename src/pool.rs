//! Reused threads for work that used to start a thread per call (G4).
//!
//! Starting and ending a thread maps and unmaps its stack, and in the WSL2 VM that serializes on
//! the process's memory map. Measured on 2026-11-24, one spawn and exit cost 0.2 to 0.4 ms of CPU
//! alone and about 2 ms with 16 or more at once, and a process topped out near 2,000 a second.
//! The PEP started four per forwarded call and the broker two, so a stall that raised concurrency
//! doubled their CPU per call, and the load stopped draining: a metastable collapse. A [`Pool`]
//! keeps a finished thread parked for the next task instead.
//!
//! A task never waits for a thread: with none parked, the pool starts one. So every limit that
//! counted threads still counts the same tasks, and a slow task never holds up another. A parked
//! thread ends after [`Pool::KEEP`] without work, except the ones [`Pool::warm`] keeps: started
//! at boot and never ended, so a burst after a stall finds threads waiting instead of starting
//! dozens at once, when starting one costs most.

use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::Duration;

/// One unit of work.
type Task = Box<dyn FnOnce() + Send + 'static>;

/// Threads of one kind, started on demand and reused.
#[derive(Debug)]
pub struct Pool {
    name: &'static str,
    /// Each parked thread's inbox, by its id. The channels are rendezvous channels: a task is
    /// handed only to a thread that is waiting for it, and one that has stopped waiting has
    /// dropped its receiver, so the send fails and gives the task back.
    parked: Mutex<Vec<(u64, SyncSender<Task>)>>,
    next_id: AtomicU64,
    /// How many parked threads never end ([`Self::warm`]).
    floor: AtomicUsize,
    /// How long a parked thread above the floor waits for a task before it ends.
    keep: Duration,
}

impl Pool {
    /// How long a parked thread waits for a task before it ends, unless it is kept warm.
    pub const KEEP: Duration = Duration::from_secs(10);
    /// The most threads a pool is kept warm with.
    pub const WARM_MAX: usize = 64;

    /// An empty pool whose threads are named `name`.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self::with_keep(name, Self::KEEP)
    }

    /// An empty pool whose idle threads above the floor end after `keep`.
    #[must_use]
    pub const fn with_keep(name: &'static str, keep: Duration) -> Self {
        Self {
            name,
            parked: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
            floor: AtomicUsize::new(0),
            keep,
        }
    }

    /// Starts `count` threads, at most [`Self::WARM_MAX`], that park at once, and from now on
    /// keeps at least that many parked: a burst after a stall then finds threads waiting (G4).
    /// Threads above the floor still end after [`Self::KEEP`] idle.
    ///
    /// # Errors
    ///
    /// The error of [`thread::Builder::spawn`] if a thread cannot start.
    pub fn warm(&'static self, count: usize) -> io::Result<()> {
        let count = count.min(Self::WARM_MAX);
        self.floor.fetch_max(count, Ordering::SeqCst);
        for _ in 0..count {
            self.start(Box::new(|| {}))?;
        }
        Ok(())
    }

    /// Runs `task` now: on a parked thread, or on a new one if none is parked.
    ///
    /// # Errors
    ///
    /// The error of [`thread::Builder::spawn`] when a new thread is needed and cannot start.
    /// The task is then dropped without running.
    pub fn spawn<F>(&'static self, task: F) -> io::Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        let mut task: Task = Box::new(task);
        while let Some((_, inbox)) = self.parked.lock().ok().and_then(|mut parked| parked.pop()) {
            match inbox.send(task) {
                Ok(()) => return Ok(()),
                // That thread stopped waiting: try the next.
                Err(mpsc::SendError(returned)) => task = returned,
            }
        }
        self.start(task)
    }

    /// Starts a new thread that runs `task`, then parks.
    fn start(&'static self, task: Task) -> io::Result<()> {
        thread::Builder::new()
            .name(self.name.to_owned())
            .spawn(move || self.work(task))
            .map(drop)
    }

    /// Runs `first`, then each task handed over, until none comes for the pool's keep while
    /// more threads than the floor are parked.
    fn work(&'static self, first: Task) {
        let mut task = first;
        loop {
            task();
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let (inbox, tasks) = mpsc::sync_channel::<Task>(0);
            match self.parked.lock() {
                Ok(mut parked) => parked.push((id, inbox)),
                Err(_) => return,
            }
            match self.wait(&tasks, id) {
                Some(next) => task = next,
                None => return,
            }
        }
    }

    /// The next task for the parked thread `id`, or `None` once it should end: idle for the
    /// pool's keep while above the floor. On the way out it unlists itself; a sender that
    /// already took its inbox gets the task back when `tasks` drops.
    fn wait(&self, tasks: &mpsc::Receiver<Task>, id: u64) -> Option<Task> {
        loop {
            match tasks.recv_timeout(self.keep) {
                Ok(next) => return Some(next),
                Err(RecvTimeoutError::Disconnected) => return None,
                Err(RecvTimeoutError::Timeout) => {
                    let mut parked = self.parked.lock().ok()?;
                    if parked.len() > self.floor.load(Ordering::SeqCst) {
                        parked.retain(|(parked_id, _)| *parked_id != id);
                        return None;
                    }
                    // At the floor: stay warm.
                }
            }
        }
    }

    /// How many threads are parked: for tests.
    #[must_use]
    pub fn parked(&self) -> usize {
        self.parked.lock().map_or(0, |parked| parked.len())
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
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    #[test]
    fn a_finished_thread_runs_the_next_task() {
        static POOL: Pool = Pool::new("test-reuse");
        let (done, finished) = mpsc::channel();
        let first = done.clone();
        POOL.spawn(move || first.send(thread::current().id()).unwrap())
            .unwrap();
        let one = finished.recv().unwrap();
        // Wait until the thread has parked, then hand it a second task.
        let until = Instant::now() + Duration::from_secs(5);
        while POOL.parked() == 0 {
            assert!(Instant::now() < until, "the thread never parked");
            thread::sleep(Duration::from_millis(1));
        }
        POOL.spawn(move || done.send(thread::current().id()).unwrap())
            .unwrap();
        assert_eq!(finished.recv().unwrap(), one);
    }

    #[test]
    fn a_task_never_waits_for_a_busy_thread() {
        static POOL: Pool = Pool::new("test-busy");
        // Ten tasks that each wait for all ten to start: they only finish if each got a thread
        // at once.
        let started = Arc::new(AtomicUsize::new(0));
        let (done, finished) = mpsc::channel();
        for _ in 0..10 {
            let started = Arc::clone(&started);
            let done = done.clone();
            POOL.spawn(move || {
                started.fetch_add(1, Ordering::SeqCst);
                let until = Instant::now() + Duration::from_secs(5);
                while started.load(Ordering::SeqCst) < 10 && Instant::now() < until {
                    thread::sleep(Duration::from_millis(1));
                }
                done.send(started.load(Ordering::SeqCst)).unwrap();
            })
            .unwrap();
        }
        for _ in 0..10 {
            assert_eq!(finished.recv().unwrap(), 10);
        }
    }

    fn eventually(what: &str, done: impl Fn() -> bool) {
        let until = Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(Instant::now() < until, "{what} never happened");
            thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn a_warm_pool_keeps_its_floor_and_sheds_the_rest() {
        static POOL: Pool = Pool::with_keep("test-warm", Duration::from_millis(30));
        POOL.warm(2).unwrap();
        eventually("two warm threads", || POOL.parked() == 2);
        // A burst of four at once: the two warm threads and two new ones.
        let started = Arc::new(AtomicUsize::new(0));
        let (release, released) = mpsc::channel::<()>();
        let released = Arc::new(Mutex::new(released));
        for _ in 0..4 {
            let started = Arc::clone(&started);
            let released = Arc::clone(&released);
            POOL.spawn(move || {
                started.fetch_add(1, Ordering::SeqCst);
                let _ = released.lock().unwrap().recv();
            })
            .unwrap();
        }
        eventually("four running", || started.load(Ordering::SeqCst) == 4);
        for _ in 0..4 {
            release.send(()).unwrap();
        }
        eventually("four parked", || POOL.parked() == 4);
        // Idle past the keep: back to the floor, and it stays there.
        eventually("back to the floor", || POOL.parked() == 2);
        thread::sleep(Duration::from_millis(150));
        assert_eq!(POOL.parked(), 2);
    }

    #[test]
    fn warming_is_capped() {
        static POOL: Pool = Pool::with_keep("test-cap", Duration::from_millis(30));
        POOL.warm(Pool::WARM_MAX + 10).unwrap();
        eventually("the cap", || POOL.parked() == Pool::WARM_MAX);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(POOL.parked(), Pool::WARM_MAX);
    }

    #[test]
    fn a_thread_that_gave_up_returns_the_task_to_the_pool() {
        static POOL: Pool = Pool::new("test-stale");
        // A listed inbox whose thread has gone: the send fails, and the task runs anyway.
        let (stale, receiver) = mpsc::sync_channel::<Task>(0);
        drop(receiver);
        POOL.parked.lock().unwrap().push((u64::MAX, stale));
        let (done, finished) = mpsc::channel();
        POOL.spawn(move || done.send(()).unwrap()).unwrap();
        finished.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}
