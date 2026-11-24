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
//! thread ends after [`Pool::KEEP`] without work.

use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
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
}

impl Pool {
    /// How long a parked thread waits for a task before it ends.
    pub const KEEP: Duration = Duration::from_secs(10);

    /// An empty pool whose threads are named `name`.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            parked: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
        }
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
        thread::Builder::new()
            .name(self.name.to_owned())
            .spawn(move || self.work(task))
            .map(drop)
    }

    /// Runs `first`, then each task handed over, until none comes for [`Self::KEEP`].
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
            let Ok(next) = tasks.recv_timeout(Self::KEEP) else {
                // Unlist this thread. A sender that already took the inbox gets its task back
                // when `tasks` drops on return.
                if let Ok(mut parked) = self.parked.lock() {
                    parked.retain(|(parked_id, _)| *parked_id != id);
                }
                return;
            };
            task = next;
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
