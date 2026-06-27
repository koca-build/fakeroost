//! Tight stat() loop across N threads over a directory of distinct files.
//!
//! Built to characterize the fakeroost supervisor's serialization (issue #7).
//! Distinct files (rather than one) so a native run actually spreads across
//! cores instead of contending on a single inode.
//!
//! We use *threads*, not forks: the supervisor sets `PTRACE_O_TRACECLONE`, so
//! every new thread arrives as a traced tracee and its trapped syscalls are
//! serviced by the same single `waitpid(-1)` loop — i.e. the serialization is
//! identical to the fork/process case a real `make -j` tree hits.
//!
//!   stat-loop <n_calls> <n_workers> <dir>
//!
//! Prints one line to stderr: workers=<W> stats=<total> wall=<sec> rate=<stats/s>

use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

fn worker(files: &[PathBuf], n_calls: u64, nfiles: u64, barrier: &Barrier, abort: &AtomicBool) {
    barrier.wait();
    let mut sink: u64 = 0;
    for i in 0..n_calls {
        if abort.load(Ordering::Relaxed) {
            return;
        }
        if let Ok(m) = fs::metadata(&files[(i % nfiles) as usize]) {
            sink = sink.wrapping_add(m.len());
        }
    }
    // Keep the loop from being optimized away / give it an observable effect.
    if sink == 0xdeadbeef_u64 {
        abort.store(true, Ordering::Relaxed);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: {} <n_calls> <n_workers> <dir>",
            args.first().map(String::as_str).unwrap_or("stat-loop")
        );
        std::process::exit(2);
    }
    let n_calls: u64 = args[1].parse().expect("n_calls");
    let n_workers: usize = args[2].parse::<usize>().unwrap_or(1).max(1);
    let dir = PathBuf::from(&args[3]);

    let files: Vec<PathBuf> = match fs::read_dir(&dir) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
            .map(|e| e.path())
            .collect(),
        Err(e) => {
            eprintln!("opendir {}: {e}", dir.display());
            std::process::exit(2);
        }
    };
    if files.is_empty() {
        eprintln!("no files in {}", dir.display());
        std::process::exit(2);
    }
    let files = Arc::new(files);
    let nfiles = files.len() as u64;

    let barrier = Arc::new(Barrier::new(n_workers));
    let abort = Arc::new(AtomicBool::new(false));

    let start = Instant::now();
    let mut handles = Vec::with_capacity(n_workers - 1);
    for _ in 1..n_workers {
        let files = Arc::clone(&files);
        let barrier = Arc::clone(&barrier);
        let abort = Arc::clone(&abort);
        handles.push(thread::spawn(move || worker(&files, n_calls, nfiles, &barrier, &abort)));
    }
    worker(&files, n_calls, nfiles, &barrier, &abort);
    for h in handles {
        let _ = h.join();
    }
    let elapsed = start.elapsed();

    let total = n_calls * n_workers as u64;
    let wall = elapsed.as_secs_f64();
    let rate = total as f64 / wall;
    eprintln!("workers={n_workers} stats={total} wall={wall:.4} rate={rate:.0}");
}
