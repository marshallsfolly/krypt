//! Runs the simulator over many seeds, in parallel.
//!
//!   krypt-sim --seeds 1000            seeds 0..1000
//!   krypt-sim --seed 42               one seed, verbose
//!   krypt-sim --seeds 100 --start 7   seeds 7..107
//!   krypt-sim --threads 2             on two threads (default: every core)
//!   options: --clients N --chaos-ms MS --poll-ms MS --no-network-faults --no-crashes
//!            --no-attacker --determinism

use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use krypt_sim::{Options, Violation, run};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |flag: &str| -> Option<u64> {
        args.iter().position(|a| a == flag).map(|i| {
            args.get(i + 1)
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("{flag} needs a number"))
        })
    };
    let has = |flag: &str| args.iter().any(|a| a == flag);

    let mut options = Options::default();
    if let Some(n) = value("--clients") {
        options.clients = usize::try_from(n).expect("small");
    }
    if let Some(ms) = value("--chaos-ms") {
        options.chaos_ms = ms;
    }
    options.network_faults = !has("--no-network-faults");
    options.crashes = !has("--no-crashes");
    options.attacker = !has("--no-attacker");
    if let Some(ms) = value("--poll-ms") {
        options.poll_ms = ms;
    }
    let determinism = has("--determinism");

    let (start, count) = match value("--seed") {
        Some(seed) => (seed, 1),
        None => (
            value("--start").unwrap_or(0),
            value("--seeds").unwrap_or(100),
        ),
    };

    let started = Instant::now();
    let next = AtomicU64::new(start);
    let done = AtomicU64::new(0);
    let failures: Mutex<Vec<Violation>> = Mutex::new(Vec::new());
    let totals = Mutex::new((0u64, 0u64, 0u64, 0u64, 0u64));
    let workers = value("--threads")
        .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| n.get()))
        .max(1);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let seed = next.fetch_add(1, Ordering::Relaxed);
                    if seed >= start + count {
                        break;
                    }
                    let result = run(seed, options).and_then(|report| {
                        if determinism {
                            let again = run(seed, options)?;
                            if again != report {
                                return Err(Violation {
                                    seed,
                                    at_ms: report.sim_ms,
                                    what: "same seed produced a different trace".to_owned(),
                                });
                            }
                        }
                        Ok(report)
                    });
                    match result {
                        Ok(report) => {
                            if count == 1 {
                                println!("{report:#?}");
                            }
                            let mut t = totals.lock().expect("not poisoned");
                            t.0 += report.messages_sent;
                            t.1 += report.deliveries;
                            t.2 += report.crashes + report.crashes_mid_step;
                            t.3 += report.max_epoch;
                            t.4 += report.signals_shown;
                        }
                        Err(violation) => {
                            eprintln!("FAIL {violation}");
                            failures.lock().expect("not poisoned").push(violation);
                        }
                    }
                    let finished = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if count > 1 && finished.is_multiple_of(25) {
                        eprintln!("{finished}/{count} seeds ({:.0?})", started.elapsed());
                    }
                }
            });
        }
    });

    let failures = failures.into_inner().expect("not poisoned");
    let (sent, delivered, crashes, epochs, signals) = totals.into_inner().expect("not poisoned");
    println!(
        "{count} seeds in {:.1?}: {} failed; {sent} messages sent, {delivered} delivered, {signals} signals shown, {crashes} crashes, {epochs} epochs advanced",
        started.elapsed(),
        failures.len()
    );
    if failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
