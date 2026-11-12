//! A small, fast slice of the simulator for `cargo test`. The long runs live
//! in `just sim`.

use krypt_sim::{Options, run};

fn options(clients: usize) -> Options {
    Options {
        clients,
        chaos_ms: 10_000,
        ..Options::default()
    }
}

#[test]
fn healthy_network_converges() {
    let calm = Options {
        network_faults: false,
        crashes: false,
        ..options(3)
    };
    for seed in 0..5 {
        let report = run(seed, calm).unwrap_or_else(|v| panic!("{v}"));
        assert!(report.deliveries > 0);
        assert_eq!(report.crashes, 0);
    }
}

#[test]
fn chaos_preserves_every_invariant() {
    for (seed, clients) in (100..124).zip([2, 3, 4, 6].into_iter().cycle()) {
        run(seed, options(clients)).unwrap_or_else(|v| panic!("{v}"));
    }
}

#[test]
fn a_seed_replays_exactly() {
    for seed in [7, 8] {
        let a = run(seed, options(4)).unwrap_or_else(|v| panic!("{v}"));
        let b = run(seed, options(4)).unwrap_or_else(|v| panic!("{v}"));
        assert_eq!(a, b);
    }
}
