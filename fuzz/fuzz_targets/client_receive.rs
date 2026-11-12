//! A device in two real conversations (the fixture), fed whatever a
//! hostile mailbox could send: responses to its requests, pushes and raw
//! frames, real log entries in any order, interleaved with time passing and
//! its user acting. It never panics, every request it sends is well formed,
//! and it can always restart from what it persisted.

#![no_main]

use krypt_fuzz::client::{self, Device};
use krypt_fuzz::fixture::Fixture;
use krypt_fuzz::input::Input;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let fixture = Fixture::get();
    let mut device = Device::from_fixture(fixture);
    client::run(fixture, &mut device, &mut Input::new(data));
    device.check_restart();
});
