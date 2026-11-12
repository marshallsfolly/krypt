//! Restarting a device from damaged storage: the fixture's records with
//! values replaced, flipped, truncated, swapped or deleted, and records
//! added. Restoring returns an error or a device that works; it never
//! panics, here or while the device then reads its logs and runs a day.

#![no_main]

use krypt_fuzz::client;
use krypt_fuzz::fixture::Fixture;
use krypt_fuzz::input::Input;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let fixture = Fixture::get();
    let disk = client::edit(fixture, &mut Input::new(data));
    client::restore_and_run(fixture, disk);
});
