//! The mailbox, statefully: a script of requests from anyone, with time
//! passing. It never panics, answers every request (and nothing else) with
//! a response that decodes, and every push and wakeup it makes is well
//! formed.

#![no_main]

use krypt_fuzz::input::Input;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    krypt_fuzz::mailbox::run(&mut Input::new(data));
});
