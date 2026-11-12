//! A device persisted through SQLite comes back exactly as it was.

use krypt_core::client::{Client, Config, Effect, Step};
use krypt_core::mailbox::LocalMailbox;
use krypt_core::provider::Rand;
use krypt_store::Store;

fn persist_and_run(
    store: &mut Store,
    mailbox: &mut LocalMailbox,
    client: &mut Client,
    step: Step,
    now: u64,
) {
    let mut pending = vec![step];
    while let Some(step) = pending.pop() {
        store.apply(&step.writes).expect("durable write");
        for effect in step.effects {
            if let Effect::Mailbox(request) = effect
                && let Some(response) = mailbox.handle(0, &request)
            {
                pending.push(client.receive(now, &response));
            }
        }
    }
}

#[test]
fn device_restores_from_sqlite() {
    let mut mailbox = LocalMailbox::new();
    let mut store = Store::open_in_memory().unwrap();
    let (mut alice, step) = Client::create(Config::default(), Rand::seeded(1), 0);
    persist_and_run(&mut store, &mut mailbox, &mut alice, step, 0);

    let mut bob_store = Store::open_in_memory().unwrap();
    let (mut bob, step) = Client::create(Config::default(), Rand::seeded(2), 0);
    persist_and_run(&mut bob_store, &mut mailbox, &mut bob, step, 0);

    let (conversation, step) = alice.start_conversation(10, bob.contact_card()).unwrap();
    persist_and_run(&mut store, &mut mailbox, &mut alice, step, 10);
    let (_, step) = alice.send(20, conversation, "persisted?").unwrap();
    persist_and_run(&mut store, &mut mailbox, &mut alice, step, 20);
    let before = alice.epoch(&conversation).unwrap();

    let (restored, _) = Client::restore(
        Config::default(),
        Rand::seeded(3),
        store.load().unwrap(),
        30,
    )
    .unwrap();
    assert_eq!(restored.identity(), alice.identity());
    assert_eq!(restored.contact_card(), alice.contact_card());
    assert_eq!(restored.epoch(&conversation).unwrap(), before);
    assert_eq!(
        restored.outbox_len(&conversation),
        alice.outbox_len(&conversation)
    );
}
