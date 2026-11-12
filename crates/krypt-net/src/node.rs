//! A running device: the client state machine, its durable store and the
//! mailbox, wired so that every step is persisted before it acts.
//!
//! The client and the store live on one dedicated thread (the actor). It
//! takes inputs (ticks, frames, commands) one at a time, applies the step's
//! writes with an fsync, and only then releases the step's effects: frames
//! go out on async tasks, events go to subscribers. Blocking disk work never
//! touches the async runtime.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use krypt_core::client::{self, Client, Effect, Event, SharedFile, Step};
use krypt_core::file;
use krypt_core::identity::{ContactCard, DeviceId, IdentityKey};
use krypt_core::provider::Rand;
use krypt_store::Store;
use krypt_wire::Route;
use krypt_wire::limits::{FILE_PART_SIZE, FILE_SIZE_MAX, FILE_TAG_SIZE};
use krypt_wire::msg::{FilePart, Platform, PushTarget};
use tokio::runtime::Handle;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinSet;
use tracing::{debug, error};

use crate::mailbox::HttpMailbox;
use crate::subscribe::Subscriptions;

#[derive(Clone, Debug)]
pub struct Config {
    /// Where the device keeps its database.
    pub data_dir: PathBuf,
    /// The mailbox's base URL.
    pub mailbox: String,
    /// How often the client's timers run.
    pub tick: Duration,
    pub client: client::Config,
}

impl Config {
    pub fn new(data_dir: impl Into<PathBuf>, mailbox: impl Into<String>) -> Config {
        Config {
            data_dir: data_dir.into(),
            mailbox: mailbox.into(),
            tick: Duration::from_millis(50),
            client: client::Config {
                // New entries are pushed over WebSockets, and every reconnect
                // fetches what was missed; polling is only a safety net.
                poll_interval_ms: 300_000,
                ..client::Config::default()
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Store(#[from] krypt_store::Error),
    #[error(transparent)]
    Client(#[from] client::Error),
    #[error(transparent)]
    Mailbox(#[from] crate::mailbox::Error),
    #[error("the device has stopped")]
    Stopped,
    #[error("files can be up to {FILE_SIZE_MAX} bytes")]
    FileTooLarge,
    #[error("the mailbox refused the file (status {0})")]
    FileRefused(u16),
    #[error("the file is no longer stored")]
    FileGone,
    #[error(transparent)]
    File(#[from] file::FileError),
}

/// A conversation as the UI sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conversation {
    pub id: Route,
    pub members: Vec<IdentityKey>,
    pub active: bool,
    pub epoch: u64,
}

type Reply<T> = oneshot::Sender<Result<T, Error>>;

enum Command {
    Start(ContactCard, Reply<Route>),
    Invite(Route, ContactCard, Reply<()>),
    Remove(Route, IdentityKey, Reply<()>),
    Send(Route, String, Reply<u64>),
    NewFile(oneshot::Sender<([u8; 16], [u8; 32])>),
    FileAuth(Route, [u8; 16], u32, u32, Reply<FilePart>),
    SendFile(Route, Box<SharedFile>, Reply<u64>),
    PushTarget(Option<(Platform, Vec<u8>)>, Reply<()>),
    Conversations(oneshot::Sender<Vec<Conversation>>),
}

enum Input {
    Tick,
    Mailbox(Vec<u8>),
    /// A subscription (re)connected: fetch whatever it missed.
    Subscribed,
    Command(Command),
    Shutdown,
}

#[derive(Debug)]
pub struct Node {
    inputs: mpsc::UnboundedSender<Input>,
    mailbox: HttpMailbox,
    events: broadcast::Sender<Event>,
    actor: Option<JoinHandle<()>>,
    tasks: JoinSet<()>,
    identity: IdentityKey,
    card: ContactCard,
    device: DeviceId,
}

fn now_ms() -> u64 {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
}

impl Node {
    /// Opens (or creates) the device stored in `config.data_dir` and starts it.
    pub async fn open(config: Config) -> Result<Node, Error> {
        crate::install_crypto_provider();
        std::fs::create_dir_all(&config.data_dir)?;
        let mut store = Store::open(config.data_dir.join("device.db"))?;

        let now = now_ms();
        let records = store.load()?;
        let (client, step) = if records.is_empty() {
            Client::create(config.client, Rand::os(), now)
        } else {
            Client::restore(config.client, Rand::os(), records, now)?
        };
        let device = client.device();
        store.apply(&step.writes)?;

        let (inputs, receiver) = mpsc::unbounded_channel();
        let (events, _) = broadcast::channel(4096);
        let (on_frame, on_connected) = (inputs.clone(), inputs.clone());
        let subscriptions = Subscriptions::new(
            &config.mailbox,
            move |frame| drop(on_frame.send(Input::Mailbox(frame))),
            move |_| drop(on_connected.send(Input::Subscribed)),
        )?;
        let io = Io {
            runtime: Handle::current(),
            inputs: inputs.clone(),
            events: events.clone(),
            mailbox: HttpMailbox::new(&config.mailbox)?,
            subscriptions: Arc::new(subscriptions),
        };
        let identity = client.identity();
        let card = client.contact_card();
        io.perform(step.effects);

        let mut tasks = JoinSet::new();
        let to_actor = inputs.clone();
        let tick = config.tick;
        tasks.spawn(async move {
            let mut interval = tokio::time::interval(tick);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                if to_actor.send(Input::Tick).is_err() {
                    break;
                }
            }
        });
        let actor = std::thread::Builder::new()
            .name("krypt-device".into())
            .spawn(move || run(client, store, receiver, io))?;

        Ok(Node {
            inputs,
            mailbox: HttpMailbox::new(&config.mailbox)?,
            events,
            actor: Some(actor),
            tasks,
            identity,
            card,
            device,
        })
    }

    pub fn identity(&self) -> IdentityKey {
        self.identity
    }

    pub fn device(&self) -> DeviceId {
        self.device
    }

    pub fn contact_card(&self) -> ContactCard {
        self.card
    }

    /// Everything the device reports from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    async fn ask<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> Result<T, Error> {
        let (reply, answer) = oneshot::channel();
        self.inputs
            .send(Input::Command(make(reply)))
            .map_err(|_| Error::Stopped)?;
        answer.await.map_err(|_| Error::Stopped)?
    }

    pub async fn start_conversation(&self, contact: ContactCard) -> Result<Route, Error> {
        self.ask(|reply| Command::Start(contact, reply)).await
    }

    pub async fn invite(&self, conversation: Route, contact: ContactCard) -> Result<(), Error> {
        self.ask(|reply| Command::Invite(conversation, contact, reply))
            .await
    }

    pub async fn remove(&self, conversation: Route, identity: IdentityKey) -> Result<(), Error> {
        self.ask(|reply| Command::Remove(conversation, identity, reply))
            .await
    }

    /// Queues a message; returns its sender_seq.
    pub async fn send(&self, conversation: Route, text: impl Into<String>) -> Result<u64, Error> {
        let text = text.into();
        self.ask(|reply| Command::Send(conversation, text, reply))
            .await
    }

    /// Shares a file: seals it in parts, stores each with proof of
    /// membership (renewed if a commit makes it stale), then sends the
    /// message. Returns its sender_seq. No metadata is removed here: callers
    /// pass photos through `krypt_core::scrub` first.
    pub async fn send_file(
        &self,
        conversation: Route,
        bytes: &[u8],
        name: &str,
        media_type: &str,
    ) -> Result<u64, Error> {
        let size = bytes.len() as u64;
        if size > FILE_SIZE_MAX {
            return Err(Error::FileTooLarge);
        }
        let (reply, answer) = oneshot::channel();
        self.inputs
            .send(Input::Command(Command::NewFile(reply)))
            .map_err(|_| Error::Stopped)?;
        let (id, key) = answer.await.map_err(|_| Error::Stopped)?;
        for part in 0..file::parts(size) {
            let start = part as usize * FILE_PART_SIZE as usize;
            let mut sealed = bytes[start..start + file::plain_len(size, part) as usize].to_vec();
            file::seal(&key, size, part, &mut sealed);
            match self.store_part(conversation, id, part, sealed).await? {
                200 | 201 => {}
                status => return Err(Error::FileRefused(status)),
            }
        }
        let shared = SharedFile {
            id,
            key,
            size,
            name: name.to_owned(),
            media_type: media_type.to_owned(),
            width: 0,
            height: 0,
            thumbnail: Vec::new(),
        };
        self.ask(|reply| Command::SendFile(conversation, Box::new(shared), reply))
            .await
    }

    /// Stores one sealed part of file `id` with proof of membership,
    /// renewing the proof if a commit makes it stale and backing off when
    /// the edge is busy. Returns the final HTTP status: 201 stored, 200
    /// already stored (never replaced), anything else refused.
    pub async fn store_part(
        &self,
        conversation: Route,
        id: [u8; 16],
        part: u32,
        sealed: Vec<u8>,
    ) -> Result<u16, Error> {
        let len = u32::try_from(sealed.len()).map_err(|_| Error::FileTooLarge)?;
        let mut attempt = 0;
        loop {
            let proof = self
                .ask(|reply| Command::FileAuth(conversation, id, part, len, reply))
                .await?;
            let auth: String = proof
                .epoch
                .to_le_bytes()
                .iter()
                .chain(&proof.auth)
                .map(|b| format!("{b:02x}"))
                .collect();
            let status = self
                .mailbox
                .put_part(&conversation, &id, part, &auth, sealed.clone())
                .await?;
            match status {
                // A commit landed (409): catch up, then prove membership again.
                409 | 429 | 500..=599 if attempt < 8 => {
                    let _ = self.inputs.send(Input::Subscribed);
                    tokio::time::sleep(Duration::from_millis(250 << attempt.min(6))).await;
                    attempt += 1;
                }
                status => return Ok(status),
            }
        }
    }

    /// Fetches and opens a file shared in `conversation`.
    pub async fn fetch_file(
        &self,
        conversation: Route,
        shared: &SharedFile,
    ) -> Result<Vec<u8>, Error> {
        if shared.size > FILE_SIZE_MAX {
            return Err(Error::FileTooLarge);
        }
        let mut out = Vec::with_capacity(usize::try_from(shared.size).unwrap_or(0));
        for part in 0..file::parts(shared.size) {
            let max = (FILE_PART_SIZE + FILE_TAG_SIZE) as usize;
            let mut stored = self
                .mailbox
                .get_part(&conversation, &shared.id, part, max)
                .await?
                .ok_or(Error::FileGone)?;
            file::open(&shared.key, shared.size, part, &mut stored)?;
            out.extend_from_slice(&stored);
        }
        Ok(out)
    }

    /// Where the mailbox should wake this device when it is not connected
    /// (`None` stops wakeups).
    pub async fn set_push_target(&self, target: Option<(Platform, Vec<u8>)>) -> Result<(), Error> {
        self.ask(|reply| Command::PushTarget(target, reply)).await
    }

    pub async fn conversations(&self) -> Result<Vec<Conversation>, Error> {
        let (reply, answer) = oneshot::channel();
        self.inputs
            .send(Input::Command(Command::Conversations(reply)))
            .map_err(|_| Error::Stopped)?;
        answer.await.map_err(|_| Error::Stopped)
    }

    /// Stops the device after its current step; nothing persisted is lost.
    pub async fn shutdown(mut self) {
        let _ = self.inputs.send(Input::Shutdown);
        if let Some(actor) = self.actor.take() {
            let _ = tokio::task::spawn_blocking(move || actor.join()).await;
        }
        self.tasks.shutdown().await;
    }
}

/// Performs a step's effects once it has been persisted.
struct Io {
    runtime: Handle,
    inputs: mpsc::UnboundedSender<Input>,
    events: broadcast::Sender<Event>,
    mailbox: HttpMailbox,
    subscriptions: Arc<Subscriptions>,
}

impl Io {
    fn perform(&self, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::Mailbox(frame) => {
                    let Err(frame) = self.subscriptions.try_send(frame) else {
                        continue;
                    };
                    let mailbox = self.mailbox.clone();
                    let inputs = self.inputs.clone();
                    self.runtime.spawn(async move {
                        match mailbox.request(frame).await {
                            Ok(Some(response)) => {
                                let _ = inputs.send(Input::Mailbox(response));
                            }
                            Ok(None) => {}
                            // The client retries on its own timer.
                            Err(e) => debug!("mailbox: {e}"),
                        }
                    });
                }
                Effect::Event(event) => {
                    let _ = self.events.send(event);
                }
            }
        }
    }
}

fn run(mut client: Client, mut store: Store, mut inputs: mpsc::UnboundedReceiver<Input>, io: Io) {
    let mut followed = BTreeSet::new();
    while let Some(input) = inputs.blocking_recv() {
        let routes: BTreeSet<Route> = client.routes().into_iter().collect();
        if routes != followed {
            let _guard = io.runtime.enter();
            io.subscriptions.set_routes(&routes);
            followed = routes;
        }
        let now = now_ms();
        let mut reply: Option<Box<dyn FnOnce()>> = None;
        let step = match input {
            Input::Shutdown => break,
            Input::Tick => client.tick(now),
            Input::Mailbox(frame) => client.receive(now, &frame),
            Input::Subscribed => client.poll_now(now),
            Input::Command(Command::Conversations(answer)) => {
                let list = client
                    .conversations()
                    .map(|id| Conversation {
                        id,
                        members: client.members(&id),
                        active: client.is_active(&id),
                        epoch: client.epoch(&id).map_or(0, |(epoch, _)| epoch),
                    })
                    .collect();
                let _ = answer.send(list);
                continue;
            }
            Input::Command(Command::Start(contact, answer)) => {
                match client.start_conversation(now, contact) {
                    Ok((id, step)) => {
                        reply = Some(Box::new(move || drop(answer.send(Ok(id)))));
                        step
                    }
                    Err(e) => {
                        let _ = answer.send(Err(e.into()));
                        continue;
                    }
                }
            }
            Input::Command(Command::Invite(id, contact, answer)) => {
                match client.invite(now, id, contact) {
                    Ok(step) => {
                        reply = Some(Box::new(move || drop(answer.send(Ok(())))));
                        step
                    }
                    Err(e) => {
                        let _ = answer.send(Err(e.into()));
                        continue;
                    }
                }
            }
            Input::Command(Command::Remove(id, identity, answer)) => {
                match client.remove(now, id, identity) {
                    Ok(step) => {
                        reply = Some(Box::new(move || drop(answer.send(Ok(())))));
                        step
                    }
                    Err(e) => {
                        let _ = answer.send(Err(e.into()));
                        continue;
                    }
                }
            }
            Input::Command(Command::PushTarget(target, answer)) => {
                let target = target.as_ref().map(|(platform, address)| PushTarget {
                    platform: *platform,
                    address,
                });
                reply = Some(Box::new(move || drop(answer.send(Ok(())))));
                client.set_push_target(now, target)
            }
            Input::Command(Command::NewFile(answer)) => {
                let _ = answer.send(client.new_file());
                continue;
            }
            Input::Command(Command::FileAuth(id, file, part, len, answer)) => {
                let _ = answer.send(client.file_auth(id, file, part, len).map_err(Error::from));
                continue;
            }
            Input::Command(Command::SendFile(id, shared, answer)) => {
                match client.send_file(now, id, *shared) {
                    Ok((seq, step)) => {
                        reply = Some(Box::new(move || drop(answer.send(Ok(seq)))));
                        step
                    }
                    Err(e) => {
                        let _ = answer.send(Err(e.into()));
                        continue;
                    }
                }
            }
            Input::Command(Command::Send(id, text, answer)) => match client.send(now, id, &text) {
                Ok((seq, step)) => {
                    reply = Some(Box::new(move || drop(answer.send(Ok(seq)))));
                    step
                }
                Err(e) => {
                    let _ = answer.send(Err(e.into()));
                    continue;
                }
            },
        };
        persist_then_act(&mut store, step, reply, &io);
    }
}

fn persist_then_act(store: &mut Store, step: Step, reply: Option<Box<dyn FnOnce()>>, io: &Io) {
    if let Err(e) = store.apply(&step.writes) {
        // Acting on a step that is not durable could, after a restart, mean
        // reusing MLS key material. Stopping is the only safe response.
        error!("storage failed, device stopping: {e}");
        std::process::abort();
    }
    if let Some(reply) = reply {
        reply();
    }
    io.perform(step.effects);
}
