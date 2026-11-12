//! krypt on the command line.
//!
//!   krypt init [--mailbox URL]
//!   krypt card                 print this device's contact card
//!   krypt chat                 interactive session
//!
//! Each `--profile` is a separate device with its own identity, stored in
//! `$XDG_DATA_HOME/krypt/<profile>` (or `--data-dir`).

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use clap::{Parser, Subcommand};
use krypt_core::client::LinkChange;
use krypt_core::identity::{ContactCard, IdentityKey, fingerprint};
use krypt_core::scrub::{self, Format};
use krypt_net::{Config, Content, Event, Node, SharedFile};
use krypt_wire::Route;
use krypt_wire::msg::CallKind;
use tokio::io::{AsyncBufReadExt, BufReader};

const DEFAULT_MAILBOX: &str = "https://api.krypt.chat";
/// Where contact links open: the web client.
const WEB: &str = "https://krypt.chat";

#[derive(Parser)]
#[command(version, about = "krypt: private, end-to-end encrypted chat")]
struct Cli {
    /// Which device to use; each profile is a separate identity.
    #[arg(long, default_value = "default", global = true)]
    profile: String,
    /// Store the device here instead of the profile directory.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Set where this device connects. Optional: `chat` and `card` create
    /// the device with defaults on first use.
    Init {
        #[arg(long, default_value = DEFAULT_MAILBOX)]
        mailbox: String,
    },
    /// Print this device's contact card for others to start a chat with.
    Card,
    /// Chat interactively. Type /help inside.
    Chat,
}

/// Settings the CLI keeps next to the device database.
struct Settings {
    mailbox: String,
}

impl Settings {
    fn file(dir: &Path) -> PathBuf {
        dir.join("cli.conf")
    }

    fn load(dir: &Path) -> Settings {
        let mut settings = Settings {
            mailbox: std::env::var("KRYPT_MAILBOX").unwrap_or_else(|_| DEFAULT_MAILBOX.to_owned()),
        };
        let text = std::fs::read_to_string(Settings::file(dir)).unwrap_or_default();
        for line in text.lines() {
            if let Some(("mailbox", value)) = line.split_once('=') {
                settings.mailbox = value.to_owned();
            }
        }
        settings
    }

    fn save(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(Settings::file(dir), format!("mailbox={}\n", self.mailbox))
    }

    fn config(&self, dir: &Path) -> Config {
        Config::new(dir, &self.mailbox)
    }
}

fn data_dir(cli: &Cli) -> PathBuf {
    if let Some(dir) = &cli.data_dir {
        return dir.clone();
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share")
        });
    base.join("krypt").join(&cli.profile)
}

fn short(id: &Route) -> String {
    id[..3].iter().map(|b| format!("{b:02x}")).collect()
}

fn who(identity: &IdentityKey, me: &IdentityKey) -> String {
    if identity == me {
        "you".to_owned()
    } else {
        fingerprint(identity)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        // Quiet unless asked: KRYPT_LOG=debug (or any filter) to see more.
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("KRYPT_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("krypt_net=error")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let dir = data_dir(&cli);
    let result = match &cli.command {
        Command::Init { mailbox } => {
            let settings = Settings {
                mailbox: mailbox.clone(),
            };
            init(&dir, settings).await
        }
        Command::Card => card(&dir).await,
        Command::Chat => chat(&dir).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn init(dir: &Path, settings: Settings) -> Result<(), Box<dyn std::error::Error>> {
    settings.save(dir)?;
    let node = Node::open(settings.config(dir)).await?;
    println!("device ready in {}", dir.display());
    println!("identity {}", fingerprint(&node.identity()));
    println!("{}", node.contact_card().to_text());
    node.shutdown().await;
    Ok(())
}

async fn card(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let node = Node::open(Settings::load(dir).config(dir)).await?;
    let card = node.contact_card().to_text();
    node.shutdown().await;
    // A terminal gets a code a phone can scan; a pipe gets just the card.
    if std::io::stdout().is_terminal() {
        let link = format!("{WEB}/#add={card}");
        println!("{}", qr(&link)?);
        println!("{link}\n");
    }
    println!("{card}");
    Ok(())
}

/// Reads a file to share: photos and videos without their location, camera
/// and editing metadata, and the media type to send it as.
fn prepare(path: &Path) -> Result<(Vec<u8>, String), String> {
    let mut bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let not_cleaned =
        |e: scrub::ScrubError| format!("could not remove its metadata ({e}); not sent");
    let media_type = match scrub::detect(&bytes) {
        Some(format @ (Format::Jpeg | Format::Png | Format::Webp | Format::Gif)) => {
            bytes = scrub::scrub_image(&bytes).map_err(not_cleaned)?;
            match format {
                Format::Jpeg => "image/jpeg",
                Format::Png => "image/png",
                Format::Gif => "image/gif",
                _ => "image/webp",
            }
        }
        Some(Format::Webm) => {
            scrub::scrub_webm(&mut bytes).map_err(not_cleaned)?;
            "video/webm"
        }
        Some(Format::StillImage) => {
            return Err(
                "convert this photo to JPEG first: krypt cannot clean its metadata".to_owned(),
            );
        }
        Some(Format::Mp4) => {
            scrub::scrub_mp4(&mut bytes).map_err(not_cleaned)?;
            if extension == "mov" {
                "video/quicktime"
            } else {
                "video/mp4"
            }
        }
        None => match extension.as_str() {
            "heic" | "heif" | "avif" | "tif" | "tiff" => {
                return Err(
                    "convert this photo to JPEG first: krypt cannot clean its metadata".to_owned(),
                );
            }
            "pdf" => "application/pdf",
            "txt" => "text/plain",
            _ => "application/octet-stream",
        },
    };
    Ok((bytes, media_type.to_owned()))
}

/// Where to save a received file: its name with any path and control or
/// text-direction characters removed, made unique in `dir`.
fn save_path(dir: &Path, name: &str) -> PathBuf {
    let name: String = Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.starts_with('.'))
        .unwrap_or("file")
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect();
    let mut path = dir.join(&name);
    for n in 1.. {
        if !path.exists() {
            break;
        }
        path = dir.join(format!("{n}-{name}"));
    }
    path
}

/// A QR code in block characters, light on the terminal's dark background
/// (scanners read it as dark on light).
fn qr(text: &str) -> Result<String, qrcode::types::QrError> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::M)?;
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .build())
}

const HELP: &str = "\
  /new <card>      start a conversation with someone
  /invite <card>   add someone to the current conversation
  /list            list conversations
  /use <n>         switch to conversation n
  /send <path>     share a file (photos and videos lose their metadata)
  /save <n> [dir]  save received file n (see the [file n] line)
  /card            show your contact card
  /quit            leave
  anything else    send it to the current conversation";

async fn chat(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let settings = Settings::load(dir);
    let node = Node::open(settings.config(dir)).await?;
    let me = node.identity();
    println!(
        "krypt · {} · mailbox {}",
        fingerprint(&me),
        settings.mailbox
    );
    println!("your card: {}", node.contact_card().to_text());
    println!("type /help for commands");

    let mut events = node.subscribe();
    let received: Arc<Mutex<Vec<(Route, SharedFile)>>> = Arc::default();
    let files = received.clone();
    let printer = tokio::spawn(async move {
        loop {
            let event = match events.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    eprintln!("(missed {n} events)");
                    continue;
                }
                Err(_) => break,
            };
            match event {
                Event::Message {
                    conversation,
                    from,
                    content,
                    ..
                } => {
                    let shown = match content {
                        Content::Text(text) => text,
                        Content::File(file) => {
                            let mut files = files.lock().expect("not poisoned");
                            let text = format!(
                                "[file {}] {} ({} bytes, {}); /save {0} to keep it",
                                files.len(),
                                file.name,
                                file.size,
                                file.media_type
                            );
                            files.push((conversation, *file));
                            text
                        }
                        // The command line has no audio or video: it only
                        // says when someone calls or hangs up.
                        Content::Call(call) => match call.kind {
                            CallKind::Offer if call.to == [0; 32] => {
                                let kind = if call.video { "video" } else { "voice" };
                                format!("[{kind} call] answer it in the app")
                            }
                            CallKind::Join => "[group call] join it in the app".to_owned(),
                            CallKind::End(_) if call.to == [0; 32] => "[call ended]".to_owned(),
                            _ => continue,
                        },
                        Content::Leave => "[left the group]".to_owned(),
                        Content::Reply { to, text } => format!("[reply to #{}] {text}", to.seq),
                        Content::React { to, emoji } if emoji.is_empty() => {
                            format!("[took back a reaction to #{}]", to.seq)
                        }
                        Content::React { to, emoji } => format!("[reacted {emoji} to #{}]", to.seq),
                        Content::Edit { to, text } => format!("[edited #{}] {text}", to.seq),
                        Content::Delete { to } => format!("[deleted #{}]", to.seq),
                        Content::Voice(voice) => format!(
                            "[voice message, {} s] answer it in the app",
                            voice.duration_ms.div_ceil(1000)
                        ),
                        // Read receipts are for screens.
                        Content::Receipt(_) => continue,
                    };
                    println!("[{}] {}: {shown}", short(&conversation), fingerprint(&from));
                }
                Event::Joined {
                    conversation,
                    members,
                    ..
                } => {
                    let names: Vec<_> = members.iter().map(|m| who(m, &me)).collect();
                    println!(
                        "* joined [{}] with {}",
                        short(&conversation),
                        names.join(", ")
                    );
                }
                Event::MembersAdded {
                    conversation,
                    identities,
                } => {
                    for identity in identities {
                        println!(
                            "* [{}] {} joined",
                            short(&conversation),
                            who(&identity, &me)
                        );
                    }
                }
                Event::MembersRemoved {
                    conversation,
                    identities,
                    by,
                } => {
                    for identity in identities {
                        match &by {
                            Some(by) => println!(
                                "* [{}] {} removed {}",
                                short(&conversation),
                                who(by, &me),
                                who(&identity, &me)
                            ),
                            None => println!(
                                "* [{}] {} left",
                                short(&conversation),
                                who(&identity, &me)
                            ),
                        }
                    }
                }
                Event::Removed { conversation } => {
                    println!("* you were removed from [{}]", short(&conversation))
                }
                Event::InviteFailed {
                    conversation,
                    identity,
                } => {
                    println!(
                        "! [{}] could not invite {}",
                        short(&conversation),
                        fingerprint(&identity)
                    );
                }
                Event::Undecryptable {
                    conversation,
                    reason,
                } => {
                    println!(
                        "! [{}] a message could not be decrypted ({reason})",
                        short(&conversation)
                    );
                }
                Event::Desync {
                    conversation,
                    reason,
                } => {
                    println!(
                        "! [{}] lost track of this conversation: {reason}",
                        short(&conversation)
                    );
                }
                Event::Timer {
                    conversation,
                    by,
                    seconds,
                } => {
                    let what = if seconds == 0 {
                        "turned off disappearing messages".to_owned()
                    } else {
                        format!("set messages to disappear {seconds} s after they are seen")
                    };
                    println!("* [{}] {} {what}", short(&conversation), who(&by, &me));
                }
                Event::Renamed {
                    conversation,
                    by,
                    name,
                } => {
                    println!(
                        "* [{}] {} named the group \"{name}\"",
                        short(&conversation),
                        who(&by, &me)
                    );
                }
                Event::Rules {
                    conversation,
                    by,
                    admins_added,
                    admins_removed,
                    link,
                    ..
                } => {
                    let mut said = Vec::new();
                    match link {
                        Some(LinkChange::On) => said.push("turned on the invite link".to_owned()),
                        Some(LinkChange::Reset) => said.push("reset the invite link".to_owned()),
                        Some(LinkChange::Off) => said.push("turned off the invite link".to_owned()),
                        None => {}
                    }
                    for admin in &admins_added {
                        said.push(format!("made {} an admin", who(admin, &me)));
                    }
                    for admin in &admins_removed {
                        said.push(format!("took {} off the admins", who(admin, &me)));
                    }
                    if said.is_empty() {
                        said.push("changed who may add people or rename the group".to_owned());
                    }
                    println!(
                        "* [{}] {} {}",
                        short(&conversation),
                        who(&by, &me),
                        said.join(", ")
                    );
                }
                // Invite links are run from the app.
                Event::JoinRequest {
                    conversation, name, ..
                } => {
                    println!(
                        "* [{}] {name} asks to join (approve it in the app)",
                        short(&conversation)
                    );
                }
                Event::Refused {
                    conversation,
                    reason,
                } => {
                    println!("* [{}] not done: {reason}", short(&conversation));
                }
                Event::TimerRefused { conversation, .. } => {
                    println!(
                        "* [{}] someone's krypt is too old for disappearing messages",
                        short(&conversation)
                    );
                }
                // Typing and presence are for screens; the command line keeps
                // its output to what was said.
                Event::Started { .. }
                | Event::Sealed { .. }
                | Event::Sent { .. }
                | Event::Signal { .. } => {}
            }
        }
    });

    let mut current: Option<Route> = node.conversations().await?.first().map(|c| c.id);
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (command, argument) = line.split_once(' ').unwrap_or((line, ""));
        // Nothing selected yet (say, we were invited after starting): use the
        // first active conversation.
        if current.is_none() {
            current = node
                .conversations()
                .await
                .ok()
                .and_then(|list| list.into_iter().find(|c| c.active))
                .map(|c| c.id);
        }
        let outcome: Result<(), String> = match command {
            "/quit" | "/exit" => break,
            "/help" => {
                println!("{HELP}");
                Ok(())
            }
            "/card" => {
                println!("{}", node.contact_card().to_text());
                Ok(())
            }
            "/new" => match ContactCard::from_text(argument) {
                Some(contact) => node
                    .start_conversation(contact)
                    .await
                    .map_err(|e| e.to_string())
                    .map(|id| {
                        println!(
                            "* started [{}]; inviting {}",
                            short(&id),
                            fingerprint(&contact.identity)
                        );
                        current = Some(id);
                    }),
                None => Err("that is not a contact card".to_owned()),
            },
            "/invite" => match (current, ContactCard::from_text(argument)) {
                (Some(id), Some(contact)) => {
                    node.invite(id, contact).await.map_err(|e| e.to_string())
                }
                (None, _) => Err("no conversation selected".to_owned()),
                (_, None) => Err("that is not a contact card".to_owned()),
            },
            "/list" => {
                let conversations = node.conversations().await.map_err(|e| e.to_string())?;
                for (i, c) in conversations.iter().enumerate() {
                    let members: Vec<_> = c.members.iter().map(|m| who(m, &me)).collect();
                    let marker = if Some(c.id) == current { "*" } else { " " };
                    let state = if c.active { "" } else { " (inactive)" };
                    println!(
                        "{marker}{i} [{}] epoch {} · {}{state}",
                        short(&c.id),
                        c.epoch,
                        members.join(", ")
                    );
                }
                Ok(())
            }
            "/use" => {
                let conversations = node.conversations().await.map_err(|e| e.to_string())?;
                match argument
                    .parse::<usize>()
                    .ok()
                    .and_then(|i| conversations.get(i))
                {
                    Some(c) => {
                        current = Some(c.id);
                        println!("* now in [{}]", short(&c.id));
                        Ok(())
                    }
                    None => Err("no such conversation; see /list".to_owned()),
                }
            }
            "/send" => match (current, argument) {
                (None, _) => Err("no conversation selected".to_owned()),
                (_, "") => Err("which file? /send <path>".to_owned()),
                (Some(id), path) => {
                    let path = Path::new(path);
                    match prepare(path) {
                        Ok((bytes, media_type)) => {
                            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
                            println!("* uploading {name} ({} bytes)…", bytes.len());
                            node.send_file(id, &bytes, name, &media_type)
                                .await
                                .map(|_| println!("* shared {name}"))
                                .map_err(|e| e.to_string())
                        }
                        Err(e) => Err(e),
                    }
                }
            },
            "/save" => {
                let (n, dir) = argument.split_once(' ').unwrap_or((argument, "."));
                let file = n
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| received.lock().expect("not poisoned").get(n).cloned());
                match file {
                    None => Err("no such file; the [file n] line has its number".to_owned()),
                    Some((conversation, file)) => {
                        match node.fetch_file(conversation, &file).await {
                            Ok(bytes) => {
                                let path = save_path(Path::new(dir), &file.name);
                                std::fs::write(&path, bytes)
                                    .map(|()| println!("* saved {}", path.display()))
                                    .map_err(|e| e.to_string())
                            }
                            Err(e) => Err(e.to_string()),
                        }
                    }
                }
            }
            _ if command.starts_with('/') => Err(format!("unknown command {command}; see /help")),
            _ => match current {
                Some(id) => node
                    .send(id, line)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                None => Err("start a conversation first: /new <card>".to_owned()),
            },
        };
        if let Err(e) = outcome {
            println!("! {e}");
        }
    }

    printer.abort();
    node.shutdown().await;
    Ok(())
}
