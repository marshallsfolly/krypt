// Every word the app shows, in one table: themes change how things look,
// never what they say (docs/design-system.md).

import type { CallRecord } from "../runtime/store";

const duration = (seconds: number) => {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = String(seconds % 60).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${s}` : `${m}:${s}`;
};

/** Disappearing-message timers offered, in seconds. */
export const TIMERS = [0, 300, 3600, 28_800, 86_400, 604_800, 2_419_200];

const timerLabel = (seconds: number): string =>
  ({
    0: "Off",
    300: "5 minutes",
    3600: "1 hour",
    28800: "8 hours",
    86400: "1 day",
    604800: "1 week",
    2419200: "4 weeks",
  })[seconds] ?? `${Math.round(seconds / 60)} minutes`;

export const strings = {
  appName: "krypt",
  tagline: "Private messaging. No phone number.",
  loading: "Starting…",
  otherTab: "krypt is open in another tab",
  otherTabHint: "One device runs in one tab at a time. Close the other tab and this one takes over.",
  fatal: "krypt stopped to protect your keys",
  fatalHint: "This browser's storage failed. Reload to try again; nothing is lost.",
  reload: "Reload",
  updateReady: "A new version of krypt is ready. Tap to reload.",

  identityReady: "Identity ready",
  identityHint:
    "This device made a new identity just now. There is no account, no phone number and no email. Others recognise you by this fingerprint:",
  continue: "Continue",
  skip: "Skip",

  presence: {
    typing: "typing…",
    typingIn: (names: string[]) =>
      names.length === 1
        ? `${names[0]} is typing…`
        : names.length === 2
          ? `${names[0]} and ${names[1]} are typing…`
          : `${names.length} people are typing…`,
    online: "online",
    onlineCount: (n: number) => `${n} online`,
    typingSetting: "Typing indicators",
    typingHint: "People you're connected with see when you're typing, and you see when they are.",
    onlineSetting: "Show when I'm online",
    onlineHint:
      "People you're connected with see when krypt is open on your screen, and you see when they are. Message requests never do. Turning either off also hides it from you.",
  },

  tour: {
    pages: [
      {
        title: "Welcome to krypt",
        body: "Private messages and calls, with no phone number, no email and no account. Everything is encrypted on your device before it leaves.",
      },
      {
        title: "Connect with your card",
        body: "Your card is how people reach you. Show its QR code or send its link, and they can message you. Anyone else waits as a request until you accept.",
      },
      {
        title: "Check it's really them",
        body: "In a chat's info, compare safety numbers with them, in person or on a call. If they match, nobody is listening in.",
      },
      {
        title: "Only your devices hold the keys",
        body: "Back up with a passkey so a new phone can restore you, link your other devices, and burn everything with one long press if you ever need to.",
      },
    ],
    next: "Next",
    progress: "How krypt works",
    page: (n: number, of: number) => `Page ${n} of ${of}`,
    done: "That's krypt",
    doneHint: "You can read this again any time in Settings.",
    close: "Done",
  },

  chats: "Chats",
  noChats: "No conversations yet",
  noChatsHint: "Share your card, or paste someone else's to start.",
  newChat: "New chat",
  myCard: "My card",
  settings: "Settings",
  back: "Back",

  cardTitle: "Your card",
  cardQr: "QR code of your card. Scanning it opens krypt with your card filled in.",
  scan: "Scan a QR code",
  noCamera: "The camera isn't available. Paste their card instead.",
  cardHint:
    "Anyone with this card can start a chat with you. Let them scan the code, or share the link: it holds no secrets.",
  copy: "Copy",
  copied: "Copied",
  shareLink: "Share link",

  startTitle: "Start a chat",
  cardLabel: "Their card or @handle",
  cardPlaceholder: "krypt:… or @name",
  nameLabel: "Name (only you see it)",
  namePlaceholder: "Optional",
  start: "Start chat",
  notACard: "That is not a krypt card.",
  ownCard: "That is your own card.",

  message: "Message",
  send: "Send",
  queued: "Sending…",
  sent: "Sent",

  mute: {
    title: "Notifications",
    on: "On",
    hour: "1 hour",
    eight: "8 hours",
    week: "1 week",
    always: "Off",
    until: (at: number) => `Muted until ${new Date(at).toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" })}`,
    forever: "Muted",
    hint: "A muted chat still updates while krypt is open; it just doesn't wake your device.",
  },

  archive: {
    archive: "Archive chat",
    unarchive: "Unarchive chat",
    archived: (n: number) => `Archived (${n})`,
    title: "Archived",
    hint: "Archived chats come back when someone writes, unless they're muted.",
  },

  search: {
    open: "Search",
    placeholder: "Search chats and messages",
    close: "Close search",
    chats: "Chats",
    messages: "Messages",
    none: "Nothing found.",
    tooShort: "Type a little more to search.",
  },

  messages: {
    actions: "Message actions",
    more: "More",
    reply: "Reply",
    copy: "Copy",
    copied: "Copied",
    edit: "Edit",
    deleteForMe: "Delete for me",
    deleteForEveryone: "Delete for everyone",
    deleted: "This message was deleted",
    edited: "edited",
    replyingTo: (name: string) => `Replying to ${name}`,
    editing: "Editing your message",
    cancel: "Cancel",
    originalGone: "Original message not found",
    read: "Read",
    readBy: (n: number) => `Read by ${n}`,
    reaction: (emoji: string, names: string) => `${emoji} ${names}`,
    receipts: "Read receipts",
    receiptsHint:
      "In one-to-one chats and groups of up to eight, people see when you've read their messages, and you see when they've read yours. Turning it off does both.",
  },

  voice: {
    record: "Record a voice message",
    recording: "Recording",
    send: "Send voice message",
    cancel: "Cancel recording",
    play: "Play voice message",
    pause: "Pause",
    speed: (x: number) => `${x}×`,
    preview: "Voice message",
    micDenied: "krypt can't use the microphone. Allow it in your browser's settings.",
    failed: "That voice message couldn't be sent.",
  },
  encrypted: "End-to-end encrypted",
  waiting: "Waiting for them to join…",
  inactive: "You are no longer in this conversation.",

  info: "Conversation",
  members: "Members",
  you: "You",
  verified: "Verified",
  notVerified: "Not verified",
  verify: "Verify",
  rename: "Name",
  safetyNumber: "Safety number",
  safetyHint:
    "Compare these numbers with them in person or on a call. If they match, nobody is between you.",
  markVerified: "They match",
  unmarkVerified: "Mark as not verified",
  addPerson: "Add someone",
  add: "Add",

  appearance: "Appearance",
  theme: "Theme",
  mode: "Mode",
  modeSystem: "System",
  modeLight: "Light",
  modeDark: "Dark",
  accent: "Accent",
  haptics: "Haptics",
  notifications: "Notifications",
  notify: "Notify me when krypt is closed",
  notifyOn: "Notifications never contain your messages, only that something arrived.",
  notifyInstall: "On iPhone and iPad, add krypt to your Home Screen first: Share, then Add to Home Screen.",
  notifyDenied: "Notifications are blocked for krypt in this browser's settings.",
  notifyUnsupported: "This browser can't show notifications.",
  identity: "Identity",
  fingerprint: "Fingerprint",
  release: {
    signed: (release: string, commit: string) => `krypt ${release} · signed release · ${commit.slice(0, 7)}`,
    development: "Development build · not a signed release",
    checking: "Checking this release…",
    refused: (release?: string) =>
      release
        ? `krypt.chat served code that isn't a signed release. It wasn't used: this is still signed ${release}.`
        : "krypt.chat served code that isn't a signed release.",
  },
  burn: "Burn this identity",
  burnHint:
    "Destroys this identity and every message on this device. It cannot be undone. Hold to confirm.",
  burnHold: "Hold to burn",
  burnKeep: "Keep holding",

  files: {
    attach: "Attach a photo or file",
    preview: (mediaType: string) =>
      mediaType.startsWith("image/") ? "Photo" : mediaType.startsWith("video/") ? "Video" : "File",
    uploading: (percent: number) => `Uploading… ${percent}%`,
    preparing: "Preparing…",
    downloading: (percent: number) => `Downloading… ${percent}%`,
    download: "Download",
    save: "Save",
    open: "View",
    close: "Close",
    retry: "Try again",
    sendFailed: "Couldn't send this file.",
    failed: "Couldn't download this file.",
    damaged: "This file was damaged on the way and can't be opened.",
    expired: "No longer available. Files are kept for 30 days.",
    tooLarge: "Files can be up to 100 MB.",
    notScrubbed:
      "krypt couldn't remove the location and camera details from this, so it wasn't sent.",
    stripped: "Location and camera details are removed from photos and videos before they're sent.",
    size: (bytes: number) =>
      bytes < 1024
        ? `${bytes} B`
        : bytes < 1024 * 1024
          ? `${(bytes / 1024).toFixed(0)} KB`
          : `${(bytes / 1024 / 1024).toFixed(1)} MB`,
  },

  calls: {
    title: "Calls",
    voice: "Voice call",
    video: "Video call",
    incomingVoice: "Incoming voice call",
    incomingVideo: "Incoming video call",
    groupRings: (name: string, video: boolean) => `${name} started a group ${video ? "video" : "voice"} call`,
    people: (n: number) => (n === 1 ? "1 other person" : `${n} other people`),
    join: "Join",
    joinCall: (video: boolean) => `Join the ${video ? "video" : "voice"} call`,
    full: "This call is full: a group call holds up to 8 devices.",
    waitingForOthers: "Waiting for others to join…",
    calling: "Calling…",
    connecting: "Connecting…",
    reconnecting: "Reconnecting…",
    accept: "Accept",
    decline: "Decline",
    hangup: "End call",
    mute: "Mute",
    unmute: "Unmute",
    cameraOn: "Turn camera on",
    cameraOff: "Turn camera off",
    flip: "Switch camera",
    encrypted: "End-to-end encrypted",
    path: (path: "direct" | "relayed" | undefined, rttMs: number | undefined) =>
      [path === "relayed" ? "Relayed" : path === "direct" ? "Direct" : undefined, rttMs === undefined ? undefined : `${rttMs} ms`]
        .filter(Boolean)
        .join(" · "),
    duration,
    ended: {
      completed: "Call ended",
      missed: "Missed call",
      declined: "Declined",
      busy: "They're on another call",
      unanswered: "No answer",
      failed: "Couldn't connect",
      elsewhere: "Answered on another device",
    } satisfies Record<CallRecord["outcome"], string>,
    notify: (name: string) => `${name} is calling`,
    groupsLater: "Calls work in one-to-one conversations for now.",
    noMedia: "krypt couldn't use your microphone or camera.",
    noRelay: "Calls are set to always use the relay, and it couldn't be reached, so the call didn't start. Try again, or turn relaying off in Settings.",
    relay: "Always relay calls",
    relayHint:
      "Calls normally connect directly, so the other person's device learns your IP address. Relaying through Cloudflare hides it; calls may be a little slower.",
    record: (call: CallRecord) => {
      const kind = `${call.group ? "Group " : ""}${call.video ? "video call" : "voice call"}`.replace(/^./, (c) => c.toUpperCase());
      switch (call.outcome) {
        case "completed":
          return `${kind} · ${duration(call.seconds)}`;
        case "missed":
          return `Missed ${kind.toLowerCase()}`;
        case "declined":
          return call.direction === "in" ? `Declined ${kind.toLowerCase()}` : `${kind} declined`;
        case "busy":
          return `${kind}: they were busy`;
        case "unanswered":
          return `${kind}: no answer`;
        case "failed":
          return `${kind}: couldn't connect`;
        case "elsewhere":
          return `${kind}, answered on another device`;
      }
    },
  },

  settingsMenu: {
    account: "Account and backup",
    privacy: "Privacy and safety",
    titles: {
      account: "Account and backup",
      devices: "Devices",
      privacy: "Privacy and safety",
      notifications: "Notifications",
      appearance: "Appearance",
      guide: "How krypt works",
      burn: "Burn this identity",
    },
    noHandle: "No backup yet: losing this device loses your identity",
    handleOnly: (name: string) => `@${name} · not backed up`,
    handleBackedUp: (name: string) => `@${name} · backed up`,
    noPasskeys: "This browser can't use passkeys",
    oneDevice: "Only this device",
    devices: (n: number) => `${n} devices`,
    privacySummary: (relay: boolean, blocked: number) =>
      `${relay ? "Calls relayed" : "Calls direct"} · ${blocked === 0 ? "nobody blocked" : `${blocked} blocked`}`,
    push: {
      on: "On",
      off: "Off",
      install: "Add krypt to your Home Screen first",
      denied: "Blocked in this browser",
      unsupported: "Not available in this browser",
    },
    burnNoBackup: "You have no backup: nothing can bring this identity back.",
  },

  devices: {
    title: "Devices",
    hint: "Every device linked here is you: it joins all your chats and sends as you.",
    thisOne: "This device",
    device: "Device",
    unlink: "Unlink",
    linkNew: "Link a new device",
    linkNewHint: "On the new device, choose \u201cLink to my other device\u201d, then scan the code it shows, or paste it here.",
    linkWarning: "Only link devices you own: a linked device holds your identity.",
    link: "Link",
    sending: "Sealing your identity for the new device…",
    linked: "Linked. It is joining your chats.",
    failed: "That didn't work. Make a new code on the new device and try again.",
    linkThis: "Link to my other device",
    linkThisHint: "On a device that already has your krypt, open Settings, Devices, Link a new device, and scan this code.",
    codeLabel: "Link code",
    preparing: "Making a code…",
    waiting: "Waiting for your other device…",
    codeUsed: "That code was used already, or has expired. Make a new code on the new device.",
    codeOld: "That code is from an older krypt. Update krypt on both devices, then make a new code.",
    linking: "Received. Setting this device up…",
    yourFingerprint: "This device's fingerprint. The new device shows the fingerprint it is joining: check they match.",
    check: "Your other device sent this fingerprint. Check it shows the same one (Settings, Devices) before going on.",
    matches: "It matches",
    differs: "It doesn't match",
    refused: "Not linked. Someone else may have seen the code. Make a new one, and show it to nobody else.",
  },

  passkeys: {
    title: "Handle and backup",
    hint: "Claim an @handle so people can find you without your card. A passkey protects it, and keeps an encrypted backup of your identity and contacts that only it can open.",
    handle: "Handle",
    claim: "Claim with a passkey",
    taken: "That handle is taken.",
    claimFailed: "Couldn't claim that handle. Try another.",
    failed: "The passkey didn't work, or was cancelled.",
    backedUp: (when: string) => `Backed up ${when}`,
    notBackedUp: "Not backed up yet",
    noPrf: "This passkey can't encrypt backups; the handle still works.",
    backupNow: "Back up now",
    backupFailed: "Couldn't back up just now.",
    release: "Give up handle",
    restore: "Restore from a passkey",
    restoreHint: "Restores your identity and contacts from the backup kept with your handle. Old chats can't be restored; your contacts will know it's you.",
    restoreButton: "Restore",
    restoring: "Restoring…",
    noBackup: "There's no backup for that handle.",
    lookingUp: "Looking up…",
    notFound: "Nobody has that handle.",
  },

  requests: {
    title: "Message requests",
    count: (n: number) => (n === 1 ? "1 request" : `${n} requests`),
    hint: (name: string) =>
      `${name} isn't someone you know on krypt yet. They can't call you, and they'll only know you saw this if you reply.`,
    accept: "Accept",
    block: "Block",
    delete: "Delete",
  },

  groups: {
    newGroup: "New group",
    newChat: "New chat",
    name: "Group name",
    namePlaceholder: "Optional",
    people: "People",
    noPeople: "Groups are made from people you're already connected with. Start a chat with someone first, and they'll appear here.",
    create: (n: number) => (n === 0 ? "Create group" : n === 1 ? "Create group with 1 person" : `Create group with ${n} people`),
    rename: "Group name",
    leave: "Leave group",
    leaveHint: "The others are told you left, and your copy of this chat is deleted from this device.",
    leaveConfirm: "Leave",
  },

  safety: {
    title: "Safety",
    block: (name: string) => `Block ${name}`,
    blockHint: "They won't be able to message you, call you or add you to groups. They aren't told.",
    unblock: "Unblock",
    blocked: "Blocked",
    noBlocked: "You haven't blocked anyone.",
    report: (name: string) => `Report ${name}`,
    reportHint: (name: string) =>
      `krypt receives the last messages ${name} sent you here, and nothing else from your device. ${name} is blocked too.`,
    reportReasons: [
      ["spam", "Spam"],
      ["abuse", "Harassment or abuse"],
      ["illegal", "Illegal content"],
      ["other", "Something else"],
    ] as [string, string][],
    reportSend: "Report and block",
    reported: "Reported. They're blocked.",
    reportFailed: "They're blocked, but the report couldn't be sent. Try again later.",
    delete: "Delete conversation",
    deleteHint: "Removes it and everything in it from this device. Nobody is told.",
    deleteConfirm: "Delete",
    cancel: "Cancel",
  },

  timer: {
    title: "Disappearing messages",
    hint: "New messages disappear from every device this long after they're seen. Anyone in the conversation can change it.",
    label: timerLabel,
    short: (seconds: number) =>
      ({ 300: "5m", 3600: "1h", 28800: "8h", 86400: "1d", 604800: "1w", 2419200: "4w" })[seconds] ?? "",
  },

  system: {
    call: (call: CallRecord) => strings.calls.record(call),
    timer: (name: string, seconds: number) =>
      seconds === 0
        ? `${name} turned off disappearing messages.`
        : `${name} set messages to disappear ${timerLabel(seconds).toLowerCase()} after they're seen.`,
    timerRefused: () => "Disappearing messages need everyone here on the latest krypt.",
    renamed: (name: string, group: string) => (group ? `${name} named the group “${group}”.` : `${name} removed the group's name.`),
    started: () => "You started this conversation.",
    joined: () => "You joined.",
    membersAdded: (names: string) => `${names} joined.`,
    membersRemoved: (names: string) => `${names} left.`,
    membersRemovedBy: (by: string, names: string) => `${by} removed ${names}.`,
    removed: () => "You were removed from this conversation.",
    inviteFailed: (names: string) => `Couldn't add ${names}: their card didn't match their keys.`,
    undecryptable: () => "A message couldn't be decrypted.",
    desync: () => "This conversation fell out of sync on this device.",
    rulesBroken: () => "Someone changed this group against its rules, so it can't continue. Start a new group to carry on.",
    refused: () => "Only admins can do that in this group.",
    rules: (by: string, added: string, removed: string, add?: string, edit?: string, link?: string) =>
      [
        link === "on" && `${by} turned on the invite link.`,
        link === "reset" && `${by} reset the invite link.`,
        link === "off" && `${by} turned off the invite link.`,
        added && `${by} made ${added} ${added.includes(",") ? "admins" : "an admin"}.`,
        removed && `${by} took ${removed} off the admins.`,
        add && (add === "admins" ? `${by}: only admins can add people now.` : `${by}: everyone can add people now.`),
        edit &&
          (edit === "admins"
            ? `${by}: only admins can change the group's name and timer now.`
            : `${by}: everyone can change the group's name and timer now.`),
      ]
        .filter(Boolean)
        .join(" "),
  },

  invite: {
    title: "Invite link",
    turnOn: "Turn on invite link",
    turnOff: "Turn off",
    reset: "Reset link",
    copy: "Copy link",
    copied: "Copied",
    hint: "Anyone with this link can ask to join. An admin lets each person in.",
    resetHint: "Resetting makes the old link stop working. krypt resets it for you when an admin removes someone, since members can see who asks.",
    asks: "Want to join",
    approve: "Let in",
    decline: "Decline",
    joinTitle: "Join a group",
    ask: (group: string) => (group ? `Ask to join “${group}”?` : "Ask to join this group?"),
    askHint: "An admin of the group sees your name and your krypt fingerprint, and lets you in.",
    yourName: "Your name, as they'll see it",
    send: "Ask to join",
    sending: "Asking…",
    sent: "Asked. You'll be in the group once an admin lets you in.",
    broken: "This invite link doesn't work any more. Ask for a new one.",
    loading: "Opening the link…",
    waiting: (group: string) => (group ? `Waiting for an admin of “${group}”` : "Waiting for an admin to let you in"),
  },

  admins: {
    admin: "Admin",
    manage: (name: string) => `Manage ${name}`,
    makeAdmin: "Make admin",
    removeAdmin: "Remove as admin",
    remove: "Remove from group",
    addTitle: "Who can add people",
    editTitle: "Who can change the name and timer",
    everyone: "Everyone",
    onlyAdmins: "Only admins",
    adminsOnly: "Only admins can change this.",
    addFromContacts: "Add someone you're connected with",
    noOneToAdd: "Everyone you're connected with is already here.",
  },
};
