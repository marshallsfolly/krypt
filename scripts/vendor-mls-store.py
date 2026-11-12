#!/usr/bin/env python3
"""Regenerate crates/krypt-core/src/mls_store.rs from openmls_memory_storage.

The upstream MemoryStorage (MIT) is copied with these changes:
  * HashMap -> `Tracked`, a BTreeMap that records which keys changed, so each
    state-machine step can hand back exactly its writes as one atomic batch;
  * test-utils, persistence, logging and draft-feature items are removed;
  * the `entry()` calls in the list helpers are rewritten as get/insert;
  * values are written as postcard behind a tag byte (`encode`), and read in
    either that or JSON, the encoding before it (`decode`). Keys stay JSON,
    so records written before keep their keys. The group join config stays
    JSON: its past-epoch policy deserializes untagged, which needs a
    self-describing format;
  * reading a value that does not decode is an error, never a panic.

Usage: scripts/vendor-mls-store.py <path to openmls_memory_storage-X.Y.Z>
"""
import pathlib
import re
import sys

src_dir = pathlib.Path(sys.argv[1])
version = src_dir.name.rsplit("-", 1)[1]
src = (src_dir / "src" / "lib.rs").read_text()
lines = src.splitlines()


def drop_gated_items(lines, features):
    """Remove each item preceded by #[cfg(feature = <one of features>)]."""
    out, i = [], 0
    pattern = re.compile(r'^\s*#\[cfg\((any\()?.*feature = "(%s)".*\)\]\s*$' % "|".join(features))
    while i < len(lines):
        if pattern.match(lines[i]):
            i += 1
            # Skip further attributes, then the item up to its end.
            while lines[i].lstrip().startswith("#["):
                i += 1
            depth, started = 0, False
            while i < len(lines):
                line = lines[i]
                depth += line.count("{") - line.count("}")
                started = started or "{" in line
                i += 1
                if (started and depth == 0) or (not started and line.rstrip().endswith(";")):
                    break
            continue
        out.append(lines[i])
        i += 1
    return out


lines = drop_gated_items(lines, ["test-utils", "persistence", "extensions-draft", "virtual-clients-draft"])
lines = [l for l in lines if "log::" not in l]
text = "\n".join(lines) + "\n"

text = text.replace(
    "use std::{collections::HashMap, sync::RwLock};",
    "use std::collections::{BTreeMap, BTreeSet};\nuse std::sync::RwLock;",
)
text = text.replace("pub struct MemoryStorage {\n    pub values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,\n}",
                    "pub struct MemoryStorage {\n    values: RwLock<Tracked>,\n}")
text = text.replace("MemoryStorageError", "MlsStoreError").replace("MemoryStorage", "MlsStore")

# The list helpers used HashMap::entry; express them with get/insert.
text = text.replace(
    """        let list_bytes = values.entry(storage_key).or_insert_with(|| b"[]".to_vec());

        // parse old value and push new data
        let mut list: Vec<Vec<u8>> = serde_json::from_slice(list_bytes)?;
        list.push(value);

        // write back, reusing the old buffer
        list_bytes.clear();
        serde_json::to_writer(list_bytes, &list)?;
""",
    """        let mut list: Vec<Vec<u8>> = match values.get(&storage_key) {
            Some(list_bytes) => serde_json::from_slice(list_bytes)?,
            None => Vec::new(),
        };
        list.push(value);
        values.insert(storage_key, serde_json::to_vec(&list)?);
""",
)
text = text.replace(
    """        let list_bytes = values.entry(storage_key).or_insert_with(|| b"[]".to_vec());

        // parse old value, find value to delete and remove it from list
        let mut list: Vec<Vec<u8>> = serde_json::from_slice(list_bytes)?;
        if let Some(pos) = list.iter().position(|stored_item| stored_item == &value) {
            list.remove(pos);
        }

        // write back, reusing the old buffer
        list_bytes.clear();
        serde_json::to_writer(list_bytes, &list)?;
""",
    """        let mut list: Vec<Vec<u8>> = match values.get(&storage_key) {
            Some(list_bytes) => serde_json::from_slice(list_bytes)?,
            None => Vec::new(),
        };
        if let Some(pos) = list.iter().position(|stored_item| stored_item == &value) {
            list.remove(pos);
        }
        values.insert(storage_key, serde_json::to_vec(&list)?);
""",
)
assert "entry(" not in text, "an entry() call survived; update the rewrite rules"
assert "HashMap" not in text


def replace(old, new, count=1):
    """Replaces exactly `count` occurrences, so upstream changes are noticed."""
    global text
    found = text.count(old)
    assert found == count, f"expected {count} of {old!r}, found {found}"
    text = text.replace(old, new)


# Values: postcard behind a tag byte.
text = re.sub(r"let value = serde_json::to_vec\(", "let value = encode(", text)
replace("serde_json::to_vec(&list)?", "encode(&list)?", count=2)
# The value argument of `self.write(label, &key, value)`: the line after the
# key, which starts with `&`.
text = re.sub(r"(?m)^(\s+)serde_json::to_vec\(([^\n]*)\)(\.unwrap\(\)|\?),$", r"\1encode(\2)?,", text)
text = re.sub(r"encode\(([^\n]*?)\)\.unwrap\(\)", r"encode(\1)?", text)
# Except the join config (see above).
replace(
    "let value = encode(config)?;",
    "// JSON: the past-epoch policy inside deserializes untagged.\n"
    "        let value = serde_json::to_vec(config)?;",
)

# Reads. The direct readers deserialized `Option<T>` from a `T`, which only
# a self-describing format allows.
replace(
    "let value = serde_json::from_slice(value).unwrap();\n\n        Ok(value)",
    "Ok(Some(decode(value)?))",
    count=5,
)
replace("return Ok(serde_json::from_slice(value).unwrap());", "return decode(value);")
replace("Some(list_bytes) => serde_json::from_slice(list_bytes).unwrap(),", "Some(list_bytes) => decode(list_bytes)?,")
replace("Some(list_bytes) => serde_json::from_slice(list_bytes)?,", "Some(list_bytes) => decode(list_bytes)?,", count=2)
replace(
    "            serde_json::from_slice(value)\n                .map_err(|_| MlsStoreError::SerializationError)\n                .map(|v| Some(v))",
    "            decode(value).map(Some)",
)
replace(".map(|value_bytes| serde_json::from_slice(value_bytes))", ".map(|value_bytes| decode(value_bytes))")
# A queued proposal missing from under its reference is damaged storage.
replace(
    "self.read(QUEUED_PROPOSAL_LABEL, &key)?.unwrap();",
    "self\n                    .read(QUEUED_PROPOSAL_LABEL, &key)?\n                    .ok_or(MlsStoreError::SerializationError)?;",
)
assert "serde_json::from_slice" not in text, "a read escaped the rewrite rules"
for line in text.splitlines():
    # Whatever still goes through serde_json is a key (or the join config).
    if "serde_json::to_vec" in line and "let value" in line:
        assert "config" in line, line

# remove_item finds a list item by its bytes, and items written before are
# JSON: the caller passes both encodings.
replace(
    """    fn remove_item<const VERSION: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    )""",
    """    fn remove_item<const VERSION: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
        json: Vec<u8>,
    )""",
)
replace(
    """        if let Some(pos) = list.iter().position(|stored_item| stored_item == &value) {""",
    """        if let Some(pos) = list
            .iter()
            .position(|stored_item| *stored_item == value || *stored_item == json)
        {""",
)
replace(
    "self.remove_item::<CURRENT_VERSION>(PROPOSAL_QUEUE_REFS_LABEL, &key, value)?;",
    "let json = serde_json::to_vec(proposal_ref)?;\n"
    "        self.remove_item::<CURRENT_VERSION>(PROPOSAL_QUEUE_REFS_LABEL, &key, value, json)?;",
)

header = f'''//! OpenMLS storage with change tracking.
//!
//! GENERATED by `scripts/vendor-mls-store.py` from openmls_memory_storage
//! {version} (Copyright (c) 2019 OpenMLS Authors, MIT License). Do not edit by
//! hand; change the script and regenerate.
//!
//! All OpenMLS state lives in one ordered in-memory map. Every key a step
//! writes or deletes is recorded, so the step can return exactly its changes
//! as a single batch that the driver persists atomically before acting.
//!
//! Values are postcard behind a tag byte ([`encode`]); OpenMLS rewrites its
//! whole ratchet tree on every commit, and JSON spells each byte as a number.
//! Values from before (JSON) are still read ([`decode`]), and keys stay JSON
//! so those records are found. Reading a damaged value is an error.
#![allow(clippy::unwrap_used, clippy::all)]

'''

tracked = '''
/// Tags a value as postcard. No JSON text starts with it, so a value without
/// it was written as JSON, as every value was before 2026-11-06.
const BINARY: u8 = 0x01;

/// A value as stored: [`BINARY`], then postcard. Postcard is compact (bytes
/// as bytes, integers as varints) and fixed by its 1.0 spec, but not
/// self-describing: it cannot read types that deserialize untagged.
fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, MlsStoreError> {
    postcard::to_extend(value, vec![BINARY]).map_err(|_| MlsStoreError::SerializationError)
}

/// Reads a value in either encoding. A value with bytes left over is as
/// damaged as one cut short.
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, MlsStoreError> {
    match bytes.split_first() {
        Some((&BINARY, rest)) => match postcard::take_from_bytes(rest) {
            Ok((value, [])) => Ok(value),
            _ => Err(MlsStoreError::SerializationError),
        },
        _ => serde_json::from_slice(bytes).map_err(|_| MlsStoreError::SerializationError),
    }
}

/// An ordered map that remembers which keys changed since the last
/// [`Tracked::take_changes`].
#[derive(Debug, Default)]
struct Tracked {
    map: BTreeMap<Vec<u8>, Vec<u8>>,
    dirty: BTreeSet<Vec<u8>>,
}

impl Tracked {
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Option<Vec<u8>> {
        self.dirty.insert(key.clone());
        self.map.insert(key, value)
    }

    fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let old = self.map.remove(key);
        if old.is_some() {
            self.dirty.insert(key.to_vec());
        }
        old
    }

    fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.map.get(key)
    }

    #[allow(dead_code)]
    fn iter(&self) -> std::collections::btree_map::Iter<'_, Vec<u8>, Vec<u8>> {
        self.map.iter()
    }

    fn take_changes(&mut self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        let dirty = std::mem::take(&mut self.dirty);
        dirty
            .into_iter()
            .map(|key| {
                let value = self.map.get(&key).cloned();
                (key, value)
            })
            .collect()
    }
}

impl MlsStore {
    /// Rebuilds a store from persisted key-value pairs.
    pub fn from_entries(entries: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>) -> Self {
        let map = entries.into_iter().collect();
        MlsStore { values: RwLock::new(Tracked { map, dirty: BTreeSet::new() }) }
    }

    /// Returns every key changed since the last call, with its new value or
    /// `None` if it was deleted.
    pub fn take_changes(&self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        self.values.write().unwrap().take_changes()
    }

    /// Writes an application record. Keys share the map with OpenMLS, whose
    /// labels are ASCII words, so application keys start with a zero byte.
    pub fn put_raw(&self, key: Vec<u8>, value: Vec<u8>) {
        debug_assert_eq!(key.first(), Some(&0));
        self.values.write().unwrap().insert(key, value);
    }

    pub fn delete_raw(&self, key: &[u8]) {
        debug_assert_eq!(key.first(), Some(&0));
        self.values.write().unwrap().remove(key);
    }

    pub fn get_raw(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.values.read().unwrap().get(key).cloned()
    }

    /// All records whose key starts with `prefix`, in key order.
    pub fn scan_raw(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let values = self.values.read().unwrap();
        values
            .map
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    /// Number of stored records, OpenMLS and application alike.
    pub fn len(&self) -> usize {
        self.values.read().unwrap().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
'''

text = header + text.rstrip() + "\n" + tracked
out = pathlib.Path(__file__).resolve().parent.parent / "crates/krypt-core/src/mls_store.rs"
out.write_text(text)
print(f"wrote {out} from openmls_memory_storage {version}")
