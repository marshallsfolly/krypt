//! Durable storage for a krypt device.
//!
//! The client hands back each step's writes as one batch, and must not act
//! on the step until the batch is durable. This store makes that contract
//! concrete: one SQLite table of key-value pairs, one transaction per batch,
//! WAL journaling with `synchronous = FULL`, so `apply` returning `Ok` means
//! the batch survives a crash or power loss, and a batch is either entirely
//! there after a crash or entirely absent.
//!
//! Several steps that happen close together can be committed with one fsync
//! through [`Store::apply_many`]; their effects are then released together.

use std::path::Path;

use rusqlite::{Connection, params};

#[derive(Debug, thiserror::Error)]
#[error("storage: {0}")]
pub struct Error(#[from] rusqlite::Error);

pub type Write = (Vec<u8>, Option<Vec<u8>>);
pub type Record = (Vec<u8>, Vec<u8>);

#[derive(Debug)]
pub struct Store {
    conn: Connection,
}

const SCHEMA: &str = "
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    CREATE TABLE IF NOT EXISTS kv (
        key   BLOB PRIMARY KEY NOT NULL,
        value BLOB NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY NOT NULL,
        value BLOB NOT NULL
    ) WITHOUT ROWID;
";

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Store, Error> {
        Store::init(Connection::open(path)?)
    }

    /// A store that lives only as long as this value; for tests.
    pub fn open_in_memory() -> Result<Store, Error> {
        Store::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Store, Error> {
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn })
    }

    /// Durably applies one step's writes, all or nothing.
    pub fn apply(&mut self, writes: &[Write]) -> Result<(), Error> {
        self.apply_many(std::iter::once(writes))
    }

    /// Durably applies several steps' writes in order, in one transaction.
    pub fn apply_many<'a>(
        &mut self,
        batches: impl IntoIterator<Item = &'a [Write]>,
    ) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        {
            let mut put =
                tx.prepare_cached("INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)")?;
            let mut delete = tx.prepare_cached("DELETE FROM kv WHERE key = ?1")?;
            for (key, value) in batches.into_iter().flatten() {
                match value {
                    Some(value) => put.execute(params![key, value])?,
                    None => delete.execute(params![key])?,
                };
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Everything stored, in key order: the input to `Client::restore`.
    pub fn load(&self) -> Result<Vec<Record>, Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM kv ORDER BY key")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// A driver-level setting (transport keys, server URLs), kept apart from
    /// the client's own records.
    pub fn meta(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT value FROM meta WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }

    pub fn set_meta(&mut self, key: &str, value: &[u8]) -> Result<(), Error> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Runs SQLite's full integrity check; at-rest corruption must be
    /// detected before state is trusted.
    pub fn check_integrity(&self) -> Result<bool, Error> {
        let result: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(result == "ok")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn puts_and_deletes_apply_in_order() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .apply(&[
                (b"a".to_vec(), Some(b"1".to_vec())),
                (b"b".to_vec(), Some(b"2".to_vec())),
            ])
            .unwrap();
        store
            .apply(&[(b"a".to_vec(), None), (b"b".to_vec(), Some(b"3".to_vec()))])
            .unwrap();
        assert_eq!(store.load().unwrap(), vec![(b"b".to_vec(), b"3".to_vec())]);
        assert!(store.check_integrity().unwrap());
    }

    #[test]
    fn a_failed_batch_leaves_nothing_behind() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .apply(&[(b"keep".to_vec(), Some(b"1".to_vec()))])
            .unwrap();
        // A trigger makes the second write of the batch fail.
        store.conn.execute_batch("CREATE TRIGGER no_poison BEFORE INSERT ON kv WHEN NEW.key = x'00' BEGIN SELECT RAISE(ABORT, 'poison'); END;").unwrap();
        let batch = [
            (b"new".to_vec(), Some(b"2".to_vec())),
            (vec![0], Some(b"x".to_vec())),
        ];
        assert!(store.apply(&batch).is_err());
        assert_eq!(
            store.load().unwrap(),
            vec![(b"keep".to_vec(), b"1".to_vec())]
        );
    }

    #[test]
    fn meta_is_separate_from_client_records() {
        let mut store = Store::open_in_memory().unwrap();
        assert_eq!(store.meta("k").unwrap(), None);
        store.set_meta("k", b"v").unwrap();
        assert_eq!(store.meta("k").unwrap(), Some(b"v".to_vec()));
        assert!(store.load().unwrap().is_empty());
    }

    #[test]
    fn survives_reopening() {
        let dir = std::env::temp_dir().join(format!("krypt-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("device.db");
        {
            let mut store = Store::open(&path).unwrap();
            store
                .apply(&[(b"k".to_vec(), Some(b"v".to_vec()))])
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.load().unwrap(), vec![(b"k".to_vec(), b"v".to_vec())]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
