//! File encryption. A shared file gets its own random key, carried only
//! inside the MLS message that shares it, and is split into parts of
//! `FILE_PART_SIZE` plaintext bytes, each sealed with ChaCha20-Poly1305.
//!
//! Each part's nonce holds its index and whether it is the last, and the
//! associated data holds the file's size, so parts cannot be reordered,
//! dropped, repeated or cut short without failing to open. The key is used
//! for one file only, so the nonces never repeat under it.
//!
//! ChaCha20 rather than AES: phones without AES instructions, and the
//! browser (WebAssembly has none), run it several times faster.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use krypt_wire::limits::{FILE_PART_SIZE, FILE_PARTS_MAX, FILE_SIZE_MAX, FILE_TAG_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FileError {
    #[error("a part has the wrong length")]
    WrongLength,
    #[error("a part failed to decrypt: damaged, or not part of this file")]
    Corrupt,
}

/// How many parts a file of `size` bytes is stored in. An empty file is one
/// empty part, so every file has a last part.
pub fn parts(size: u64) -> u32 {
    assert!(size <= FILE_SIZE_MAX);
    let parts = size.div_ceil(u64::from(FILE_PART_SIZE)).max(1);
    let parts = u32::try_from(parts).expect("FILE_SIZE_MAX bounds the part count");
    assert!(parts <= FILE_PARTS_MAX);
    parts
}

/// Plaintext bytes in part `part` of a file of `size` bytes.
pub fn plain_len(size: u64, part: u32) -> u32 {
    let count = parts(size);
    assert!(part < count);
    if part + 1 < count {
        return FILE_PART_SIZE;
    }
    let before = u64::from(part) * u64::from(FILE_PART_SIZE);
    u32::try_from(size - before).expect("a part is at most FILE_PART_SIZE")
}

/// Bytes stored for part `part`: its plaintext and the tag.
pub fn stored_len(size: u64, part: u32) -> u32 {
    plain_len(size, part) + FILE_TAG_SIZE
}

fn nonce(part: u32, last: bool) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&part.to_be_bytes());
    nonce[4] = u8::from(last);
    Nonce::from(nonce)
}

fn associated(size: u64) -> [u8; 21] {
    let mut data = [0u8; 21];
    data[..13].copy_from_slice(b"krypt file v1");
    data[13..].copy_from_slice(&size.to_le_bytes());
    data
}

/// Encrypts part `part` of a file of `size` bytes in place: `buffer` holds
/// its plaintext and gets the tag appended.
pub fn seal(key: &[u8; 32], size: u64, part: u32, buffer: &mut Vec<u8>) {
    let last = part + 1 == parts(size);
    assert_eq!(buffer.len(), plain_len(size, part) as usize);
    let tag = ChaCha20Poly1305::new(key.into())
        .encrypt_in_place_detached(&nonce(part, last), &associated(size), buffer)
        .expect("a part is far below ChaCha20's length limit");
    buffer.extend_from_slice(&tag);
    assert_eq!(buffer.len(), stored_len(size, part) as usize);
}

/// Decrypts part `part` of a file of `size` bytes in place: `buffer` holds
/// what was stored and is left holding the plaintext. On failure `buffer`
/// holds nothing usable.
pub fn open(key: &[u8; 32], size: u64, part: u32, buffer: &mut Vec<u8>) -> Result<(), FileError> {
    if size > FILE_SIZE_MAX || part >= parts(size) {
        return Err(FileError::WrongLength);
    }
    if buffer.len() != stored_len(size, part) as usize {
        return Err(FileError::WrongLength);
    }
    let last = part + 1 == parts(size);
    let at = buffer.len() - FILE_TAG_SIZE as usize;
    let tag = Tag::clone_from_slice(&buffer[at..]);
    buffer.truncate(at);
    ChaCha20Poly1305::new(key.into())
        .decrypt_in_place_detached(&nonce(part, last), &associated(size), buffer, &tag)
        .map_err(|_| {
            buffer.clear();
            FileError::Corrupt
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(key: &[u8; 32], plaintext: &[u8]) -> Vec<Vec<u8>> {
        let size = plaintext.len() as u64;
        (0..parts(size))
            .map(|part| {
                let start = part as usize * FILE_PART_SIZE as usize;
                let end = start + plain_len(size, part) as usize;
                let mut buffer = plaintext[start..end].to_vec();
                seal(key, size, part, &mut buffer);
                buffer
            })
            .collect()
    }

    #[test]
    fn part_layout() {
        let part = u64::from(FILE_PART_SIZE);
        assert_eq!(parts(0), 1);
        assert_eq!(plain_len(0, 0), 0);
        assert_eq!(parts(1), 1);
        assert_eq!(parts(part), 1);
        assert_eq!(parts(part + 1), 2);
        assert_eq!(plain_len(part + 1, 0), FILE_PART_SIZE);
        assert_eq!(plain_len(part + 1, 1), 1);
        assert_eq!(parts(FILE_SIZE_MAX), FILE_PARTS_MAX);
        assert_eq!(stored_len(5, 0), 5 + FILE_TAG_SIZE);
    }

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let size = u64::from(FILE_PART_SIZE) * 2 + 3;
        #[allow(clippy::cast_possible_truncation)]
        let plaintext: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
        let stored = sealed(&key, &plaintext);
        assert_eq!(stored.len(), 3);
        let mut out = Vec::new();
        for (part, bytes) in stored.into_iter().enumerate() {
            let mut buffer = bytes;
            let part = u32::try_from(part).unwrap();
            open(&key, size, part, &mut buffer).unwrap();
            out.extend_from_slice(&buffer);
        }
        assert_eq!(out, plaintext);
    }

    #[test]
    fn parts_cannot_be_moved_cut_or_swapped() {
        let key = [9u8; 32];
        let size = u64::from(FILE_PART_SIZE) + 10;
        let plaintext = vec![1u8; usize::try_from(size).unwrap()];
        let stored = sealed(&key, &plaintext);

        // Wrong key.
        let mut buffer = stored[1].clone();
        assert_eq!(
            open(&[8; 32], size, 1, &mut buffer),
            Err(FileError::Corrupt)
        );
        assert!(buffer.is_empty());
        // A flipped bit.
        let mut buffer = stored[1].clone();
        buffer[3] ^= 1;
        assert_eq!(open(&key, size, 1, &mut buffer), Err(FileError::Corrupt));
        // The first part presented as a whole file: its size, then its
        // position, do not match.
        let mut buffer = stored[0].clone();
        assert_eq!(
            open(&key, u64::from(FILE_PART_SIZE), 0, &mut buffer),
            Err(FileError::Corrupt)
        );
        // The last part at another index, or claiming another size.
        let mut buffer = stored[1].clone();
        assert_eq!(
            open(&key, size, 0, &mut buffer),
            Err(FileError::WrongLength)
        );
        let mut buffer = stored[1].clone();
        assert_eq!(
            open(&key, size, 2, &mut buffer),
            Err(FileError::WrongLength)
        );
        let mut buffer = stored[1].clone();
        buffer.push(0);
        assert_eq!(
            open(&key, size + 1, 1, &mut buffer),
            Err(FileError::Corrupt)
        );
        // Hostile sizes are refused, not asserted on.
        let mut buffer = stored[1].clone();
        assert_eq!(
            open(&key, FILE_SIZE_MAX + 1, 0, &mut buffer),
            Err(FileError::WrongLength)
        );
    }
}
