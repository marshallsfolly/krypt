//! The OpenMLS provider: RustCrypto primitives, change-tracked storage, and a
//! randomness source that is the operating system in production and a seeded
//! ChaCha20 stream in simulation.
//!
//! Simulation caveat: OpenMLS's HPKE and signature key generation draw from
//! their own OS-seeded generators, so MLS ciphertext bytes differ between runs
//! of the same seed. krypt-core never branches on ciphertext byte values, so
//! control flow (and therefore every simulator decision) still replays exactly.

use std::sync::Mutex;

use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::random::OpenMlsRand;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use crate::mls_store::MlsStore;

#[derive(Debug)]
pub enum Rand {
    Os(RustCrypto),
    Seeded(Mutex<ChaCha20Rng>),
}

#[derive(Debug, thiserror::Error)]
#[error("randomness source failed")]
pub struct RandError;

impl Rand {
    pub fn os() -> Rand {
        Rand::Os(RustCrypto::default())
    }

    pub fn seeded(seed: u64) -> Rand {
        Rand::Seeded(Mutex::new(ChaCha20Rng::seed_from_u64(seed)))
    }

    /// Random bytes for krypt's own use (keys, identifiers). Running out of
    /// entropy is not a recoverable condition.
    pub fn bytes<const N: usize>(&self) -> [u8; N] {
        self.random_array().expect("randomness source failed")
    }
}

impl OpenMlsRand for Rand {
    type Error = RandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        match self {
            Rand::Os(crypto) => crypto.random_array().map_err(|_| RandError),
            Rand::Seeded(rng) => {
                let mut out = [0u8; N];
                rng.lock().map_err(|_| RandError)?.fill_bytes(&mut out);
                Ok(out)
            }
        }
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        match self {
            Rand::Os(crypto) => crypto.random_vec(len).map_err(|_| RandError),
            Rand::Seeded(rng) => {
                let mut out = vec![0u8; len];
                rng.lock().map_err(|_| RandError)?.fill_bytes(&mut out);
                Ok(out)
            }
        }
    }
}

#[derive(Debug)]
pub struct Provider {
    crypto: RustCrypto,
    rand: Rand,
    storage: MlsStore,
}

impl Provider {
    pub fn new(rand: Rand, storage: MlsStore) -> Provider {
        Provider {
            crypto: RustCrypto::default(),
            rand,
            storage,
        }
    }
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = Rand;
    type StorageProvider = MlsStore;

    fn storage(&self) -> &MlsStore {
        &self.storage
    }

    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }

    fn rand(&self) -> &Rand {
        &self.rand
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_rand_is_reproducible() {
        let a = Rand::seeded(7);
        let b = Rand::seeded(7);
        assert_eq!(a.bytes::<32>(), b.bytes::<32>());
        assert_eq!(a.random_vec(5).unwrap(), b.random_vec(5).unwrap());
        assert_ne!(Rand::seeded(8).bytes::<32>(), Rand::seeded(7).bytes::<32>());
    }
}
