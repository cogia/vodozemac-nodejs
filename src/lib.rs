#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;

mod account;
mod session;
mod sas;
mod group_sessions;

pub use account::Account;
pub use session::Session;
pub use sas::{EstablishedSas, Sas, SasBytes};

#[napi]
pub struct SessionConfig {
     _version: u8,
}

#[napi]
impl SessionConfig {
    /// Get the numeric version of this `SessionConfig`.
    #[napi]
    pub const fn version(&self) -> u8 {
        self._version
    }

    /// Create a `SessionConfig` for the Olm version 1. This version of Olm will
    /// use AES-256 and HMAC with a truncated MAC to encrypt individual
    /// messages. The MAC will be truncated to 8 bytes.
    #[napi]
    pub const fn version_1() -> Self {
        SessionConfig { _version: 1 }
    }

    /// Create a `SessionConfig` for the Olm version 2. This version of Olm will
    /// use AES-256 and HMAC to encrypt individual messages. The MAC won't be
    /// truncated.
    #[napi]
    pub const fn version_2() -> Self {
        SessionConfig { _version: 2 }
    }
}

#[napi]
pub struct OlmMessage {
    pub ciphertext: String,
    pub message_type: u32,
}

#[napi]
impl OlmMessage {
    #[napi(constructor)]
    pub fn new(message_type: u32, ciphertext: String) -> Self {
        Self {
            ciphertext,
            message_type,
        }
    }
}