#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;

mod account;
mod session;

pub use account::Account;
pub use session::Session;

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