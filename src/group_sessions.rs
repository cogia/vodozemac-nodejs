use napi::bindgen_prelude::*;
use napi_derive::napi;

use super::{SessionConfig};

use vodozemac::megolm::{ExportedSessionKey, MegolmMessage, SessionKey};

#[napi]
pub struct GroupSession {
    pub(super) inner: vodozemac::megolm::GroupSession,
}

#[napi]
impl GroupSession {
    #[napi(constructor)]
    pub fn new(config: &SessionConfig) -> Self {
        let _config = if config.version() == 2 { vodozemac::megolm::SessionConfig::version_2() } else { vodozemac::megolm::SessionConfig::version_1() };

        Self {
            inner: vodozemac::megolm::GroupSession::new(_config),
        }
    }

    #[napi(getter)]
    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }

    #[napi(getter)]
    pub fn session_key(&self) -> String {
        self.inner.session_key().to_base64()
    }

    #[napi(getter)]
    pub fn message_index(&self) -> u32 {
        self.inner.message_index()
    }

    #[napi]
    pub fn encrypt(&mut self, plaintext: String) -> String {
        self.inner.encrypt(&plaintext).to_base64()
    }
    #[napi]
    pub fn pickle(&self, pickle_key: &[u8]) -> Result<String> {
        let pickle_key: &[u8; 32] = pickle_key
            .try_into()
            .map_err(|_| Error::new(Status::GenericFailure, "Invalid pickle key length, expected 32 bytes"))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }
    #[napi]
    pub fn from_pickle(pickle: String, pickle_key: &[u8]) -> Result<GroupSession> {
        let pickle_key: &[u8; 32] = pickle_key
            .try_into()
            .map_err(|_| Error::new(Status::GenericFailure, "Invalid pickle key length, expected 32 bytes"))?;
        let pickle = vodozemac::megolm::GroupSessionPickle::from_encrypted(&pickle, pickle_key)
            .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        let session = vodozemac::megolm::GroupSession::from_pickle(pickle);

        Ok(Self { inner: session })
    }
}

#[napi]
pub struct DecryptedMessage {
    pub plaintext: String,
    pub message_index: u32,
}

#[napi]
pub struct InboundGroupSession {
    pub(super) inner: vodozemac::megolm::InboundGroupSession,
}

#[napi]
impl InboundGroupSession {
    #[napi(constructor)]
    pub fn new(session_key: String, session_config: &SessionConfig) -> Result<InboundGroupSession> {
        let key = SessionKey::from_base64(&session_key).map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;
        let config = if session_config.version() == 2 { vodozemac::megolm::SessionConfig::version_2() } else { vodozemac::megolm::SessionConfig::version_1() };
        Ok(Self {
            inner: vodozemac::megolm::InboundGroupSession::new(&key, config),
        })
    }
    #[napi]
    pub fn import(session_key: String, session_config: &SessionConfig) -> Result<InboundGroupSession> {

        let config = if session_config.version() == 2 { vodozemac::megolm::SessionConfig::version_2() } else { vodozemac::megolm::SessionConfig::version_1() };

        let key = ExportedSessionKey::from_base64(&session_key).map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        Ok(Self {
            inner: vodozemac::megolm::InboundGroupSession::import(&key, config),
        })
    }

    #[napi(getter)]
    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }

    #[napi(getter)]
    pub fn first_known_index(&self) -> u32 {
        self.inner.first_known_index()
    }

    #[napi]
    pub fn export_at(&mut self, index: u32) -> Option<String> {
        self.inner.export_at(index).map(|k| k.to_base64())
    }
    #[napi]
    pub fn decrypt(&mut self, ciphertext: String) -> Result<DecryptedMessage> {
        let message = MegolmMessage::from_base64(&ciphertext).map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;
        let ret = self.inner.decrypt(&message).map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        Ok(DecryptedMessage {
            plaintext: String::from_utf8(ret.plaintext).unwrap(),
            message_index: ret.message_index,
        })
    }
    #[napi]
    pub fn pickle(&self, pickle_key: &[u8]) -> Result<String> {
        let pickle_key: &[u8; 32] = pickle_key
            .try_into()
            .map_err(|_| Error::new(Status::GenericFailure, "Invalid pickle key length, expected 32 bytes"))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }
    #[napi]
    pub fn from_pickle(pickle: String, pickle_key: &[u8]) -> Result<InboundGroupSession> {
        let pickle_key: &[u8; 32] = pickle_key
            .try_into()
            .map_err(|_| Error::new(Status::GenericFailure, "Invalid pickle key length, expected 32 bytes"))?;
        let pickle =
            vodozemac::megolm::InboundGroupSessionPickle::from_encrypted(&pickle, pickle_key)
                .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        let session = vodozemac::megolm::InboundGroupSession::from_pickle(pickle);

        Ok(Self { inner: session })
    }
    #[napi]
    pub fn from_libolm_pickle(
        pickle: String,
        pickle_key: &[u8],
    ) -> Result<InboundGroupSession> {
        let inner = vodozemac::megolm::InboundGroupSession::from_libolm_pickle(&pickle, pickle_key)
            .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        Ok(Self { inner })
    }
}
