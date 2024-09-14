use std::collections::HashMap;
use napi::bindgen_prelude::*;
use napi::JsObject;
use napi_derive::napi;
use vodozemac::olm::SessionConfig;


use super::{session::Session, OlmMessage, IdentityKeys};

#[napi]
pub struct Account {
    inner: vodozemac::olm::Account,
}
#[repr(C)]
#[napi]
pub struct InboundCreationResult {
    session: Session,
    plaintext: String,
}

/*
impl InboundCreationResult {

    pub fn session(&self) -> Session {
        self.session
    }


    pub fn plaintext(&self) -> String {
        self.plaintext.clone()
    }
}*/

impl From<vodozemac::olm::InboundCreationResult> for InboundCreationResult {
    fn from(result: vodozemac::olm::InboundCreationResult) -> Self {
        Self {
            session: Session {
                inner: result.session,
            },
            plaintext: String::from_utf8(result.plaintext).unwrap(),
        }
    }
}

#[napi]
impl Account {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: vodozemac::olm::Account::new(),
        }
    }
    #[napi]
    pub fn identity_keys(&self) -> Result<IdentityKeys> {
        let identity_keys = self.inner.identity_keys();//.map_err(|_| {});
        Ok(
            IdentityKeys {
                ed25519: identity_keys.ed25519.to_base64(),
                curve25519: identity_keys.curve25519.to_base64(),
            }
        )
    }

    #[napi]
    pub fn from_pickle(pickle: String, pickle_key: String) -> Result<Account> {
        let pickle_key: &[u8; 32] = pickle_key
            .as_bytes()
            .try_into()
            .map_err(|err: _| Error::new(Status::GenericFailure, err))?;

        let pickle = vodozemac::olm::AccountPickle::from_encrypted(&pickle, pickle_key)
            .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;


        let inner = vodozemac::olm::Account::from_pickle(pickle);

        Ok(Self { inner })
    }

    #[napi]
    pub fn from_libolm_pickle(pickle: String, pickle_key: &[u8]) -> Result<Account> {
        let inner =
            vodozemac::olm::Account::from_libolm_pickle(&pickle, pickle_key)
                .map_err(|_| Error::new(Status::GenericFailure, "Invalid data"))?;

        Ok(Self { inner })
    }

    #[napi]
    pub fn pickle(&self, pickle_key: String) -> Result<String> {
        let pickle_key: &[u8; 32] = pickle_key
            .as_bytes()
            .try_into()
            .map_err(|_| Error::from_reason("Invalid pickle key length, expected 32 bytes"))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    #[napi(getter)]
    pub fn ed25519_key(&self) -> String {
        self.inner.ed25519_key().to_base64()
    }

    #[napi(getter)]
    pub fn curve25519_key(&self) -> String {
        self.inner.curve25519_key().to_base64()
    }

    #[napi]
    pub fn sign(&self, message: String) -> String {
        self.inner.sign(&message).to_base64()
    }

    #[napi(getter)]
    pub fn max_number_of_one_time_keys(&self) -> u32 {
        self.inner.max_number_of_one_time_keys().try_into().unwrap()
    }

    #[napi(getter, ts_return_type = "Record<string, string>")]
    pub fn one_time_keys(&self, env: Env) -> Result<JsObject> {
        let _keys: HashMap<_, _> = self
            .inner
            .one_time_keys()
            .into_iter()
            .map(|(k, v)| (k.to_base64(), v.to_base64()))
            .collect();

        let mut res = env.create_object().unwrap();
        for (key, value) in _keys.iter() {
            res.set(key, value)?;
        }

        Ok(res)
    }

    #[napi]
    pub fn generate_one_time_keys(&mut self, count: u32) {
        self.inner.generate_one_time_keys(count.try_into().unwrap());
    }

    #[napi(getter)]
    pub fn fallback_key(&self, env: Env) -> Result<JsObject> {
        let _keys: HashMap<String, String> = self
            .inner
            .fallback_key()
            .into_iter()
            .map(|(k, v)| (k.to_base64(), v.to_base64()))
            .collect();

        let mut res = env.create_object().unwrap();
        for (key, value) in _keys.iter() {
            res.set(key, value)?;
        }
        Ok(res)
    }

    #[napi]
    pub fn generate_fallback_key(&mut self) {
        self.inner.generate_fallback_key()
        ;
    }

    #[napi]
    pub fn mark_keys_as_published(&mut self) {
        self.inner.mark_keys_as_published()
    }

    #[napi]
    pub fn create_outbound_session(
        &self,
        identity_key: String,
        one_time_key: String,
    ) -> Result<Session> {
        let identity_key =
            vodozemac::Curve25519PublicKey::from_base64(&identity_key).map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;
        let one_time_key =
            vodozemac::Curve25519PublicKey::from_base64(&one_time_key).map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;
        let session = self
            .inner
            .create_outbound_session(SessionConfig::version_2(), identity_key, one_time_key);

        Ok(Session { inner: session })
    }

    #[napi]
    pub fn create_inbound_session(
        &mut self,
        identity_key: String,
        message: &OlmMessage,
    ) -> Result<InboundCreationResult> {
        let identity_key =
            vodozemac::Curve25519PublicKey::from_base64(&identity_key).unwrap();

        let message =
            vodozemac::olm::OlmMessage::from_parts(message.message_type.try_into().unwrap(), &message.ciphertext.as_bytes()).unwrap();

        if let vodozemac::olm::OlmMessage::PreKey(message) = message {
            Ok(self
                .inner
                .create_inbound_session(identity_key, &message)
                .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?
                .into()
            )
        } else {
            Err(Error::new(Status::GenericFailure, "Invalid message type, expected a pre-key message"))
            //napi::Error::from_reason("Invalid message type, expected a pre-key message");
           // throw_error("Invalid message type, expected a pre-key message")
        }
    }
}
