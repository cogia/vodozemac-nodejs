use std::collections::HashMap;
use napi::bindgen_prelude::*;
use napi::{JsObject};
use napi_derive::napi;
use vodozemac::base64_decode;
use vodozemac::olm::SessionConfig;


use super::{session::Session,  OlmMessage, IdentityKeys};


#[napi]
pub struct Account {
    inner: vodozemac::olm::Account,
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
    pub fn from_libolm_pickle(pickle: String, pickle_key: String) -> Result<Account> {
        let inner =
            vodozemac::olm::Account::from_libolm_pickle(&pickle, &pickle_key.as_bytes())
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
        config: &crate::SessionConfig
    ) -> Result<Session> {
        let _config = if config.version() == 2 { vodozemac::megolm::SessionConfig::version_2() } else { vodozemac::megolm::SessionConfig::version_1() };

        let identity_key =
            vodozemac::Curve25519PublicKey::from_base64(&identity_key).map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;
        let one_time_key =
            vodozemac::Curve25519PublicKey::from_base64(&one_time_key).map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;
        let session = self
            .inner
            .create_outbound_session(SessionConfig::version_2(), identity_key, one_time_key);

        Ok(Session { inner: session })
    }

    #[napi(ts_return_type = "{ session: Session, plaintext: string }")]
    pub fn create_inbound_session(
        &mut self,
        identity_key: String,
        message: &OlmMessage,
        env: Env
    ) -> Result<JsObject> {
        let identity_key =
            vodozemac::Curve25519PublicKey::from_base64(&identity_key)
                .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        let _message = vodozemac::olm::OlmMessage::from_parts(
                message.message_type.try_into().unwrap(),
                &(base64_decode(&message.ciphertext).unwrap())
               // &message.ciphertext.as_bytes()
            )
                .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        if let vodozemac::olm::OlmMessage::PreKey(m) = _message {
            let res = self
                .inner
                .create_inbound_session(identity_key, &m)
                .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

            let mut obj = env.create_object().unwrap();
            let _ = obj.set("session", Session { inner: res.session })?;
            let _ = obj.set("plaintext", String::from_utf8_lossy(&res.plaintext).to_string())?;
            Ok(obj)
        } else {
            Err(Error::new(Status::GenericFailure, "Invalid message type, expected a pre-key message"))
        }
    }
}
