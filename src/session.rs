use napi_derive::napi;
use vodozemac::{base64_decode, base64_encode};
use napi::*;
use super::OlmMessage;

#[napi]
pub struct Session {
    pub(super) inner: vodozemac::olm::Session,
}

#[napi]
impl Session {
    #[napi]
    pub fn pickle(&self, pickle_key: String) -> Result<String> {
        let pickle_key: &[u8; 32] = pickle_key
            .as_bytes()
            .try_into()
            .map_err(|_| Error::new(Status::GenericFailure, "Invalid pickle key length, expected 32 bytes"))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    #[napi]
    pub fn from_pickle(pickle: String, pickle_key: String) -> Result<Session> {
        let pickle_key: &[u8; 32] = pickle_key
            .as_bytes()
            .try_into()
            .map_err(|_| Error::new(Status::GenericFailure, "Invalid pickle key length, expected 32 bytes"))?;
        let pickle = vodozemac::olm::SessionPickle::from_encrypted(&pickle, pickle_key)
            .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        let session = vodozemac::olm::Session::from_pickle(pickle);

        Ok(Self { inner: session })
    }

    #[napi]
    pub fn from_libolm_pickle(pickle: String, pickle_key: String) -> Result<Session> {
        let session =
            vodozemac::olm::Session::from_libolm_pickle(&pickle, &pickle_key.as_bytes()).map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        Ok(Self { inner: session })
    }

    #[napi(getter)]
    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }

    #[napi]
    pub fn session_matches(&self, message: &OlmMessage) -> bool {
        let message =
            vodozemac::olm::OlmMessage::from_parts(
                message.message_type.try_into().unwrap(),
                &base64_decode(&message.ciphertext).unwrap()
            );

        match message {
            Ok(m) => {
                if let vodozemac::olm::OlmMessage::PreKey(m) = m {
                    self.inner.session_keys() == m.session_keys()
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    #[napi]
    pub fn encrypt(&mut self, plaintext: String) -> OlmMessage {
        let message = self.inner.encrypt(plaintext);

        let (message_type, ciphertext) = message.to_parts();

        OlmMessage {
            ciphertext: base64_encode(ciphertext), //String::from_utf8_lossy(&ciphertext).into_owned(),
            message_type: message_type.try_into().unwrap(),
        }
    }

    #[napi]
    pub fn decrypt(&mut self, message: &OlmMessage) -> Result<String> {
        /*let _message =
            vodozemac::olm::OlmMessage::from_parts(message.message_type.try_into().unwrap(), &message.ciphertext.as_bytes())
                .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        Ok(self.inner.decrypt(&_message).map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?)*/
        let _message = vodozemac::olm::OlmMessage::from_parts(
            message.message_type.try_into().unwrap(),
            &base64_decode(&message.ciphertext).unwrap()
        )
            .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        let decrypted_message = self.inner.decrypt(&_message)
            .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        let decrypted_message = String::from_utf8(decrypted_message)
            .map_err(|err| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        Ok(decrypted_message)
    }
}