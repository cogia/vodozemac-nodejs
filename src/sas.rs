use napi::bindgen_prelude::*;
use napi_derive::napi;


#[napi]
pub struct Sas {
    inner: vodozemac::sas::Sas,
}

#[napi]
impl Sas {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: vodozemac::sas::Sas::new(),
        }
    }

    #[napi(getter)]
    pub fn public_key(&self) -> String {
        self.inner.public_key().to_base64()
    }

    pub fn diffie_hellman(self, key: &str) -> Result<EstablishedSas> {
        let sas = self
            .inner
            .diffie_hellman_with_raw(key)
            .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        Ok(EstablishedSas { inner: sas })
    }
}

#[napi]
pub struct EstablishedSas {
    inner: vodozemac::sas::EstablishedSas,
}

#[napi]
impl EstablishedSas {
    pub fn bytes(&self, info: &str) -> SasBytes {
        let bytes = self.inner.bytes(info);

        SasBytes { inner: bytes }
    }

    pub fn calculate_mac(&self, input: &str, info: &str) -> String {
        self.inner.calculate_mac(input, info).to_base64()
    }

    pub fn calculate_mac_invalid_base64(&self, input: &str, info: &str) -> String {
        self.inner.calculate_mac_invalid_base64(input, info)
    }

    pub fn verify_mac(&self, input: &str, info: &str, tag: &str) -> Result<()> {
        let tag = vodozemac::sas::Mac::from_base64(tag)
            .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        self.inner
            .verify_mac(input, info, &tag)
            .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        Ok(())
    }
}

#[napi]
pub struct SasBytes {
    inner: vodozemac::sas::SasBytes,
}

#[napi]
impl SasBytes {
    #[napi(getter)]
    pub fn emoji_indices(&self) -> Vec<u8> {
        self.inner.emoji_indices().to_vec()
    }

    #[napi(getter)]
    pub fn decimals(&self) -> Vec<u16> {
        let (first, second, third) = self.inner.decimals();

        [first, second, third].to_vec()
    }
}
