use aead::{generic_array::GenericArray, Aead, AeadCore, Key, KeyInit, KeySizeUser, OsRng};
use secrecy::{ExposeSecret, Secret, SecretVec, Zeroize};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::marker::PhantomData;

use crate::serialization::{decode::Decoder, encode::Encoder};

/// represents the encrypted form of the data, can be serialized and deserialized
#[derive(Debug, Serialize, Deserialize)]
pub struct Encrypted<Data> {
    nonce: Vec<u8>,
    data: Vec<u8>,
    #[serde(skip)]
    phantom: PhantomData<Data>,
}

/// represents data that has been decrypted, but still needs to be deserialized
/// assumes the data is sensitive and wraps it in a `[Secret]`
#[derive(Deserialize)]
pub struct Decrypted<Data> {
    data: SecretVec<u8>,
    #[serde(skip)]
    phantom: PhantomData<Data>,
}

/// represents data that has been decrypted, but still needs to be deserialized
/// doesn't make the assumption that data is sensitive
#[derive(Debug, Deserialize)]
pub struct DecryptedExposed<Data> {
    data: Vec<u8>,
    #[serde(skip)]
    phantom: PhantomData<Data>,
}
type GenericErr = Box<(dyn std::error::Error)>;

/// general trait for encrypting serializable data
pub trait Encryption {
    type Cipher: Aead + AeadCore + KeyInit + KeySizeUser;
    type Scheme: Encoder + Decoder;

    fn encode<Data>(data: &Encrypted<Data>) -> Result<Vec<u8>, GenericErr> {
        Self::Scheme::encode(data)
    }

    fn decode<Data>(data: &[u8]) -> Result<Encrypted<Data>, Box<(dyn std::error::Error)>> {
        Self::Scheme::decode(data)
    }

    fn extract<'de, Data: Deserialize<'de> + Zeroize>(
        decrypted: &'de Decrypted<Data>,
    ) -> Result<Secret<Data>, Box<(dyn std::error::Error)>> {
        Self::Scheme::decode(decrypted.data.expose_secret()).map(|x| Secret::new(x))
    }

    fn extract_exposed<'de, Data: Deserialize<'de>>(
        decrypted: &'de DecryptedExposed<Data>,
    ) -> Result<Data, Box<(dyn std::error::Error)>> {
        Self::Scheme::decode(&decrypted.data)
    }

    /// convert the data to it's serialized form and then encypt it using `[Cipher]`
    fn encrypt<Data: Serialize>(
        data: &Data,
        key: &Key<Self::Cipher>,
    ) -> Result<Encrypted<Data>, GenericErr> {
        let cipher = Self::Cipher::new(key);
        let nonce = Self::Cipher::generate_nonce(&mut OsRng);
        let serialized = Self::Scheme::encode(data)?;
        let encrypted = cipher.encrypt(&nonce, serialized.as_ref())?;
        Ok(Encrypted {
            nonce: nonce.to_vec(),
            data: encrypted,
            phantom: PhantomData,
        })
    }

    /// take ownership of encrypted value and directly decrypt it without needing
    /// a separate decode step
    fn into_data<Data: DeserializeOwned + Zeroize>(
        encrypted: Encrypted<Data>,
        key: &GenericArray<u8, <Self::Cipher as KeySizeUser>::KeySize>,
    ) -> Result<Secret<Data>, GenericErr> {
        let cipher = Self::Cipher::new(key);
        let data = cipher.decrypt(
            GenericArray::from_slice(encrypted.nonce.as_ref()),
            encrypted.data.as_ref(),
        )?;
        let decoded = Self::Scheme::decode_owned(data)?;
        Ok(Secret::new(decoded))
    }

    /// take ownership of encrypted value and directly decrypt it without needing
    /// a separate decode step
    /// doesn't return a secret value
    fn into_data_exposed<Data: DeserializeOwned>(
        encrypted: Encrypted<Data>,
        key: &GenericArray<u8, <Self::Cipher as KeySizeUser>::KeySize>,
    ) -> Result<Data, GenericErr> {
        let cipher = Self::Cipher::new(key);
        let data = cipher.decrypt(
            GenericArray::from_slice(encrypted.nonce.as_ref()),
            encrypted.data.as_ref(),
        )?;
        Self::Scheme::decode_owned(data)
    }
    /// decrypt the data to it's serialized form, pre-emptively wraps data in
    /// a [Secret]
    fn decrypt<Data>(
        encrypted: &Encrypted<Data>,
        key: &GenericArray<u8, <Self::Cipher as KeySizeUser>::KeySize>,
    ) -> Result<Decrypted<Data>, GenericErr> {
        let cipher = Self::Cipher::new(key);
        let data = cipher.decrypt(
            GenericArray::from_slice(encrypted.nonce.as_ref()),
            encrypted.data.as_ref(),
        )?;
        Ok(Decrypted {
            data: data.into(),
            phantom: PhantomData,
        })
    }

    /// decrypt the data to it's serialized form
    fn decrypt_exposed<Data>(
        encrypted: &Encrypted<Data>,
        key: &GenericArray<u8, <Self::Cipher as KeySizeUser>::KeySize>,
    ) -> Result<DecryptedExposed<Data>, GenericErr> {
        let cipher = Self::Cipher::new(key);
        let data = cipher.decrypt(
            GenericArray::from_slice(encrypted.nonce.as_ref()),
            encrypted.data.as_ref(),
        )?;
        Ok(DecryptedExposed {
            data,
            phantom: PhantomData,
        })
    }
}
