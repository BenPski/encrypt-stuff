use aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, KeySizeUser, OsRng};
use secrecy::{ExposeSecret, Secret, SecretVec, Zeroize};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use crate::error::EncryptionError;

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

impl<'a, Data> Decrypted<Data>
where
    Data: Deserialize<'a> + Zeroize,
{
    pub fn deserialize(&'a self) -> Result<Secret<Data>, bitcode::Error> {
        bitcode::deserialize(&self.data.expose_secret()).map(|res| Secret::new(res))
    }
}

impl<'a, Data> DecryptedExposed<Data>
where
    Data: Deserialize<'a>,
{
    pub fn deserialize(&'a self) -> Result<Data, bitcode::Error> {
        bitcode::deserialize(&self.data)
    }
}

impl<'de, Data> Encrypted<Data>
where
    Data: Serialize + Deserialize<'de>,
{
    pub fn encode(&self) -> Result<Vec<u8>, bitcode::Error> {
        bitcode::serialize(&self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, bitcode::Error> {
        bitcode::deserialize(bytes)
    }
}

/// general trait for encrypting serializable data
pub trait Encryption {
    type Cipher: Aead + AeadCore + KeyInit + KeySizeUser;
    /// convert the data to it's serialized form and then encypt it using `[Cipher]`
    fn encrypt<Data: Serialize>(
        data: &Data,
        key: &GenericArray<u8, <Self::Cipher as KeySizeUser>::KeySize>,
    ) -> Result<Encrypted<Data>, EncryptionError> {
        let cipher = Self::Cipher::new(key);
        let nonce = Self::Cipher::generate_nonce(&mut OsRng);
        let serialized = bitcode::serialize(data)?;
        let encrypted = cipher.encrypt(&nonce, serialized.as_ref())?;
        Ok(Encrypted {
            nonce: nonce.to_vec(),
            data: encrypted,
            phantom: PhantomData,
        })
    }

    /// decrypt the data to it's serialized form, pre-emptively wraps data in
    /// a [Secret]
    fn decrypt<Data>(
        encrypted: &Encrypted<Data>,
        key: &GenericArray<u8, <Self::Cipher as KeySizeUser>::KeySize>,
    ) -> Result<Decrypted<Data>, EncryptionError> {
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
    ) -> Result<DecryptedExposed<Data>, EncryptionError> {
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
