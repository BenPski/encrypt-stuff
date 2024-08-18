use aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, KeySizeUser, OsRng};
use secrecy::{ExposeSecret, Secret, SecretVec, Zeroize};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use super::{decode::Decoder, encode::Encoder, schemes::bitcode::Bitcode};

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
pub trait Encryption<Scheme = Bitcode>
where
    Scheme: Encoder + Decoder,
{
    type Cipher: Aead + AeadCore + KeyInit + KeySizeUser;
    // type Scheme: Encoder + Decoder;

    fn encode<Data>(data: &Encrypted<Data>) -> Result<Vec<u8>, GenericErr> {
        Scheme::encode(data)
    }

    fn decode<Data>(data: &[u8]) -> Result<Encrypted<Data>, Box<(dyn std::error::Error)>> {
        Scheme::decode(data)
    }

    fn extract<'de, Data: Deserialize<'de> + Zeroize>(
        decrypted: &'de Decrypted<Data>,
    ) -> Result<Secret<Data>, Box<(dyn std::error::Error)>> {
        Scheme::decode(decrypted.data.expose_secret()).map(|x| Secret::new(x))
    }

    fn extract_exposed<'de, Data: Deserialize<'de>>(
        decrypted: &'de DecryptedExposed<Data>,
    ) -> Result<Data, Box<(dyn std::error::Error)>> {
        Scheme::decode(&decrypted.data)
    }

    /// convert the data to it's serialized form and then encypt it using `[Cipher]`
    fn encrypt<Data: Serialize>(
        data: &Data,
        key: &GenericArray<u8, <Self::Cipher as KeySizeUser>::KeySize>,
    ) -> Result<Encrypted<Data>, GenericErr> {
        let cipher = Self::Cipher::new(key);
        let nonce = Self::Cipher::generate_nonce(&mut OsRng);
        let serialized = Scheme::encode(data)?;
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
