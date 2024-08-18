pub mod serialization;
pub mod symmetric;

macro_rules! cipher {
    ($name:ident, $cipher:path, $scheme:path) => {
        #[derive(Debug, Default)]
        pub struct $name;
        impl crate::symmetric::encryption::Encryption for $name {
            type Cipher = $cipher;
            type Scheme = $scheme;
        }
    };
}

#[cfg(all(feature = "aes256gcm", feature = "bitcode"))]
pub type DefaultScheme = Aes256GcmBitcode;

#[cfg(all(feature = "aes128gcm", feature = "bitcode"))]
cipher!(
    Aes128GcmBitcode,
    aes_gcm::Aes128Gcm,
    crate::serialization::bitcode::Bitcode
);
#[cfg(all(feature = "aes128gcmsiv", feature = "bitcode"))]
cipher!(
    Aes128GcmSivBitcode,
    aes_gcm_siv::Aes128GcmSiv,
    crate::serialization::bitcode::Bitcode
);
#[cfg(all(feature = "aes256gcm", feature = "bitcode"))]
cipher!(
    Aes256GcmBitcode,
    aes_gcm::Aes256Gcm,
    crate::serialization::bitcode::Bitcode
);
#[cfg(all(feature = "aes256gcmsiv", feature = "bitcode"))]
cipher!(
    Aes256GcmSivBitcode,
    aes_gcm_siv::Aes256GcmSiv,
    crate::serialization::bitcode::Bitcode
);
#[cfg(all(feature = "chacha8poly1305", feature = "bitcode"))]
cipher!(
    ChaCha8Poly1305Bitcode,
    chacha20poly1305::ChaCha8Poly1305,
    crate::serialization::bitcode::Bitcode
);
#[cfg(all(feature = "xchacha8poly1305", feature = "bitcode"))]
cipher!(
    XChaCha8Poly1305Bitcode,
    chacha20poly1305::XChaCha8Poly1305,
    crate::serialization::bitcode::Bitcode
);
#[cfg(all(feature = "chacha12poly1305", feature = "bitcode"))]
cipher!(
    ChaCha12Poly1305Bitcode,
    chacha20poly1305::ChaCha12Poly1305,
    crate::serialization::bitcode::Bitcode
);
#[cfg(all(feature = "xchacha12poly1305", feature = "bitcode"))]
cipher!(
    XChaCha12Poly1305Bitcode,
    chacha20poly1305::XChaCha12Poly1305,
    crate::serialization::bitcode::Bitcode
);
#[cfg(all(feature = "chacha20poly1305", feature = "bitcode"))]
cipher!(
    ChaCha20Poly1305Bitcode,
    chacha20poly1305::ChaCha20Poly1305,
    crate::serialization::bitcode::Bitcode
);
#[cfg(all(feature = "xchacha20poly1305", feature = "bitcode"))]
cipher!(
    XChaCha20Poly1305Bitcode,
    chacha20poly1305::XChaCha20Poly1305,
    crate::serialization::bitcode::Bitcode
);
#[cfg(all(feature = "aes128gcm", feature = "bincode"))]
cipher!(
    Aes128GcmBincode,
    aes_gcm::Aes128Gcm,
    crate::serialization::bincode::Bincode
);
#[cfg(all(feature = "aes128gcmsiv", feature = "bincode"))]
cipher!(
    Aes128GcmSivBincode,
    aes_gcm_siv::Aes128GcmSiv,
    crate::serialization::bincode::Bincode
);
#[cfg(all(feature = "aes256gcm", feature = "bincode"))]
cipher!(
    Aes256GcmBincode,
    aes_gcm::Aes256Gcm,
    crate::serialization::bincode::Bincode
);
#[cfg(all(feature = "aes256gcmsiv", feature = "bincode"))]
cipher!(
    Aes256GcmSivBincode,
    aes_gcm_siv::Aes256GcmSiv,
    crate::serialization::bincode::Bincode
);
#[cfg(all(feature = "chacha8poly1305", feature = "bincode"))]
cipher!(
    ChaCha8Poly1305Bincode,
    chacha20poly1305::ChaCha8Poly1305,
    crate::serialization::bincode::Bincode
);
#[cfg(all(feature = "xchacha8poly1305", feature = "bincode"))]
cipher!(
    XChaCha8Poly1305Bincode,
    chacha20poly1305::XChaCha8Poly1305,
    crate::serialization::bincode::Bincode
);
#[cfg(all(feature = "chacha12poly1305", feature = "bincode"))]
cipher!(
    ChaCha12Poly1305Bincode,
    chacha20poly1305::ChaCha12Poly1305,
    crate::serialization::bincode::Bincode
);
#[cfg(all(feature = "xchacha12poly1305", feature = "bincode"))]
cipher!(
    XChaCha12Poly1305Bincode,
    chacha20poly1305::XChaCha12Poly1305,
    crate::serialization::bincode::Bincode
);
#[cfg(all(feature = "chacha20poly1305", feature = "bincode"))]
cipher!(
    ChaCha20Poly1305Bincode,
    chacha20poly1305::ChaCha20Poly1305,
    crate::serialization::bincode::Bincode
);
#[cfg(all(feature = "xchacha20poly1305", feature = "bincode"))]
cipher!(
    XChaCha20Poly1305Bincode,
    chacha20poly1305::XChaCha20Poly1305,
    crate::serialization::bincode::Bincode
);
