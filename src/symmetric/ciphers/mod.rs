/// create the tag/wrapper structs to indicate an encryption scheme with a
/// serialization scheme
///
/// takes on the general form
/// ```
/// struct Cipher<S>(S);
/// ```
///
/// includes the serialization scheme so it can be parameterized by it
/// ```
/// type DefaultScheme = Aes256Gcm<Bitcode>;
/// let scheme = DefaultScheme::default();
/// ```
macro_rules! cipher {
    ($name:ident, $path:path) => {
        #[derive(Debug, Default)]
        pub struct $name<S>(S);
        impl<S> crate::symmetric::encryption::Encryption<S> for $name<S>
        where
            S: crate::symmetric::decode::Decoder + crate::symmetric::encode::Encoder,
        {
            type Cipher = $path;
        }
    };
}

#[cfg(feature = "aes128gcm")]
cipher!(Aes128Gcm, aes_gcm::Aes128Gcm);
#[cfg(feature = "aes256gcm")]
cipher!(Aes256Gcm, aes_gcm::Aes256Gcm);
#[cfg(feature = "aes128gcmsiv")]
cipher!(Aes128GcmSiv, aes_gcm_siv::Aes128GcmSiv);
#[cfg(feature = "aes256gcmsiv")]
cipher!(Aes256GcmSiv, aes_gcm_siv::Aes256GcmSiv);
#[cfg(feature = "chacha20poly1305")]
cipher!(ChaCha20Poly1305, chacha20poly1305::ChaCha20Poly1305);
#[cfg(feature = "chacha12poly1305")]
cipher!(ChaCha12Poly1305, chacha20poly1305::ChaCha12Poly1305);
#[cfg(feature = "chacha8poly1305")]
cipher!(ChaCha8Poly1305, chacha20poly1305::ChaCha8Poly1305);
#[cfg(feature = "xchacha20poly1305")]
cipher!(XChaCha20Poly1305, chacha20poly1305::XChaCha20Poly1305);
#[cfg(feature = "xchacha12poly1305")]
cipher!(XChaCha12Poly1305, chacha20poly1305::XChaCha12Poly1305);
#[cfg(feature = "xchacha8poly1305")]
cipher!(XChaCha8Poly1305, chacha20poly1305::XChaCha8Poly1305);
