use crate::symmetric::{decode::Decoder, encode::Encoder};

#[derive(Default)]
pub struct Bitcode;

impl Encoder for Bitcode {
    fn encode<T: serde::Serialize + ?Sized>(
        t: &T,
    ) -> Result<Vec<u8>, Box<(dyn std::error::Error)>> {
        let res = bitcode::serialize(t)?;
        Ok(res)
    }
}

impl Decoder for Bitcode {
    fn decode<'de, T: serde::Deserialize<'de>>(
        input: &'de [u8],
    ) -> Result<T, Box<(dyn std::error::Error + 'static)>> {
        let res = bitcode::deserialize(input)?;
        Ok(res)
    }
}
