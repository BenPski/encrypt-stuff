use super::{decode::Decoder, encode::Encoder};

#[derive(Debug, Default)]
pub struct Bincode;

impl Encoder for Bincode {
    fn encode<T: serde::Serialize + ?Sized>(
        t: &T,
    ) -> Result<Vec<u8>, Box<(dyn std::error::Error)>> {
        let res = bincode::serialize(t)?;
        Ok(res)
    }
}

impl Decoder for Bincode {
    fn decode<'de, T: serde::Deserialize<'de>>(
        input: &'de [u8],
    ) -> Result<T, Box<(dyn std::error::Error + 'static)>> {
        let res = bincode::deserialize(input)?;
        Ok(res)
    }
    fn decode_owned<T: serde::de::DeserializeOwned>(
        input: Vec<u8>,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let res = bincode::deserialize(&input)?;
        Ok(res)
    }
}
