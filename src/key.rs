/// decryption Key
pub trait Key {
    /// verify plain text and signature with this key
    fn verify(self, plain: &str, signature: Vec<u8>) -> Result<bool, crate::Error>;
}

/// fetch decryption Key
pub trait KeyFetcher {
    /// decryption key
    type Key: Key;

    /// fetch decryption key
    fn fetch<H, P>(self, header: &H, payload: &P) -> Result<Self::Key, crate::Error>
    where
        H: crate::Header,
        P: crate::Payload;
}

#[cfg(test)]
mod tests {}
