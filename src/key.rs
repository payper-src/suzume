pub trait Key {
    fn verify(self, plain: &str, signature: Vec<u8>) -> Result<bool, crate::Error>;
}

pub trait KeyFetcher {
    type Key: Key;

    fn fetch<P>(payload: &P) -> Result<Self::Key, crate::Error>
    where
        P: crate::Payload;
}

#[cfg(test)]
mod tests {}
