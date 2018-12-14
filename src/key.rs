pub trait Key {
    fn verify(self, plain: &str, string: &str) -> Result<bool, crate::Error>;
}

pub trait KeyFetcher {
    type Key: Key;

    fn fetch<P>(payload: P) -> Result<Self::Key, crate::Error>;
}

#[cfg(test)]
mod tests {}
