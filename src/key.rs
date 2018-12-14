pub trait Key {}

pub trait KeyFetcher {
    type Key: Key;

    fn fetch<P>(payload: P) -> Result<Self::Key, crate::Error>;
}

#[cfg(test)]
mod tests {}
