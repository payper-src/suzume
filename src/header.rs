/// JWT header
pub trait Header {
    /// get algorithm
    fn get_alg(&self) -> Option<String> {
        None
    }

    /// get key id
    fn get_kid(&self) -> Option<String> {
        None
    }
}
