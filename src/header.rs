pub trait Header {
    fn get_alg(&self) -> Option<String> {
        None
    }

    fn get_kid(&self) -> Option<String> {
        None
    }
}
