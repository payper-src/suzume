/// Payload is contained in jwt
pub trait Payload {
    /// get issuer
    fn get_iss(&self) -> Option<String> {
        None
    }

    /// get expiration time
    fn get_exp(&self) -> Option<i64> {
        None
    }

    /// whether this jwt is expired or not
    fn is_expired(&self) -> bool {
        if let Some(exp) = self.get_exp() {
            exp < time::now_utc().to_timespec().sec
        } else {
            true
        }
    }

    /// get not before time
    fn get_nbf(&self) -> Option<i64> {
        None
    }

    /// whether this jwt is "not before" or not
    fn is_not_before(&self) -> bool {
        if let Some(nbf) = self.get_nbf() {
            nbf >= time::now_utc().to_timespec().sec
        } else {
            true
        }
    }
}
