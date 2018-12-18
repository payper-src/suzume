pub trait Payload {
    fn get_iss(&self) -> Option<String> {
        None
    }

    fn get_exp(&self) -> Option<i64> {
        None
    }

    fn is_expired(&self) -> bool {
        if let Some(exp) = self.get_exp() {
            exp < time::now_utc().to_timespec().sec
        } else {
            false
        }
    }

    fn get_nbf(&self) -> Option<i64> {
        None
    }

    fn is_not_before(&self) -> bool {
        if let Some(nbf) = self.get_nbf() {
            nbf >= time::now_utc().to_timespec().sec
        } else {
            false
        }
    }
}