//! extract jwt from something
use crate::{Error, ErrorKind};

/// from http authroization header
pub fn from_authorization_header<'a>(authorization_header: &'a str) -> Result<&'a str, Error> {
    let (bearer, jwt_str) = {
        let mut split_whitespace = authorization_header.split_whitespace();
        let bearer = match split_whitespace.next() {
            None => return Err(ErrorKind::WrongToken.into()),
            Some(x) => x,
        };
        let jwt_str = match split_whitespace.next() {
            None => return Err(ErrorKind::WrongToken.into()),
            Some(x) => x,
        };
        (bearer, jwt_str)
    };

    if bearer != "Bearer" {
        return Err(ErrorKind::WrongToken.into());
    }

    Ok(jwt_str)
}
