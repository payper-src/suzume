extern crate base64;

use failure::Fail;

use super::{Error, ErrorKind};

const DELIMITER: &str = ".";

fn split_jwt(jwt: &str) -> Result<(&str, &str), Error> {
    let splitted = jwt.rsplitn(2, DELIMITER).collect::<Vec<&str>>();
    if splitted.len() != 2 {
        return Err(Error::from(ErrorKind::WrongToken));
    } else {
        Ok((splitted[0], splitted[1]))
    }
}

fn split_plain<H, P>(plain: &str) -> Result<(H, P), Error>
where
    H: serde::de::DeserializeOwned,
    P: serde::de::DeserializeOwned,
{
    const DELIMITER: &str = ".";
    let splitted = plain.split(DELIMITER).collect::<Vec<&str>>();
    if splitted.len() != 2 {
        return Err(Error::from(ErrorKind::WrongToken));
    } else {
        Ok((decode(splitted[0])?, decode(splitted[1])?))
    }
}

fn decode<T>(s: &str) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    let decoded =
        base64::decode_config(s, base64::URL_SAFE_NO_PAD).map_err::<Error, _>(Into::into)?;
    serde_json::from_slice::<T>(&decoded).map_err::<Error, _>(Into::into)
}

pub fn from_raw_jwt<'a, H, P>(jwt: &'a str) -> Result<(H, P, &'a str, &'a str), Error>
where
    H: serde::de::DeserializeOwned,
    P: serde::de::DeserializeOwned,
{
    let (signature, plain) = split_jwt(&jwt)?;
    let (header, payload) = split_plain(&plain)?;

    Ok((header, payload, plain, signature))
}

impl From<base64::DecodeError> for Error {
    fn from(origin: base64::DecodeError) -> Error {
        Error::new(origin.context(ErrorKind::WrongToken))
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(origin: serde_json::error::Error) -> Error {
        Error::new(origin.context(ErrorKind::WrongToken))
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn split_jwt() -> Result<(), super::Error> {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
                   .eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ\
                   .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let raw_plain = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        let raw_signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        assert_eq!(super::split_jwt(jwt)?, (raw_signature, raw_plain));
        Ok(())
    }
}
