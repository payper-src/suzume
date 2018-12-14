extern crate base64;

use failure::Fail;

use super::{Error, ErrorKind};

fn split_jwt(jwt: &str) -> Result<Vec<&str>, Error> {
    const DELIMITER: &str = ".";
    let splitted = jwt.split(DELIMITER).collect::<Vec<&str>>();
    if splitted.len() != 3 {
        return Err(Error::from(ErrorKind::WrongToken));
    } else {
        Ok(splitted)
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

pub fn from_raw_jwt<H, P>(jwt: String) -> Result<(H, P, String), Error>
where
    H: serde::de::DeserializeOwned,
    P: serde::de::DeserializeOwned,
{
    let splitted = split_jwt(&jwt)?;

    Ok((
        decode::<H>(splitted[0])?,
        decode::<P>(splitted[1])?,
        splitted[2].to_owned(),
    ))
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
        let raw_header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let raw_payload =
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        let raw_signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        assert_eq!(
            super::split_jwt(jwt)?,
            vec![raw_header, raw_payload, raw_signature]
        );
        Ok(())
    }
}
