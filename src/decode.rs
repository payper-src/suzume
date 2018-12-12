extern crate base64;

use failure::Fail;

use super::{Error, ErrorKind};

pub struct Decoded<H, P>
where
    H: serde::de::DeserializeOwned,
    P: serde::de::DeserializeOwned,
{
    header: H,
    payload: P,
    signature: String,
}

/// Decode jwt to provided struct.
///
/// ## Example
///
/// ```
/// #[macro_use]
/// extern crate serde_derive;
///
/// extern crate suzume;
///
/// #[derive(Deserialize)]
/// struct Header {
///     alg: String,
///     typ: String,
/// }
///
/// #[derive(Deserialize)]
/// struct Payload {
///     sub: i32,
///     name: String,
///     iat: i32,
/// }
///
/// fn main() {
///     let jwt =  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c".to_owned();
///     let decoded = suzume::from_raw_jwt::<Header, Payload>(jwt);
/// }
/// ```
pub fn from_raw_jwt<H, P>(jwt: String) -> Result<Decoded<H, P>, Error>
where
    H: serde::de::DeserializeOwned,
    P: serde::de::DeserializeOwned,
{
    const DELIMITER: &str = ".";
    let splitted = jwt.split(DELIMITER).collect::<Vec<&str>>();
    if splitted.len() != 3 {
        return Err(Error::from(ErrorKind::WrongToken));
    }

    let decoded = Decoded {
        header: token_to_struct::<H>(splitted[0])?,
        payload: token_to_struct::<P>(splitted[1])?,
        signature: splitted[2].to_owned(),
    };

    Ok(decoded)
}

fn token_to_struct<T>(s: &str) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    let decoded =
        base64::decode_config(s, base64::URL_SAFE_NO_PAD).map_err::<Error, _>(Into::into)?;
    serde_json::from_slice::<T>(&decoded).map_err::<Error, _>(Into::into)
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
    fn decode_test() {
        //TODO: write exception test.
    }
}
