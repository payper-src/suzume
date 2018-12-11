extern crate base64;

use super::{Error, ErrorKind};

pub struct Decoded<H, P> {
    header: H,
    payload: P,
}

pub fn decode<'a, H, P>(jwt: String) -> Result<Decoded<H, P>, Error>
where
    H: serde::Deserialize<'a>,
    P: serde::Deserialize<'a>,
{
    const DELIMITER: &str = ".";
    let splitted = jwt.split(DELIMITER).collect::<Vec<&str>>();
    if splitted.len() != 3 {
        return Err(Error::from(ErrorKind::WrongToken));
    }

    Ok(Decoded {
        header: token_to_rust_data::<'a, H>(splitted[0].to_owned())?,
        payload: token_to_rust_data::<'a, P>(splitted[1].to_owned())?,
    })
}

fn token_to_rust_data<'a, T>(s: String) -> Result<T, Error>
where
    T: serde::Deserialize<'a>,
{
    let raw_json = Box::new(
        base64::decode_config(&s, base64::URL_SAFE_NO_PAD).map_err::<Error, _>(Into::into)?,
    );
    serde_json::from_slice::<T>(Box::leak(raw_json)).map_err::<Error, _>(Into::into)
}

impl From<base64::DecodeError> for Error {
    fn from(_error: base64::DecodeError) -> Error {
        Error::from(ErrorKind::WrongToken)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(_error: serde_json::error::Error) -> Error {
        Error::from(ErrorKind::WrongToken)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(_error: std::str::Utf8Error) -> Error {
        Error::from(ErrorKind::WrongToken)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn decode_test() {}
}
