extern crate base64;

use super::{Error, ErrorKind};

pub struct Decoded<H, P> {
    header: H,
    payload: P,
}

pub fn decode<'a, H, P>(jwt: String) -> Result<String, Error>
where
    H: serde::Deserialize<'a>,
    P: serde::Deserialize<'a>,
{
    const DELIMITER: &str = ".";
    let splitted = jwt.split(DELIMITER).collect::<Vec<&str>>();
    if splitted.len() != 3 {
        return Err(Error::from(ErrorKind::WrongToken));
    }

    let _decoded = Decoded {
        header: base64_to_json::<'a, H>(&splitted[0])?,
        payload: base64_to_json::<'a, P>(&splitted[1])?,
    };
    Ok("hoge".to_owned())
}

fn base64_to_json<'a, T>(s: &str) -> Result<T, Error>
where
    T: serde::Deserialize<'a>,
{
    let byte_array: Result<Vec<u8>, Error> =
        base64::decode_config(&s, base64::URL_SAFE_NO_PAD).map_err(Into::into);
    let decoded: Result<&str, Error> = std::str::from_utf8(&byte_array?).map_err(Into::into);
    serde_json::from_str::<T>(&decoded?).map_err(Into::into)
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
