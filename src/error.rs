#[derive(Fail, Debug)]
pub enum ErrorKind {
    #[fail(display = "Json parse error")]
    JsonParse,
    #[fail(display = "Fetch failed error")]
    FetchFailed,
    #[fail(display = "Wrong token")]
    WrongToken,
    #[fail(display = "Token is expired")]
    ExpiredToken,
    #[fail(display = "Token has been not enable yet")]
    NotBefore,
    #[fail(display = "Validation Fail")]
    ValidationFail,
    #[fail(display = "Does Not Support Kind of Algorithm: {:?}", kind)]
    DoesNotSupportAlgorithm { kind: AlgorithmKind },
    #[fail(display = "Not Found Item: {:?}", item)]
    NotFoundPayloadItem { item: PayloadItem },
    #[fail(display = "Not Found Item: {:?}", item)]
    NotFoundHeaderItem { item: HeaderItem },
    #[fail(display = "Not Found jwk's key")]
    NotFoundJwks,
    #[fail(display = "Not Found x5c")]
    NotFoundx5c,
    #[fail(display = "Open SSL Error")]
    OpenSSLError,
}

#[derive(Debug)]
pub enum PayloadItem {
    ISS,
}

#[derive(Debug)]
pub enum HeaderItem {
    ALG,
    KID,
}

#[derive(Debug)]
pub enum AlgorithmKind {
    RS256,
    Others,
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Error {
        Error {
            inner: error.context(ErrorKind::FetchFailed),
        }
    }
}

// #[cfg(test)]
// mod tests {
//     #[test]
//     fn serde_json_error_test() {
//         #[derive(Deserialize)]
//         struct SomeType {}

//         fn tester() -> Result<SomeType, super::Error> {
//             serde_json::from_str("invalid string").map_err(Into::into)
//         }

//         match tester() {
//             Ok(_) => assert!(false),
//             Err(err) => match err.kind() {
//                 super::ErrorKind::JsonParse => { /*OK*/ }
//                 _ => assert!(false),
//             },
//         }
//     }

//     #[test]
//     fn reqwest_error_test() {
//         fn tester() -> Result<reqwest::Response, super::Error> {
//             reqwest::get("invalid url").map_err(Into::into)
//         }

//         match tester() {
//             Ok(_) => assert!(false),
//             Err(err) => match err.kind() {
//                 super::ErrorKind::FetchFailed => { /*OK*/ }
//                 _ => assert!(false),
//             },
//         }
//     }
// }

// Fxxkin boilerplate from https://boats.gitlab.io/failure/error-errorkind.html
use failure::{Backtrace, Context, Fail};
use std::fmt;
use std::fmt::Display;

#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl Error {
    pub fn new(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }

    pub fn kind(&self) -> &ErrorKind {
        self.inner.get_context()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}
//end boilerplate
