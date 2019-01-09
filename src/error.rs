/// kind of this library Error
#[derive(Fail, Debug)]
pub enum ErrorKind {
    /// JSON parse error
    #[fail(display = "Json parse error")]
    JsonParse,
    /// Fetch failed error
    #[fail(display = "Fetch failed error")]
    FetchFailed,
    /// Wrong Token
    #[fail(display = "Wrong token")]
    WrongToken,
    /// Token is expired
    #[fail(display = "Token is expired")]
    ExpiredToken,
    /// Token has been not enable yet.
    #[fail(display = "Token has been not enable yet")]
    NotBefore,
    /// Validation Fail
    #[fail(display = "Validation Fail")]
    ValidationFail,
    /// Does not support kind of algorithm
    #[fail(display = "Does Not Support Kind of Algorithm: {:?}", kind)]
    DoesNotSupportAlgorithm {
        /// KInd of Algorithm
        kind: AlgorithmKind,
    },
    /// Not found payload item
    #[fail(display = "Not Found Item: {:?}", item)]
    NotFoundPayloadItem {
        /// payload item
        item: PayloadItem,
    },
    /// Not found header item
    #[fail(display = "Not Found Item: {:?}", item)]
    NotFoundHeaderItem {
        /// header item
        item: HeaderItem,
    },
    /// Not found jwk's key
    #[fail(display = "Not Found jwk's key")]
    NotFoundJwks,
    /// Not found x.509 Certification chain
    #[fail(display = "Not Found x5c")]
    NotFoundx5c,
    /// Openssl error
    #[fail(display = "Open SSL Error")]
    OpenSSLError,
    /// Not expected issuer
    #[fail(display = "Not Expected Issuer")]
    NotExpectedIssuer,
    /// Others
    #[fail(display = "Something Happens")]
    Others,
}

/// Payload item
#[derive(Debug)]
pub enum PayloadItem {
    /// issuer
    ISS,
}

/// Header item
#[derive(Debug)]
pub enum HeaderItem {
    /// Algorithm
    ALG,
    /// Key Id
    KID,
}

/// Kind of Algorithm
#[derive(Debug)]
pub enum AlgorithmKind {
    /// RS256
    RS256,
    /// Others
    Others,
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

/// this library Error
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
    /// new with context
    pub fn new(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }

    /// get kind of error
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

impl From<failure::Error> for Error {
    fn from(error: failure::Error) -> Error {
        Error {
            inner: error.context(ErrorKind::Others),
        }
    }
}
