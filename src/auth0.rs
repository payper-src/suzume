//! # For Auth0 settings
//!
//! ```
//! use suzume::{verify, Auth0Header, Auth0Payload, Auth0Fetcher};
//! fn main() -> Result<(), failure::Error> {
//!     verify::<Auth0Header, Auth0Payload,
//!     Auth0Fetcher>("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik56WTNSa1k1UlVNelFUUkNSamxHUkRrNVJrRkNSVEl6UXpBMk5FSkJOME5EUWpkR09ESXhNZyJ9.eyJpc3MiOiJodHRwczovL3BheXBlci5hdXRoMC5jb20vIiwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMTI4MjUxMjE2ODQ3NjE3ODU2MDkiLCJhdWQiOiJtWE5TbDYyZWJHQ0lJcmVORUc3d3RCRlREYTlzdTNQRSIsImlhdCI6MTU0NDE4MzQ0MCwiZXhwIjoxMTU0NDE4MzQzOSwiYXRfaGFzaCI6IjJuVm81M2xUTW01anJ5MkhkLWp1MXciLCJub25jZSI6Ik0zNFBJVn52b3h4bEktWEVQaUtRWFNIZTBjejVpYnZDIn0.cuArVuZh2o947UabPga4ojjVktDiW4WA5GvxrDVOx0KSKyAui4qscVSoZrBfjXGHsDYnWC8GvBqqAv6G2Sb6bnWW9wKabZMQB4KKej6hik-wIt835lmEo9QJQQ7Dfy1swbQL4J7Yyo62WucH0RoCtrKUKXHHw8W5asacIAC024EuTOoBLtsTby_yMf3UeZ1GANztCw8CtDOKgvEo-O0uE0grw-OyFpEx8Cjq1Ac9M4dpHQWil9PR-Bh_bTwVSclaKio-Ex2v_6b3DPL0obipWoz13nDY-18iUqVr1HAIglpzH-nG7fBDarTjj5U-tGkLugteWC2imSjlz7rjKmXgfQ".to_owned())?;
//!     Ok(())
//! }
//! ```
//!

use crate::{AlgorithmKind, Error, ErrorKind, HeaderItem, Jwks, PayloadItem};
use failure::Fail;
use openssl::hash::MessageDigest;
use openssl::pkey::{self, PKey};
use openssl::sign::Verifier;

pub struct Auth0Fetcher;

pub struct Key {
    inner: PKey<pkey::Public>,
}

#[derive(Debug, Deserialize)]
pub struct Auth0Header {
    typ: String,
    alg: String,
    kid: String,
}

impl crate::Header for Auth0Header {
    fn get_alg(&self) -> Option<String> {
        Some(self.alg.to_string())
    }

    fn get_kid(&self) -> Option<String> {
        Some(self.kid.to_string())
    }
}

#[derive(Debug, Deserialize)]
pub struct Auth0Payload {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
    at_hash: String,
    nonce: String,
}

impl crate::Payload for Auth0Payload {
    fn get_iss(&self) -> Option<String> {
        Some(self.iss.to_string())
    }

    fn get_exp(&self) -> Option<i64> {
        Some(self.exp)
    }

    fn is_not_before(&self) -> bool {
        false
    }
}

impl crate::Key for Key {
    fn verify(self, verify_targe: &str, signature: Vec<u8>) -> Result<bool, Error> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.inner)?;
        verifier.update(verify_targe.as_bytes())?;
        Ok(verifier.verify(&signature)?)
    }
}

impl crate::KeyFetcher for Auth0Fetcher {
    type Key = Key;
    fn fetch<H, P>(header: &H, payload: &P) -> Result<Self::Key, crate::Error>
    where
        H: crate::Header,
        P: crate::Payload,
    {
        let alg = header.get_alg().ok_or(ErrorKind::NotFoundHeaderItem {
            item: HeaderItem::ALG,
        })?;

        if alg != "RS256" {
            return Err(ErrorKind::DoesNotSupportAlgorithm {
                kind: AlgorithmKind::Others,
            }
            .into());
        }

        let kid = header.get_kid().ok_or(ErrorKind::NotFoundHeaderItem {
            item: HeaderItem::KID,
        })?;

        let url_path = std::path::Path::new(&payload.get_iss().ok_or(Error::from(
            ErrorKind::NotFoundPayloadItem {
                item: PayloadItem::ISS,
            },
        ))?)
        .join(".well-known")
        .join("jwks.json");
        let url = url_path.to_str().ok_or(ErrorKind::FetchFailed)?;

        let jwks = serde_json::from_str::<Jwks>(&reqwest::get(url)?.text()?)?;
        let key_string = jwks
            .keys
            .iter()
            .find(|x| x.kid == kid)
            .ok_or(ErrorKind::FetchFailed)?
            .x5c
            .iter()
            .next()
            .ok_or(ErrorKind::FetchFailed)?;
        let key_der = base64::decode(key_string)?;
        let key = openssl::x509::X509::from_der(key_der.as_ref())?.public_key()?;
        Ok(Key { inner: key })
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(origin: openssl::error::ErrorStack) -> Self {
        Error::new(origin.context(ErrorKind::OpenSSLError))
    }
}
