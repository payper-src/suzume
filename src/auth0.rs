//! # For Auth0 settings
//!
//! ```no_run
//! use suzume::{verify, Auth0Header, Auth0Payload, Auth0Fetcher, Auth0JwksFetcher};
//!
//! struct ReqwestFetcher;
//!
//! impl Auth0JwksFetcher for ReqwestFetcher {
//!     fn fetch(self, url: String) -> Result<String, failure::Error> {
//!         Ok(reqwest::get(&url)?.text()?)
//!     }
//! }
//!
//! fn main() -> Result<(), failure::Error> {
//!     verify::<Auth0Header, Auth0Payload, _>("some.jwt.string".to_owned(), Auth0Fetcher {
//!         issuers: vec!["your jwks issuer"],
//!         jwks_fetcher: ReqwestFetcher,
//!     })?;
//!     Ok(())
//! }
//! ```
//!

use crate::{AlgorithmKind, Error, ErrorKind, HeaderItem, Jwks, PayloadItem};
use failure::Fail;
use openssl::hash::MessageDigest;
use openssl::pkey::{self, PKey};
use openssl::sign::Verifier;

pub trait Auth0JwksFetcher {
    fn fetch(self, url: String) -> Result<String, failure::Error>;
}

pub struct Auth0Fetcher<'a, JF>
where
    JF: Auth0JwksFetcher,
{
    pub issuers: Vec<&'a str>,
    pub jwks_fetcher: JF,
}

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

impl<'a, JF> crate::KeyFetcher for Auth0Fetcher<'a, JF>
where
    JF: Auth0JwksFetcher,
{
    type Key = Key;
    fn fetch<H, P>(self, header: &H, payload: &P) -> Result<Self::Key, crate::Error>
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

        let iss = payload.get_iss().ok_or(ErrorKind::NotFoundPayloadItem {
            item: PayloadItem::ISS,
        })?;

        if !self.issuers.contains(&iss.as_str()) {
            return Err(ErrorKind::NotExpectedIssuer.into());
        }

        let url_path = std::path::Path::new(&iss)
            .join(".well-known")
            .join("jwks.json");
        let url = url_path.to_str().ok_or(ErrorKind::FetchFailed)?;

        let jwks = serde_json::from_str::<Jwks>(&self.jwks_fetcher.fetch(url.to_owned())?)?;
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
