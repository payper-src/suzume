#[macro_use]
extern crate serde_derive;

mod auth0;
mod decode;
mod error;
mod header;
mod jwks;
mod key;
mod payload;

pub use self::auth0::{Auth0Fetcher, Auth0Header, Auth0Payload};
use self::decode::from_raw_jwt;
pub use self::error::{AlgorithmKind, Error, ErrorKind, HeaderItem, PayloadItem};
pub use self::header::Header;
pub use self::jwks::{Jwk, Jwks};
pub use self::key::{Key, KeyFetcher};
pub use self::payload::Payload;

pub fn verify<H, P, F>(jwt: String) -> Result<P, Error>
where
    H: Header + serde::de::DeserializeOwned,
    P: Payload + serde::de::DeserializeOwned,
    F: KeyFetcher,
{
    let (header, payload, (plain, signature)) = from_raw_jwt::<H, P>(&jwt)?;

    if payload.is_expired() {
        return Err(ErrorKind::ExpiredToken.into());
    }

    if payload.is_not_before() {
        return Err(ErrorKind::NotBefore.into());
    }

    let key = F::fetch(&header, &payload)?;
    if key.verify(plain, signature)? {
        Ok(payload)
    } else {
        Err(ErrorKind::ValidationFail.into())
    }
}

#[cfg(test)]
mod tests {
    // use crate::JwksFetcher;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn verify_success() -> Result<(), failure::Error> {
        #[derive(Debug, Serialize, Deserialize)]
        struct MyHeader {
            som: String,
        }

        impl crate::Header for MyHeader {}

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct MyPayload {
            iss: String,
            exp: i64,
        }

        impl crate::Payload for MyPayload {
            fn get_exp(&self) -> Option<i64> {
                Some(self.exp)
            }

            fn is_not_before(&self) -> bool {
                false
            }
        }

        struct MyFetcher;

        struct MyKey;

        impl super::Key for MyKey {
            fn verify(self, _: &str, _: Vec<u8>) -> Result<bool, crate::Error> {
                Ok(true)
            }
        }

        impl super::KeyFetcher for MyFetcher {
            type Key = MyKey;
            fn fetch<H, P>(self, _: &H, _: &P) -> Result<Self::Key, crate::Error> {
                Ok(MyKey)
            }
        }

        let my_header = MyHeader {
            som: "Something".to_owned(),
        };

        let my_payload = MyPayload {
            iss: "https://example.com".to_owned(),
            exp: time::now_utc().to_timespec().sec + time::Duration::days(1).num_seconds(),
        };

        let jwt = {
            let encoded_h = {
                let json = serde_json::to_string(&my_header)?;
                base64::encode_config(&json, base64::URL_SAFE_NO_PAD)
            };
            let encoded_p = {
                let json = serde_json::to_string(&my_payload)?;
                base64::encode_config(&json, base64::URL_SAFE_NO_PAD)
            };
            format!("{}.{}.", encoded_h, encoded_p)
        };

        let payload = super::verify::<MyHeader, MyPayload, MyFetcher>(jwt)?;
        assert_eq!(payload, my_payload);

        Ok(())
    }

    #[test]
    fn verify_self_signed_jwt() -> Result<(), failure::Error> {
        use openssl::hash::MessageDigest;
        use openssl::pkey::{self, PKey};
        use openssl::sign::Verifier;

        #[derive(Debug, Serialize, Deserialize)]
        struct MyHeader {
            typ: String,
            alg: String,
        }

        impl crate::Header for MyHeader {}

        #[derive(Debug, Serialize, Deserialize)]
        struct MyPayload {
            sub: String,
            iat: i64,
            exp: i64,
            azp: String,
            scope: String,
        }

        impl crate::Payload for MyPayload {
            fn is_expired(&self) -> bool {
                false
            }

            fn is_not_before(&self) -> bool {
                false
            }
        }

        struct RSAPublicKey {
            inner: PKey<pkey::Public>,
        };

        impl RSAPublicKey {
            fn new() -> Result<Self, crate::Error> {
                let crt = include_str!("test_files/example.crt");
                let key = openssl::x509::X509::from_pem(crt.as_ref())?.public_key()?;
                Ok(RSAPublicKey { inner: key })
            }
        }

        impl crate::Key for RSAPublicKey {
            fn verify(self, verify_target: &str, signature: Vec<u8>) -> Result<bool, crate::Error> {
                let mut verifier = Verifier::new(MessageDigest::sha256(), &self.inner)?;
                verifier.update(verify_target.as_bytes())?;
                Ok(verifier.verify(&signature)?)
            }
        }

        struct MyFetcher;

        impl crate::KeyFetcher for MyFetcher {
            type Key = RSAPublicKey;
            fn fetch<H, P>(_header: &H, _payload: &P) -> Result<Self::Key, crate::Error>
            where
                H: crate::Header,
                P: crate::Payload,
            {
                Ok(RSAPublicKey::new()?)
            }
        }

        let valid_self_signed_jwt = include_str!("test_files/example_jwt").trim();

        let _ = crate::verify::<MyHeader, MyPayload, MyFetcher>(valid_self_signed_jwt.to_owned())?;

        Ok(())
    }

    #[test]
    fn fetch_test() {
        // let fetcher = super::MyJwksFetcher {};
        // match fetcher.fetch("https://payper.auth0.com/.well-known/jwks.json".to_owned()) {
        //     Ok(value) => {
        //         println!("{:?}", value);
        //     }
        //     Err(err) => {
        //         println!("{:?}", err);
        //     }
        // }
    }
}
