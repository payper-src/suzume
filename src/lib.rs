#[macro_use]
extern crate serde_derive;

mod decode;
mod error;
mod key;
mod jwks;
mod payload;

pub use self::error::{Error, ErrorKind, PayloadItem};
pub use self::key::{Key, KeyFetcher};
pub use self::jwks::{Jwk, Jwks};
pub use self::payload::{Payload};
use self::decode::{from_raw_jwt};

pub fn verify<H, P, F>(jwt: String) -> Result<P, Error>
where
    H: serde::de::DeserializeOwned,
    P: Payload + serde::de::DeserializeOwned,
    F: KeyFetcher,
{
    let (_header, payload, (plain, signature)) = from_raw_jwt::<H, P>(&jwt)?;

    if payload.is_expired() {
        return Err(ErrorKind::ExpiredToken.into())
    }

    if payload.is_not_before() {
        return Err(ErrorKind::NotBefore.into())
    }

    let key = F::fetch(&payload)?;
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
    fn verify_success() -> Result<(), failure::Error>{
        #[derive(Debug, Serialize, Deserialize)]
        struct MyHeader {
            som: String,
        }

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
            fn fetch<P>(_: &P) -> Result<Self::Key, crate::Error> 
            { Ok(MyKey)
            }
        }

        let my_header = MyHeader {
            som: "Something".to_owned(),
        };

        let my_payload = MyPayload {
            iss: "https://example.com".to_owned(),
            exp: time::now_utc().to_timespec().sec + time::Duration::days(1).num_seconds()
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
    fn verify_auth0_jwt() -> Result<(), failure::Error>{
        use openssl::pkey::{self, PKey};
        use openssl::hash::MessageDigest;
        use openssl::sign::{Verifier};
        use failure::Fail;

        #[derive(Debug, Serialize, Deserialize)]
        struct Auth0Header {
            typ: String,
            alg: String,
            kid: String,
        }

        #[derive(Debug, Serialize, Deserialize)]
        struct Auth0Payload {
            iss: String,
            sub: String,
            aud: String,
            iat: i64,
            exp: i64,
            azp: String,
            scope: String,
        }

        impl crate::Payload for Auth0Payload {
            fn get_iss(&self) -> Option<String> {
                Some(self.iss.clone())
            }
        }

        struct RSAPublicKey {
            inner: PKey<pkey::Public>
        };

        impl RSAPublicKey {
            fn new(iss: String) -> Result<Self, crate::Error> {
                let url = std::path::Path::new(&iss).join(".well-known").join("jwks.json");
                let jwks = reqwest::get(url.to_str().unwrap())?.json::<crate::Jwks>()?;
                let key = {
                    let x509_auth = base64::decode(jwks.keys.iter().next().ok_or(crate::Error::from(crate::ErrorKind::NotFoundJwks))?.x5c.iter().next().ok_or(crate::Error::from(crate::ErrorKind::NotFoundx5c))?)?;
                    openssl::x509::X509::from_der(x509_auth.as_ref())?
        .public_key()?
                };
                Ok(
                RSAPublicKey {
                    inner: key,
                })
            }
        }

        impl crate::Key for RSAPublicKey {
            fn verify(self, verify_target: &str, signature: Vec<u8>) -> Result<bool, crate::Error> {
                let mut verifier = Verifier::new(MessageDigest::sha256(), &self.inner)?;
                verifier.update(verify_target.as_bytes())?;
                Ok(verifier.verify(&signature)?)
            }
        }

        struct Auth0Fetcher;

        impl crate::KeyFetcher for Auth0Fetcher {
            type Key = RSAPublicKey;
            fn fetch<P>(payload: &P) -> Result<Self::Key, crate::Error> 
            where
                P: crate::Payload,
            {
                if let Some(iss) = payload.get_iss() {
                    Ok(RSAPublicKey::new(iss)?)
                } else {
                    Err(crate::ErrorKind::NotFoundItem {
                        item: crate::PayloadItem::ISS,
                    }.into())
                }
            }
        }

        impl From<openssl::error::ErrorStack> for crate::Error {
            fn from(origin: openssl::error::ErrorStack) -> crate::Error {
                crate::Error::new(origin.context(crate::ErrorKind::OpenSSLError))
            }
        }

        let valid_auth0_jwt = include_str!("test_files/valid_auth0_jwt").trim();

        let _ = crate::verify::<Auth0Header, Auth0Payload, Auth0Fetcher>(valid_auth0_jwt.to_owned())?;

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
