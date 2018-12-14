#[macro_use]
extern crate serde_derive;

mod decode;
mod error;
mod key;
mod jwks;
mod payload;

pub use self::error::{Error, ErrorKind};
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
            fn verify(self, _: &str, _: &str) -> Result<bool, crate::Error> {
                Ok(true)
            }
        }

        impl super::KeyFetcher for MyFetcher {
            type Key = MyKey;
            fn fetch<P>(_: P) -> Result<Self::Key, crate::Error> 
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
