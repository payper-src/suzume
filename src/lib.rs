#[macro_use]
extern crate serde_derive;

mod decode;
mod error;
mod fetcher;

pub use self::error::{Error, ErrorKind};
pub use self::fetcher::{Jwks, JwksFetcher};
pub use self::decode::{from_raw_jwt};

pub fn verify<'a, P>(jwt: String) -> Result<P, Error>
where
    P: serde::Deserialize<'a>,
{
    serde_json::from_str("{\"iss\": \"hoge\"}").map_err(Into::into)
}

#[cfg(test)]
mod tests {
    // use crate::JwksFetcher;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn verify_test() {
        #[derive(Deserialize)]
        struct MyPayload {
            iss: String,
        }

        match super::verify::<MyPayload>("aaa".to_owned()) {
            Ok(payload) => println!("{}", payload.iss),
            Err(err) => panic!("{:?}", err),
        }
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
