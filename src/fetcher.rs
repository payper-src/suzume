use super::Error;

/// Json web key type.
#[derive(Deserialize, Debug)]
pub struct Jwk {
    #[serde(rename = "use")]
    use_: String,
    alg: String,
    kty: String,
    x5c: Vec<String>,
    n: String,
    e: String,
    kid: String,
    x5t: String,
}

/// Json web key set type
#[derive(Deserialize, Debug)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

/// Jwks fetch client trait.
///
/// ## Example
/// This example is reference implementation by `reqwest`.
///
/// ```
/// extern crate suzume;
///
/// use suzume::{Jwks, JwksFetcher};
///
/// struct ReqwestFetcher {}
///
/// impl JwksFetcher for ReqwestFetcher {
///     fn fetch(&self, url: String) -> Result<Jwks, suzume::Error> {
///         match reqwest::get(&url).map_err(Into::into) {
///             Ok(mut resp) => resp.json::<Jwks>().map_err(Into::into),
///             Err(err) => return Err(err),
///         }
///     }
/// }
/// ```
pub trait JwksFetcher {
    /// Fetch jwks from `url`.
    fn fetch(&self, url: String) -> Result<Jwks, Error>;
}

#[cfg(test)]
mod tests {}
