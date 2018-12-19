/// Json web key type.
#[derive(Deserialize, Debug)]
pub struct Jwk {
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
    pub kty: String,
    pub x5c: Vec<String>,
    pub n: String,
    pub e: String,
    pub kid: String,
    pub x5t: String,
}

/// Json web key set type
#[derive(Deserialize, Debug)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}
