/// Json web key type.
#[derive(Deserialize, Debug)]
pub struct Jwk {
    /// what to use
    #[serde(rename = "use")]
    pub use_: String,
    /// used algorithm
    pub alg: String,
    /// key type
    pub kty: String,
    /// X.509 Certificate Chain
    pub x5c: Vec<String>,
    /// value n about encryption
    pub n: String,
    /// value e about encryption
    pub e: String,
    /// key id
    pub kid: String,
    /// X.509 Certificate SHA-1 Thumbprint
    pub x5t: String,
}

/// Json web key set type
#[derive(Deserialize, Debug)]
pub struct Jwks {
    /// json web keys
    pub keys: Vec<Jwk>,
}
