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
