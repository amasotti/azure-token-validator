use anyhow::Result;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;

/// Represents a JSON Web Key from Azure AD
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    #[serde(rename = "use")]
    pub usage: Option<String>,
    pub n: String,
    pub e: String,
}

impl Jwk {
    /// Converts a JWK to a DecodingKey for token validation
    pub fn to_decoding_key(&self) -> Result<DecodingKey> {
        // jsonwebtoken's from_rsa_components expects the raw base64 strings from the JWK
        Ok(DecodingKey::from_rsa_components(&self.n, &self.e)?)
    }
}

/// Represents a response from a JWKS endpoint
#[derive(Debug, Deserialize, Clone)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

impl JwksResponse {
    /// Finds a key by its ID (kid)
    pub fn find_key(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|key| key.kid == kid)
    }
}
