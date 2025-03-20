use anyhow::{anyhow, Context, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::token::claims::Claims;
use crate::token::jwk::{Jwk, JwksResponse};

/// Formats for Azure AD tokens (v1 and v2 endpoints)
#[derive(Debug, Clone, Copy)]
pub enum AzureTokenFormat {
    V1,
    V2,
    Common,
}

impl fmt::Display for AzureTokenFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AzureTokenFormat::V1 => write!(f, "v1.0"),
            AzureTokenFormat::V2 => write!(f, "v2.0"),
            AzureTokenFormat::Common => write!(f, "common"),
        }
    }
}

/// Token validator configuration
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub tenant_id: String,
    pub validate_exp: bool,
    pub validate_aud: bool,
    pub validate_iss: bool,
    pub leeway: u64, // in seconds
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            tenant_id: "common".to_string(),
            validate_exp: true,
            validate_aud: false,
            validate_iss: true,
            leeway: 300, // 5 minutes
        }
    }
}

/// Azure AD token validator
pub struct TokenValidator {
    client: Client,
    jwks_cache: HashMap<String, JwksResponse>,
    config: ValidatorConfig,
}

impl TokenValidator {
    /// Creates a new token validator with the given configuration
    pub fn new(config: ValidatorConfig) -> Self {
        TokenValidator {
            client: Client::new(),
            jwks_cache: HashMap::new(),
            config,
        }
    }

    /// Gets the JWKS URI for the given format and tenant
    pub fn get_jwks_uri(&self, format: AzureTokenFormat) -> String {
        match format {
            AzureTokenFormat::V1 => {
                format!("https://login.microsoftonline.com/{}/discovery/keys", self.config.tenant_id)
            }
            AzureTokenFormat::V2 => {
                format!("https://login.microsoftonline.com/{}/discovery/v2.0/keys", self.config.tenant_id)
            }
            AzureTokenFormat::Common => {
                "https://login.microsoftonline.com/common/discovery/keys".to_string()
            }
        }
    }

    /// Determines the token format based on the issuer claim
    pub fn determine_token_format(&self, claims: &Claims) -> AzureTokenFormat {
        if claims.iss.contains("sts.windows.net") {
            AzureTokenFormat::V1
        } else if claims.iss.contains("/v2.0") {
            AzureTokenFormat::V2
        } else {
            AzureTokenFormat::Common
        }
    }

    /// Decodes a token without validation to inspect its claims
    pub fn decode_token(&self, token: &str) -> Result<(Value, Claims)> {
        let header = decode_header(token)?;

        // Just decode the payload without validating the signature
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(&[]),
            &{
                let mut validation = Validation::new(Algorithm::RS256);
                validation.insecure_disable_signature_validation();
                validation.validate_aud = false;
                validation.validate_exp = false;
                validation.validate_nbf = false;
                validation
            },
        )?;

        Ok((json!(header), token_data.claims))
    }

    /// Fetches JWKS from the given URI
    pub async fn fetch_jwks(&mut self, uri: &str) -> Result<JwksResponse> {
        let response = self.client.get(uri).send().await?;
        if !response.status().is_success() {
            return Err(anyhow!("Failed to fetch JWKS: {}", response.status()));
        }

        let jwks: JwksResponse = response.json().await?;
        self.jwks_cache.insert(uri.to_string(), jwks.clone());
        Ok(jwks)
    }

    /// Gets JWKS from cache or fetches if not cached
    pub async fn get_jwks(&mut self, uri: &str) -> Result<JwksResponse> {
        if let Some(jwks) = self.jwks_cache.get(uri) {
            return Ok(jwks.clone());
        }

        self.fetch_jwks(uri).await
    }

    /// Validates a token against Azure AD public keys
    pub async fn validate_token(&mut self, token: &str) -> Result<Claims> {
        let (header, claims) = self.decode_token(token)?;

        // Check expiration if configured to do so
        if self.config.validate_exp {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs();

            if claims.exp < now {
                return Err(anyhow!("Token has expired"));
            }
        }

        // Get kid from header
        let kid = header["kid"].as_str().context("Missing 'kid' in token header")?;

        // Get the appropriate JWKS URI
        let format = self.determine_token_format(&claims);
        let jwks_uri = self.get_jwks_uri(format);

        // Fetch JWKS
        let jwks = self.get_jwks(&jwks_uri).await?;
        let jwk = jwks.find_key(kid).context("Signing key not found in JWKS")?;
        let decoding_key = jwk.to_decoding_key()?;

        // Configure validation settings
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = self.config.validate_exp;
        validation.validate_aud = self.config.validate_aud;
        validation.leeway = self.config.leeway;

        // Set issuer validation if configured
        if self.config.validate_iss {
            validation.set_issuer(&[&claims.iss]);
        }

        // Validate token with proper signature verification
        let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
        Ok(token_data.claims)
    }
}