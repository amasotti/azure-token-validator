use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

/// Represents the claims in an Azure AD JWT token
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: Value,
    pub exp: u64,
    pub iat: u64,
    pub nbf: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scp: Option<String>,
    // Additional fields that might be present
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl Claims {
    /// Determines if this token is an access token or ID token based on the audience
    pub fn token_type(&self) -> TokenType {
        // Microsoft Graph API ID
        const GRAPH_API_ID: &str = "00000003-0000-0000-c000-000000000000";

        if let Value::String(aud) = &self.aud {
            if aud == GRAPH_API_ID {
                return TokenType::Access;
            }
        }
        TokenType::Id
    }

    /// Gets a formatted display of the audience claim
    pub fn audience_display(&self) -> String {
        match &self.aud {
            Value::String(aud) => aud.clone(),
            Value::Array(auds) => serde_json::to_string(auds).unwrap_or_else(|_| "Error formatting".to_string()),
            _ => "Unknown format".to_string(),
        }
    }

    /// Formats a timestamp as human-readable date/time
    pub fn format_timestamp(timestamp: u64) -> String {
        match chrono::DateTime::from_timestamp(timestamp as i64, 0) {
            Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            None => format!("{} (invalid timestamp)", timestamp),
        }
    }
}

/// Represents the type of token
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Access,
    Id,
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenType::Access => write!(f, "access_token"),
            TokenType::Id => write!(f, "id_token"),
        }
    }
}