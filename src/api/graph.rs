use anyhow::{anyhow, Result};
use reqwest::{header, Client};
use serde_json::Value;

/// Microsoft Graph API client
pub struct GraphClient {
    client: Client,
}

impl GraphClient {
    /// Creates a new Graph API client
    pub fn new() -> Self {
        GraphClient {
            client: Client::new(),
        }
    }

    /// Calls the /me endpoint to get user information
    pub async fn get_me(&self, token: &str) -> Result<Value> {
        let response = self
            .client
            .get("https://graph.microsoft.com/v1.0/me")
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .header(header::ACCEPT, "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Graph API error: {}", response.status()));
        }

        Ok(response.json().await?)
    }

    /// Calls a custom Graph API endpoint
    pub async fn call_endpoint(&self, token: &str, endpoint: &str) -> Result<Value> {
        let url = if endpoint.starts_with("https://") {
            endpoint.to_string()
        } else {
            format!(
                "https://graph.microsoft.com/v1.0/{}",
                endpoint.trim_start_matches('/')
            )
        };

        let response = self
            .client
            .get(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .header(header::ACCEPT, "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Graph API error: {} - {}", response.status(), url));
        }

        Ok(response.json().await?)
    }
}
