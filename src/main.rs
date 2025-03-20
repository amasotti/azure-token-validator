mod api;
mod token;

use anyhow::Result;
use clap::Parser;
use std::io::{self, Write};

use api::GraphClient;
use token::{Claims, TokenType, TokenValidator, ValidatorConfig};

/// Azure AD Token Validator CLI
#[derive(Parser)]
#[command(
    name = "azure-token-validator",
    author,
    version,
    about = "Validates and inspects Azure AD JWT tokens",
    long_about = None
)]
struct Cli {
    /// JWT token to validate (if not provided, will prompt for input)
    token: Option<String>,

    /// Azure AD tenant ID (defaults to 'common')
    #[arg(long, default_value = "common")]
    tenant: String,

    /// Skip token expiration check
    #[arg(long)]
    skip_expiration: bool,

    /// Test Microsoft Graph API with the token
    #[arg(long)]
    test_graph: bool,

    /// Custom Graph API endpoint to call (requires --test-graph)
    #[arg(long)]
    endpoint: Option<String>,
}

/// Displays token information in a structured way
fn display_token_info(claims: &Claims) {
    println!("\n=== Token Information ===");
    println!("Token type: {}", claims.token_type());
    println!("Issuer: {}", claims.iss);
    println!("Audience: {}", claims.audience_display());

    // Display timestamps
    println!("Not before: {}", Claims::format_timestamp(claims.nbf));
    println!("Issued at: {}", Claims::format_timestamp(claims.iat));
    println!("Expiration: {}", Claims::format_timestamp(claims.exp));

    // Display common claims if present
    if let Some(name) = &claims.name {
        println!("Name: {}", name);
    }

    if let Some(email) = &claims.email {
        println!("Email: {}", email);
    }

    if let Some(username) = &claims.preferred_username {
        println!("Username: {}", username);
    }

    if let Some(appid) = &claims.appid {
        println!("App ID: {}", appid);
    }

    if let Some(scope) = &claims.scp {
        println!("Scope: {}", scope);
    }

    // Display additional claims
    if !claims.extra.is_empty() {
        println!("\n=== Additional Claims ===");
        for (key, value) in &claims.extra {
            println!("{}: {}", key, value);
        }
    }
}

/// Prompts the user to enter a token
fn prompt_for_token() -> Result<String> {
    print!("Enter token: ");
    io::stdout().flush()?;

    let mut token = String::new();
    io::stdin().read_line(&mut token)?;

    Ok(token.trim().to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    // Get token from args or prompt
    let token = match args.token {
        Some(t) => t,
        None => prompt_for_token()?,
    };

    // Configure the validator
    let config = ValidatorConfig {
        tenant_id: args.tenant,
        validate_exp: !args.skip_expiration,
        validate_aud: false, // Always disable audience validation for this tool
        validate_iss: true,
        leeway: 300, // 5 minutes
    };

    let mut validator = TokenValidator::new(config);

    // First decode without validation to display token info
    match validator.decode_token(&token) {
        Ok((_, claims)) => {
            display_token_info(&claims);

            println!("\n=== Validation Result ===");
            match validator.validate_token(&token).await {
                Ok(_) => println!("✅ Token signature is valid"),
                Err(e) => println!("❌ Token validation failed: {}", e),
            }

            // Run Graph API test if requested
            if args.test_graph && claims.token_type() == TokenType::Access {
                println!("\n=== Graph API Test ===");
                let graph_client = GraphClient::new();

                if let Some(endpoint) = args.endpoint {
                    match graph_client.call_endpoint(&token, &endpoint).await {
                        Ok(response) => println!("Graph API response: {}", response),
                        Err(e) => println!("❌ Graph API test failed: {}", e),
                    }
                } else {
                    match graph_client.get_me(&token).await {
                        Ok(user_info) => println!("Graph API response: {}", user_info),
                        Err(e) => println!("❌ Graph API test failed: {}", e),
                    }
                }
            } else if args.test_graph && claims.token_type() != TokenType::Access {
                println!("\n⚠️  Warning: Cannot test Graph API with an ID token. You need an access token.");
            }
        }
        Err(e) => println!("❌ Failed to decode token: {}", e),
    }

    Ok(())
}
