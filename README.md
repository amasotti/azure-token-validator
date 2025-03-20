# Azure Token Validator

A command-line utility for validating and inspecting Azure AD JWT tokens.

## Features

- Decode and display token claims
- Validate token signatures using Azure AD JWKS endpoints
- Test tokens against Microsoft Graph API
- Support for both v1.0 and v2.0 Azure AD tokens
- Support for ID tokens and access tokens

## Installation

### From Source

```bash
git clone https://github.com/yourusername/azure-token-validator.git
cd azure-token-validator
cargo build --release
```

The binary will be available at `target/release/azure-token-validator`.

## Usage

### Basic Usage

```bash
# Validate a token (will prompt for input if not provided)
azure-token-validator

# Validate a token passed as an argument
azure-token-validator eyJ0eXAiOiJKV...

# Validate a token for a specific tenant
azure-token-validator --tenant 00000000-0000-0000-0000-000000000000 eyJ0eXAiOiJKV...
```

### Options

```
--tenant <TENANT>      Azure AD tenant ID (defaults to 'common')
--skip-expiration      Skip token expiration check
--test-graph           Test Microsoft Graph API with the token
--endpoint <ENDPOINT>  Custom Graph API endpoint to call (requires --test-graph)
--help                 Print help
--version              Print version
```

### Examples

```bash
# Validate a token and test it against Graph API
azure-token-validator --test-graph eyJ0eXAiOiJKV...

# Skip expiration check (useful for testing expired tokens)
azure-token-validator --skip-expiration eyJ0eXAiOiJKV...

# Test a specific Graph API endpoint
azure-token-validator --test-graph --endpoint users eyJ0eXAiOiJKV...
```

## Output

The tool provides detailed information about the token:

```
=== Token Information ===
Token type: access_token
Issuer: https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0
Audience: 00000003-0000-0000-c000-000000000000
Not before: 2023-09-01 12:34:56 UTC
Issued at: 2023-09-01 12:34:56 UTC
Expiration: 2023-09-01 13:34:56 UTC
Name: John Doe
Email: john.doe@example.com
Username: john.doe@example.com
Scope: User.Read profile openid email

=== Additional Claims ===
tid: 00000000-0000-0000-0000-000000000000
...

=== Validation Result ===
✅ Token signature is valid

=== Graph API Test ===
Graph API response: {"displayName":"John Doe",...}
```

## Related Resources:

- [Azure OIDC Troubleshooting](https://github.com/gary-archer/oauth.blog/blob/master/public/posts/azure-ad-troubleshooting.mdx)
- [Microsoft - Token and Claims Overview](https://learn.microsoft.com/en-us/entra/identity-platform/security-tokens)