use crate::{AuthError, Challenge, FlowState, LocalSession};
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::ureq::http_client;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, 
    Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, OAuth2TokenResponse, TokenResponse
};
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;

// Default to 8080, but allow OS to override if needed later
const REDIRECT_URL: &str = "http://127.0.0.1:8080";

fn build_client() -> Result<CoreClient, AuthError> {
    // Pull from OS Environment Variables
    let rauthy_url = env::var("MOR_RAUTHY_URL")
        .unwrap_or_else(|_| "http://localhost:8080/auth/v1".to_string());
    let client_id_str = env::var("MOR_CLIENT_ID")
        .unwrap_or_else(|_| "moribund_lms".to_string());

    let issuer_url = IssuerUrl::new(rauthy_url)
        .map_err(|_| AuthError::NetworkFailure)?;
        
    let provider_metadata = CoreProviderMetadata::discover(&issuer_url, http_client)
        .map_err(|_| AuthError::NetworkFailure)?;
        
    let client_id = ClientId::new(client_id_str);
    
    let redirect_url = RedirectUrl::new(REDIRECT_URL.to_string())
        .map_err(|_| AuthError::NetworkFailure)?;

    Ok(CoreClient::from_provider_metadata(provider_metadata, client_id, None)
        .set_redirect_uri(redirect_url))
}

pub fn begin() -> Result<(Challenge, FlowState), AuthError> {
    let client = build_client()?;

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    
    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    Ok((
        Challenge {
            url: auth_url.to_string(),
        },
        FlowState {
            pkce_verifier: Some(pkce_verifier.secret().to_string()),
            csrf_token: Some(csrf_token.secret().to_string()),
            nonce: Some(nonce.secret().to_string()),
        }
    ))
}

pub fn complete(flow: FlowState, returned_state: Option<&str>, proof: &str) -> Result<LocalSession, AuthError> {
    // 1. Verify CSRF State
    let expected_csrf = flow.csrf_token.ok_or(AuthError::StateMismatch)?;
    if expected_csrf.as_str() != returned_state.unwrap_or("") {
        return Err(AuthError::StateMismatch);
    }

    let client = build_client()?;
    let code = AuthorizationCode::new(proof.to_string());
    let pkce_secret = flow.pkce_verifier.ok_or(AuthError::StateMismatch)?;
    let pkce_verifier = PkceCodeVerifier::new(pkce_secret);

    // 2. Trade Code + Verifier for Tokens
    let token_response = client
        .exchange_code(code)
        .set_pkce_verifier(pkce_verifier)
        .request(http_client)
        .map_err(|_| AuthError::NetworkFailure)?;

    // 3. Extract and Verify ID Token (Closes the security hole)
    let id_token = token_response.id_token().ok_or(AuthError::InvalidSignature)?;
    let expected_nonce = Nonce::new(flow.nonce.unwrap_or_default());
    
    // Cryptographically verify the token against Rauthy's public keys
    let claims = id_token
        .claims(&client.id_token_verifier(), &expected_nonce)
        .map_err(|_| AuthError::InvalidSignature)?;

    // Extract the true subject (user ID) from the verified token
    let real_user_id = claims.subject().as_str().to_string();

    let access_token = token_response.access_token().secret().to_string();
    let refresh_token = token_response.refresh_token().map(|t| t.secret().to_string());
    
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let expires_in = token_response.expires_in().map(|d| d.as_secs()).unwrap_or(3600);

    Ok(LocalSession {
        user_id: real_user_id,
        provider: "oidc".to_string(),
        access_token: Some(access_token),
        refresh_token,
        expires_at: now + expires_in, 
    })
}