use lms_core::auth::{AuthProvider, UserSession};
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    RedirectUrl, Scope, OAuth2TokenResponse,
};
use std::io::{Read, Write};
use std::net::TcpListener;

// Import the ureq HTTP client
use openidconnect::ureq::http_client;

pub struct RauthyAuthProvider {
    issuer_url: String,
    client_id: String,
    redirect_url: String,
}

impl RauthyAuthProvider {
    pub fn new(issuer: &str, client_id: &str, redirect: &str) -> Self {
        Self {
            issuer_url: issuer.to_string(),
            client_id: client_id.to_string(),
            redirect_url: redirect.to_string(),
        }
    }

    fn build_client(&self) -> Result<CoreClient, String> {
        let issuer_url = IssuerUrl::new(self.issuer_url.clone())
            .map_err(|e| format!("Invalid issuer URL: {}", e))?;

        // Uses the ureq http_client
        let provider_metadata = CoreProviderMetadata::discover(
            &issuer_url,
            http_client,
        ).map_err(|e| format!("Failed to discover Rauthy metadata: {:?}", e))?;

        let client_id = ClientId::new(self.client_id.clone());
        let redirect_url = RedirectUrl::new(self.redirect_url.clone())
            .map_err(|e| format!("Invalid redirect URL: {}", e))?;

        Ok(CoreClient::from_provider_metadata(
            provider_metadata,
            client_id,
            None,
        )
        .set_redirect_uri(redirect_url))
    }
}

impl AuthProvider for RauthyAuthProvider {
    fn login(&self) -> Result<UserSession, String> {
        let client = self.build_client()?;

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, _csrf_token, _nonce) = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        println!("Please log in via your browser:");
        println!("{}", auth_url);

        let listener = TcpListener::bind("127.0.0.1:8080")
            .map_err(|e| format!("Could not bind to local port 8080: {}", e))?;

        let mut auth_code = String::new();

        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                let mut buffer = [0; 2048];
                stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..]);

                if let Some(code_start) = request.find("code=") {
                    let code_end = request[code_start..].find(' ').unwrap_or(request.len());
                    auth_code = request[code_start + 5..code_start + code_end].to_string();
                    
                    let response = "HTTP/1.1 200 OK\r\n\r\n<html><body><h2>Login Successful! You can close this tab and return to Moribund.</h2></body></html>";
                    stream.write_all(response.as_bytes()).unwrap();
                    break;
                }
            }
        }

        let token_response = client
            .exchange_code(AuthorizationCode::new(auth_code))
            .set_pkce_verifier(pkce_verifier)
            .request(http_client) // Uses the ureq http_client here as well
            .map_err(|e| format!("Failed to exchange code for token: {:?}", e))?;

        let access_token = token_response.access_token().secret().to_string();

        Ok(UserSession {
            user_id: "rauthed_user_123".to_string(), 
            email: "scholar@moribund.edu".to_string(),
            access_token,
        })
    }

    fn refresh_session(&self, _session: &UserSession) -> Result<UserSession, String> {
        Err("Not yet implemented".to_string())
    }

    fn logout(&self, _session: &UserSession) -> Result<(), String> {
        Ok(())
    }
}