use crate::{AuthError, Challenge, FlowState, LocalSession};

pub fn begin() -> Result<(Challenge, FlowState), AuthError> {
    Ok((
        Challenge { url: "Sign this: nonce_999".to_string() },
        FlowState { pkce_verifier: None, csrf_token: None, nonce: Some("nonce_999".to_string()) }
    ))
}

pub fn complete(_flow: FlowState, _proof: &str) -> Result<LocalSession, AuthError> {
    Ok(LocalSession {
        user_id: "0xAbCd...".to_string(),
        provider: "web3".to_string(),
        access_token: None,
        refresh_token: None,
        expires_at: 2000000000,
    })
}