use serde::{Deserialize, Serialize};

// Connect the new files
pub mod oidc;
pub mod steam;
pub mod web3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSession {
    pub user_id: String,
    pub provider: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: u64,
}

#[derive(Debug)]
pub enum AuthError {
    NetworkFailure,
    InvalidSignature,
    StateMismatch,
    UserCancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowState {
    pub pkce_verifier: Option<String>,
    pub csrf_token: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub url: String, 
}

pub enum Provider {
    Oidc,
    Web3,
    Steam,
}

impl Provider {
    pub fn begin(&self) -> Result<(Challenge, FlowState), AuthError> {
        match self {
            Provider::Oidc => oidc::begin(),
            Provider::Web3 => web3::begin(),
            Provider::Steam => steam::begin(),
        }
    }

    pub fn complete(&self, flow: FlowState, returned_state: Option<&str>, proof: &str) -> Result<LocalSession, AuthError> {
        match self {
            Provider::Oidc => oidc::complete(flow, returned_state, proof),
            Provider::Web3 => web3::complete(flow, proof),
            Provider::Steam => steam::complete(flow, proof),
        }
    }
}