use serde::{Deserialize, Serialize};

/// Represents an active, authenticated user session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub user_id: String,
    pub email: String,
    pub access_token: String,
}

/// The Authentication Port. 
/// Adapters (like Rauthy or Local Dev) must implement this to handle logins.
pub trait AuthProvider {
    /// Initiates a login flow and returns an active session if successful.
    fn login(&self) -> Result<UserSession, String>;
    
    /// Refreshes an expired session token.
    fn refresh_session(&self, session: &UserSession) -> Result<UserSession, String>;
    
    /// Ends the session locally and remotely.
    fn logout(&self, session: &UserSession) -> Result<(), String>;
}