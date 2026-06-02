use crate::{AuthError, Challenge, FlowState, LocalSession};

pub fn begin() -> Result<(Challenge, FlowState), AuthError> {
    Err(AuthError::NetworkFailure)
}

pub fn complete(_flow: FlowState, _proof: &str) -> Result<LocalSession, AuthError> {
    Err(AuthError::NetworkFailure)
}