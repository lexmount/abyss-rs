//! PKCE and state material for terminal SSO attempts.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore as _;
use sha2::{Digest, Sha256};

const RANDOM_BYTES: usize = 32;

/// Random state and PKCE material for one terminal SSO attempt.
pub struct TerminalLoginMaterial {
    state: String,
    code_verifier: String,
    code_challenge: String,
}

impl TerminalLoginMaterial {
    /// Generates backend-compatible state, code verifier, and S256 challenge.
    #[must_use]
    pub fn generate() -> Self {
        let state = random_url_safe();
        let code_verifier = random_url_safe();
        let code_challenge = code_challenge_for_verifier(&code_verifier);
        Self {
            state,
            code_verifier,
            code_challenge,
        }
    }

    /// Returns the OAuth state value sent to the control plane.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Returns the PKCE code verifier retained locally for polling.
    #[must_use]
    pub fn code_verifier(&self) -> &str {
        &self.code_verifier
    }

    /// Returns the S256 PKCE challenge sent when creating the login attempt.
    #[must_use]
    pub fn code_challenge(&self) -> &str {
        &self.code_challenge
    }
}

/// Calculates a base64url S256 PKCE challenge for a code verifier.
#[must_use]
pub fn code_challenge_for_verifier(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn random_url_safe() -> String {
    let mut bytes = [0_u8; RANDOM_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::{TerminalLoginMaterial, code_challenge_for_verifier};

    #[test]
    fn pkce_challenge_matches_rfc_vector() {
        let challenge = code_challenge_for_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        assert_eq!(
            challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "PKCE S256 challenge should match RFC 7636"
        );
    }

    #[test]
    fn generated_login_material_is_backend_compatible() {
        let material = TerminalLoginMaterial::generate();

        for value in [
            material.state(),
            material.code_verifier(),
            material.code_challenge(),
        ] {
            assert!(
                value.len() >= 43 && value.len() <= 128,
                "terminal login value should fit backend PKCE validation"
            );
            assert!(
                value.bytes().all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~')),
                "terminal login value should be URL-safe"
            );
        }
    }
}
