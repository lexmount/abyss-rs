//! Deterministic identifiers for normalized Agent events.

use sha2::{Digest, Sha256};

/// Builds a stable backend event id from deterministic identity fields.
#[must_use]
pub fn stable_event_id<'a, I>(parts: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(b"\0");
    }
    format!("evt_{}", hex::encode(hasher.finalize())[..32].to_owned())
}

#[cfg(test)]
mod tests {
    use super::stable_event_id;

    #[test]
    fn event_id_is_prefixed_and_deterministic() {
        assert_eq!(stable_event_id(["a", "b"]), stable_event_id(["a", "b"]));
        assert!(stable_event_id(["a", "b"]).starts_with("evt_"));
    }
}
