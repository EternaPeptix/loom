//! Identifiers. All are opaque strings on the wire.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }
        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
    };
}

id!(SessionId, "One agent session (`s-…`). Every agent, including a child, is a session.");
id!(MissionId, "One goal and the sessions pursuing it (`m-…`). Sessions in a mission share a ledger.");
id!(CallId, "One tool call, unique within its session.");
id!(BlobId, "Lowercase hex SHA-256 of a stored output.");

const ALPHABET: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Time-sortable id body: 9 chars of millisecond time + 7 random chars (Crockford-style base32).
fn sortable(now_ms: u64) -> String {
    use rand::Rng;
    let mut out = String::with_capacity(16);
    for shift in (0..9).rev() {
        out.push(ALPHABET[((now_ms >> (shift * 5)) & 31) as usize] as char);
    }
    let mut rng = rand::rng();
    for _ in 0..7 {
        out.push(ALPHABET[rng.random_range(0..32)] as char);
    }
    out
}

impl SessionId {
    pub fn generate() -> Self {
        Self(format!("s-{}", sortable(crate::now_ms())))
    }
}

impl MissionId {
    pub fn generate() -> Self {
        Self(format!("m-{}", sortable(crate::now_ms())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_prefixed() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert_ne!(a, b);
        assert!(a.as_str().starts_with("s-"));
        assert_eq!(a.as_str().len(), 18);
        assert!(MissionId::generate().as_str().starts_with("m-"));
    }

    #[test]
    fn ids_serialize_as_plain_strings() {
        let id = CallId::from("c1");
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"c1\"");
    }
}
