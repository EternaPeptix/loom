//! Guard that a session's request prefix only grows.
//!
//! The server caches by prefix, so within one epoch every request must start with exactly the stable
//! messages of the request before it. The agent layer calls [`PrefixGuard::check`] with the stable
//! messages of each request; a [`PrefixCheck::Break`] is logged as a `cache_break` event.

use crate::message::Message;
use crate::sha256_hex;

#[derive(Clone, Debug, Default)]
pub struct PrefixGuard {
    epoch: u32,
    hashes: Vec<String>,
    seen_any: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrefixCheck {
    /// The previous request's stable messages are a prefix of this one's.
    Ok,
    /// First request, or the epoch changed (a re-weave): nothing to compare.
    NewEpoch,
    Break { first_diff_message: u32, detail: String },
}

/// Hash of one message as sent.
pub fn message_hash(m: &Message) -> String {
    sha256_hex(m.to_openai().to_string().as_bytes())
}

/// Hash over all stable messages, in order.
pub fn stable_hash(messages: &[Message]) -> String {
    let mut joined = String::new();
    for m in messages {
        joined.push_str(&message_hash(m));
    }
    sha256_hex(joined.as_bytes())
}

impl PrefixGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&mut self, epoch: u32, stable: &[Message]) -> PrefixCheck {
        let hashes: Vec<String> = stable.iter().map(message_hash).collect();
        let result = if !self.seen_any || epoch != self.epoch {
            PrefixCheck::NewEpoch
        } else if let Some(i) = first_difference(&self.hashes, &hashes) {
            let detail = if i >= hashes.len() {
                format!("request has {} stable messages, the previous one had {}", hashes.len(), self.hashes.len())
            } else {
                format!("message {} ({}) differs from the previous request", i, stable[i].role.as_str())
            };
            PrefixCheck::Break { first_diff_message: i as u32, detail }
        } else {
            PrefixCheck::Ok
        };
        self.epoch = epoch;
        self.hashes = hashes;
        self.seen_any = true;
        result
    }
}

/// Index of the first message where `new` stops being an extension of `old`.
fn first_difference(old: &[String], new: &[String]) -> Option<usize> {
    for (i, h) in old.iter().enumerate() {
        match new.get(i) {
            Some(n) if n == h => {}
            _ => return Some(i),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msgs(texts: &[&str]) -> Vec<Message> {
        texts.iter().map(|t| Message::user(*t)).collect()
    }

    #[test]
    fn growth_is_ok() {
        let mut g = PrefixGuard::new();
        assert_eq!(g.check(0, &msgs(&["a"])), PrefixCheck::NewEpoch);
        assert_eq!(g.check(0, &msgs(&["a", "b"])), PrefixCheck::Ok);
        assert_eq!(g.check(0, &msgs(&["a", "b"])), PrefixCheck::Ok);
        assert_eq!(g.check(0, &msgs(&["a", "b", "c", "d"])), PrefixCheck::Ok);
    }

    #[test]
    fn edit_and_shrink_are_breaks() {
        let mut g = PrefixGuard::new();
        g.check(0, &msgs(&["a", "b", "c"]));
        match g.check(0, &msgs(&["a", "X", "c", "d"])) {
            PrefixCheck::Break { first_diff_message, .. } => assert_eq!(first_diff_message, 1),
            other => panic!("expected break, got {other:?}"),
        }
        match g.check(0, &msgs(&["a"])) {
            PrefixCheck::Break { first_diff_message, .. } => assert_eq!(first_diff_message, 1),
            other => panic!("expected break, got {other:?}"),
        }
    }

    #[test]
    fn new_epoch_resets() {
        let mut g = PrefixGuard::new();
        g.check(0, &msgs(&["a", "b"]));
        assert_eq!(g.check(1, &msgs(&["z"])), PrefixCheck::NewEpoch);
        assert_eq!(g.check(1, &msgs(&["z", "y"])), PrefixCheck::Ok);
    }

    #[test]
    fn stable_hash_depends_on_order_and_content() {
        assert_eq!(stable_hash(&msgs(&["a", "b"])), stable_hash(&msgs(&["a", "b"])));
        assert_ne!(stable_hash(&msgs(&["a", "b"])), stable_hash(&msgs(&["b", "a"])));
    }
}
