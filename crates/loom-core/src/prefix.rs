//! Guard that a session's request prefix only grows.
//!
//! The server caches by prefix, so within one epoch every request must start with exactly the stable
//! messages of the request before it. The agent layer calls [`PrefixGuard::check`] with the stable
//! messages of each request; a [`PrefixCheck::Break`] is logged as a `cache_break` event.
//!
//! One change to an earlier message is growth and not a break: the *last* stable message of the
//! previous request may have had text appended. That happens when a request ended without a reply
//! being recorded (a stop, a restart, the server being unreachable) and the next thing to arrive is
//! another user-role item, which the weave merges into that message. What the server cached is a
//! prefix of tokens, and appending to the final message keeps all of it but the few tokens that
//! closed the message.

use crate::message::Message;
use crate::sha256_hex;

#[derive(Clone, Debug, Default)]
pub struct PrefixGuard {
    epoch: u32,
    hashes: Vec<String>,
    /// The final stable message of the previous request.
    last: Option<Message>,
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
        let grown_tail = match (&self.last, self.hashes.len().checked_sub(1)) {
            (Some(old), Some(i)) => stable.get(i).is_some_and(|new| extends(old, new)).then_some(i),
            _ => None,
        };
        let result = if !self.seen_any || epoch != self.epoch {
            PrefixCheck::NewEpoch
        } else if let Some(i) = first_difference(&self.hashes, &hashes).filter(|i| Some(*i) != grown_tail) {
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
        self.last = stable.last().cloned();
        self.seen_any = true;
        result
    }
}

/// `new` is `old` with text appended and nothing else changed.
fn extends(old: &Message, new: &Message) -> bool {
    old.role == new.role
        && old.tool_call_id == new.tool_call_id
        && old.tool_calls == new.tool_calls
        && old.reasoning == new.reasoning
        && new.content.len() > old.content.len()
        && new.content.starts_with(&old.content)
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
    fn appending_to_the_final_message_is_growth() {
        let mut g = PrefixGuard::new();
        assert_eq!(g.check(0, &msgs(&["sys", "do it"])), PrefixCheck::NewEpoch);
        // The request got no reply; a note and a new message were merged into the last message.
        assert_eq!(g.check(0, &msgs(&["sys", "do it\n\nnote\n\nmore"])), PrefixCheck::Ok);
        // ...and the conversation carries on from there.
        assert_eq!(g.check(0, &msgs(&["sys", "do it\n\nnote\n\nmore", "x"])), PrefixCheck::Ok);
        // Appending to a message that is no longer the last one is a break.
        assert!(matches!(
            g.check(0, &msgs(&["sys", "do it\n\nnote\n\nmore and more", "x"])),
            PrefixCheck::Break { first_diff_message: 1, .. }
        ));
    }

    #[test]
    fn a_changed_final_message_is_a_break_unless_it_only_grew() {
        let mut g = PrefixGuard::new();
        g.check(0, &msgs(&["sys", "do it"]));
        // Different text that merely has the same length class.
        assert!(matches!(g.check(0, &msgs(&["sys", "do IT now"])), PrefixCheck::Break { first_diff_message: 1, .. }));
        // A different role with extended text.
        let mut g = PrefixGuard::new();
        g.check(0, &msgs(&["sys", "do it"]));
        let changed = vec![Message::user("sys"), Message::assistant("do it and more")];
        assert!(matches!(g.check(0, &changed), PrefixCheck::Break { first_diff_message: 1, .. }));
        // Growth of the last message together with a change before it.
        let mut g = PrefixGuard::new();
        g.check(0, &msgs(&["sys", "do it"]));
        assert!(matches!(g.check(0, &msgs(&["SYS", "do it more"])), PrefixCheck::Break { first_diff_message: 0, .. }));
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
