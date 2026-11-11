//! Token estimation calibrated against what the server reports.
//!
//! Sizes inside loom are estimates (characters divided by a ratio). After every request the agent
//! layer feeds back the server's `prompt_tokens` for the characters it sent, and the ratio follows.

use crate::message::Message;
use serde::{Deserialize, Serialize};

const START_RATIO: f64 = 3.3;
const MIN_RATIO: f64 = 1.5;
const MAX_RATIO: f64 = 6.0;
/// Requests smaller than this say little about the ratio (fixed template overhead dominates).
const MIN_SAMPLE_TOKENS: u64 = 2_000;
/// Per-message template overhead, in tokens.
const PER_MESSAGE: u64 = 4;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenEstimator {
    chars_per_token: f64,
    samples: u32,
}

impl Default for TokenEstimator {
    fn default() -> Self {
        Self { chars_per_token: START_RATIO, samples: 0 }
    }
}

impl TokenEstimator {
    pub fn with_ratio(chars_per_token: f64) -> Self {
        Self { chars_per_token: chars_per_token.clamp(MIN_RATIO, MAX_RATIO), samples: 0 }
    }

    pub fn ratio(&self) -> f64 {
        self.chars_per_token
    }

    pub fn samples(&self) -> u32 {
        self.samples
    }

    /// Estimated tokens for `chars` characters of text.
    pub fn tokens(&self, chars: usize) -> u64 {
        (chars as f64 / self.chars_per_token).ceil() as u64
    }

    /// Characters that fit in `tokens` tokens.
    pub fn chars(&self, tokens: u64) -> usize {
        (tokens as f64 * self.chars_per_token).floor() as usize
    }

    pub fn tokens_for_messages(&self, messages: &[Message]) -> u64 {
        messages.iter().map(|m| self.tokens(m.chars()) + PER_MESSAGE).sum()
    }

    /// Feed back one observation: `chars` characters were sent and the server counted `prompt_tokens`.
    pub fn calibrate(&mut self, chars: usize, prompt_tokens: u64) {
        if prompt_tokens < MIN_SAMPLE_TOKENS || chars == 0 {
            return;
        }
        let observed = (chars as f64 / prompt_tokens as f64).clamp(MIN_RATIO, MAX_RATIO);
        // The first sample replaces the starting guess; later ones move it a quarter of the way.
        self.chars_per_token = if self.samples == 0 { observed } else { self.chars_per_token * 0.75 + observed * 0.25 };
        self.samples = self.samples.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_default_and_rounds_up() {
        let e = TokenEstimator::default();
        assert_eq!(e.tokens(0), 0);
        assert_eq!(e.tokens(1), 1);
        assert_eq!(e.tokens(33), 10);
        assert!(e.chars(10) <= 33);
    }

    #[test]
    fn small_samples_are_ignored() {
        let mut e = TokenEstimator::default();
        e.calibrate(100, 50);
        assert_eq!(e.samples(), 0);
        assert_eq!(e.ratio(), START_RATIO);
    }

    #[test]
    fn calibration_converges_and_is_clamped() {
        let mut e = TokenEstimator::default();
        e.calibrate(40_000, 10_000);
        assert!((e.ratio() - 4.0).abs() < 1e-9);
        for _ in 0..40 {
            e.calibrate(30_000, 10_000);
        }
        assert!((e.ratio() - 3.0).abs() < 0.01);
        e.calibrate(1_000_000, 2_000);
        assert!(e.ratio() <= MAX_RATIO);
    }

    #[test]
    fn messages_include_overhead() {
        let e = TokenEstimator::with_ratio(4.0);
        let m = [Message::user("abcd"), Message::user("abcd")];
        assert_eq!(e.tokens_for_messages(&m), 2 * (3 + PER_MESSAGE));
    }
}
