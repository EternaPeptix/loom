//! Token estimation calibrated against what the server reports.
//!
//! Sizes inside ferret are estimates (characters divided by a ratio). After every request the agent
//! layer feeds back the server's `prompt_tokens` for the characters it sent, and the ratio follows.
//!
//! An image costs `ImageRef::est_tokens`, not characters: `tokens_for_messages` adds the images of its messages
//! while the estimator is told the model takes images (`set_vision(true)`; a model that does not gets a sentence
//! in the text instead, which the characters already count). `image_tokens` is that sum, for taking it out of
//! the server's count before `calibrate`.

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
    #[serde(default)]
    vision: bool,
}

impl Default for TokenEstimator {
    fn default() -> Self {
        Self { chars_per_token: START_RATIO, samples: 0, vision: false }
    }
}

impl TokenEstimator {
    pub fn with_ratio(chars_per_token: f64) -> Self {
        Self { chars_per_token: chars_per_token.clamp(MIN_RATIO, MAX_RATIO), samples: 0, vision: false }
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

    /// Count the images of messages (the model takes images) or not.
    pub fn set_vision(&mut self, vision: bool) {
        self.vision = vision;
    }

    pub fn vision(&self) -> bool {
        self.vision
    }

    /// Tokens of the images of `messages` (0 while the model does not take images).
    pub fn image_tokens(&self, messages: &[Message]) -> u64 {
        if !self.vision {
            return 0;
        }
        messages.iter().flat_map(|m| m.images.iter()).map(crate::image::ImageRef::est_tokens).sum()
    }

    pub fn tokens_for_messages(&self, messages: &[Message]) -> u64 {
        let text: u64 = messages.iter().map(|m| self.tokens(m.chars()) + PER_MESSAGE).sum();
        text.saturating_add(self.image_tokens(messages))
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
    fn images_cost_their_pixels_only_for_a_vision_model() {
        use crate::image::ImageRef;
        let img = |w: u32, h: u32| ImageRef {
            blob: "ab".repeat(32),
            mime: "image/png".into(),
            bytes: 1,
            width: w,
            height: h,
            name: None,
        };
        let mut m = Message::user("");
        m.images = vec![img(300, 300), img(10, 10), img(4000, 4000)];
        let mut e = TokenEstimator::with_ratio(4.0);
        assert_eq!(e.image_tokens(std::slice::from_ref(&m)), 0);
        e.set_vision(true);
        // ceil(90000 / 750) = 120; the floor is 85; the ceiling is 2000.
        assert_eq!(e.image_tokens(std::slice::from_ref(&m)), 120 + 85 + 2000);
        assert_eq!(e.tokens_for_messages(std::slice::from_ref(&m)), e.tokens(m.chars()) + PER_MESSAGE + 2205);
    }

    #[test]
    fn messages_include_overhead() {
        let e = TokenEstimator::with_ratio(4.0);
        let m = [Message::user("abcd"), Message::user("abcd")];
        assert_eq!(e.tokens_for_messages(&m), 2 * (3 + PER_MESSAGE));
    }
}
