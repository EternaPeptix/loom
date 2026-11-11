//! [`Limiter`]: at most N holders at a time, highest priority first, first come first served within
//! a priority.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! - `acquire` returns as soon as a slot is free and no waiter of higher priority (or equal priority
//!   that arrived earlier) is waiting. Dropping the [`Permit`] frees the slot and wakes the best
//!   waiter.
//! - A waiter whose `cancel` token fires leaves the queue and gets `None`; a slot is never lost when
//!   a waiter is cancelled or its future is dropped at any point (including after it was chosen but
//!   before it resumed).
//! - `waited_ms` on the permit is how long the caller waited.
//! - `in_use()` / `waiting()` report current counts; `capacity()` the limit. `set_capacity` may raise
//!   or lower the limit at any time (lowering takes effect as holders release).
//!
//! Tests required: never more than N concurrent holders under 200 tasks; priority order; FIFO within
//! a priority; cancellation while waiting; dropping a pending acquire future does not leak a slot;
//! `set_capacity` up and down.

use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// Digests, titles, anything nobody is waiting on.
    Background = 0,
    /// Child sessions.
    Child = 1,
    /// A session the operator is talking to, and leads.
    Lead = 2,
}

#[derive(Clone)]
pub struct Limiter {
    inner: Arc<Inner>,
}

struct Inner {
    _private: (),
}

pub struct Permit {
    pub waited_ms: u64,
    _inner: Arc<Inner>,
}

impl Limiter {
    pub fn new(capacity: u32) -> Limiter {
        let _ = capacity;
        todo!("implement per module contract (replace `_private` with real state; add Drop for Permit)")
    }

    pub async fn acquire(&self, priority: Priority, cancel: &CancellationToken) -> Option<Permit> {
        let _ = (&self.inner, priority, cancel);
        todo!("implement per module contract")
    }

    pub fn capacity(&self) -> u32 {
        todo!("implement per module contract")
    }

    pub fn set_capacity(&self, capacity: u32) {
        let _ = capacity;
        todo!("implement per module contract")
    }

    pub fn in_use(&self) -> u32 {
        todo!("implement per module contract")
    }

    pub fn waiting(&self) -> u32 {
        todo!("implement per module contract")
    }
}
