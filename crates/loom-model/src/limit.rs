//! [`Limiter`]: at most N holders at a time, highest priority first, first come first served within
//! a priority.
//!
//! CONTRACT.
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

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::sync::Notify;
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

/// Queue order: highest priority first, then arrival order.
type Key = (Reverse<Priority>, u64);

struct Waiter {
    /// Set under the lock when a slot has been handed to this waiter (already counted in `in_use`).
    granted: bool,
    wake: Arc<Notify>,
}

#[derive(Default)]
struct State {
    capacity: u32,
    in_use: u32,
    next_seq: u64,
    queue: BTreeMap<Key, Waiter>,
}

impl State {
    /// Hands free slots to the best waiters, waking them.
    fn dispatch(&mut self) {
        for w in self.queue.values_mut() {
            if self.in_use >= self.capacity {
                break;
            }
            if !w.granted {
                w.granted = true;
                self.in_use = self.in_use.saturating_add(1);
                w.wake.notify_one();
            }
        }
    }
}

struct Inner {
    state: Mutex<State>,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        // Nothing under the lock can panic half-way through an update, so a poisoned lock is usable.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub struct Permit {
    pub waited_ms: u64,
    _inner: Arc<Inner>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut st = self._inner.lock();
        st.in_use = st.in_use.saturating_sub(1);
        st.dispatch();
    }
}

/// Owns a queue entry while `acquire` is pending. Dropping it (the future was dropped or the waiter
/// was cancelled) removes the entry and, if a slot had already been handed over, gives it back.
struct Ticket {
    inner: Arc<Inner>,
    key: Key,
    armed: bool,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut st = self.inner.lock();
        if let Some(w) = st.queue.remove(&self.key) {
            if w.granted {
                st.in_use = st.in_use.saturating_sub(1);
            }
        }
        st.dispatch();
    }
}

impl Limiter {
    pub fn new(capacity: u32) -> Limiter {
        let state = State { capacity, ..State::default() };
        Limiter { inner: Arc::new(Inner { state: Mutex::new(state) }) }
    }

    pub async fn acquire(&self, priority: Priority, cancel: &CancellationToken) -> Option<Permit> {
        if cancel.is_cancelled() {
            return None;
        }
        let started = Instant::now();
        let wake = Arc::new(Notify::new());
        let key = {
            let mut st = self.inner.lock();
            let key = (Reverse(priority), st.next_seq);
            st.next_seq = st.next_seq.wrapping_add(1);
            st.queue.insert(key, Waiter { granted: false, wake: wake.clone() });
            st.dispatch();
            key
        };
        // From here on, leaving this function by any route (including the future being dropped)
        // runs the ticket's Drop, which undoes the queue entry and any slot handed to it.
        let mut ticket = Ticket { inner: self.inner.clone(), key, armed: true };
        loop {
            {
                let mut st = self.inner.lock();
                if st.queue.get(&key).is_some_and(|w| w.granted) {
                    st.queue.remove(&key);
                    ticket.armed = false;
                    drop(st);
                    let waited_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    return Some(Permit { waited_ms, _inner: self.inner.clone() });
                }
            }
            tokio::select! {
                _ = wake.notified() => {}
                _ = cancel.cancelled() => return None,
            }
        }
    }

    pub fn capacity(&self) -> u32 {
        self.inner.lock().capacity
    }

    pub fn set_capacity(&self, capacity: u32) {
        let mut st = self.inner.lock();
        st.capacity = capacity;
        st.dispatch();
    }

    pub fn in_use(&self) -> u32 {
        self.inner.lock().in_use
    }

    pub fn waiting(&self) -> u32 {
        let st = self.inner.lock();
        u32::try_from(st.queue.values().filter(|w| !w.granted).count()).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    fn never() -> CancellationToken {
        CancellationToken::new()
    }

    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn immediate_when_free() {
        let l = Limiter::new(2);
        let c = never();
        let a = l.acquire(Priority::Child, &c).await;
        assert!(a.is_some());
        assert_eq!((l.in_use(), l.waiting(), l.capacity()), (1, 0, 2));
        drop(a);
        assert_eq!(l.in_use(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn never_more_than_n_holders() {
        let l = Limiter::new(5);
        let cur = Arc::new(AtomicU32::new(0));
        let peak = Arc::new(AtomicU32::new(0));
        let mut tasks = Vec::new();
        for i in 0..200u32 {
            let (l, cur, peak) = (l.clone(), cur.clone(), peak.clone());
            tasks.push(tokio::spawn(async move {
                let prio = match i % 3 {
                    0 => Priority::Background,
                    1 => Priority::Child,
                    _ => Priority::Lead,
                };
                let p = l.acquire(prio, &CancellationToken::new()).await;
                assert!(p.is_some());
                let now = cur.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(1)).await;
                cur.fetch_sub(1, Ordering::SeqCst);
                drop(p);
            }));
        }
        for t in tasks {
            assert!(t.await.is_ok());
        }
        assert!(peak.load(Ordering::SeqCst) <= 5);
        assert!(peak.load(Ordering::SeqCst) >= 2);
        assert_eq!((l.in_use(), l.waiting()), (0, 0));
    }

    /// Queues waiters in the given order behind a held slot and returns the order they were served.
    async fn serve_order(prios: &[Priority]) -> Vec<usize> {
        let l = Limiter::new(1);
        let held = l.acquire(Priority::Lead, &never()).await;
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for (i, p) in prios.iter().copied().enumerate() {
            let (l2, order) = (l.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                let permit = l2.acquire(p, &CancellationToken::new()).await;
                order.lock().unwrap_or_else(|e| e.into_inner()).push(i);
                drop(permit);
            }));
            settle().await; // let it enqueue before the next one arrives
        }
        assert_eq!(l.waiting(), u32::try_from(prios.len()).unwrap_or(0));
        drop(held);
        for t in tasks {
            assert!(t.await.is_ok());
        }
        let got = order.lock().unwrap_or_else(|e| e.into_inner()).clone();
        got
    }

    #[tokio::test]
    async fn priority_order() {
        let got = serve_order(&[Priority::Background, Priority::Child, Priority::Lead, Priority::Child, Priority::Lead]).await;
        assert_eq!(got, vec![2, 4, 1, 3, 0]);
    }

    #[tokio::test]
    async fn fifo_within_priority() {
        let got = serve_order(&[Priority::Child; 8]).await;
        assert_eq!(got, (0..8).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn cancel_while_waiting() {
        let l = Limiter::new(1);
        let held = l.acquire(Priority::Lead, &never()).await;
        let c = CancellationToken::new();
        let (l2, c2) = (l.clone(), c.clone());
        let t = tokio::spawn(async move { l2.acquire(Priority::Child, &c2).await.is_none() });
        settle().await;
        assert_eq!(l.waiting(), 1);
        c.cancel();
        assert_eq!(t.await.ok(), Some(true));
        assert_eq!((l.in_use(), l.waiting()), (1, 0));
        drop(held);
        assert_eq!(l.in_use(), 0);
        assert!(l.acquire(Priority::Child, &never()).await.is_some());
    }

    #[tokio::test]
    async fn already_cancelled_gets_none_without_taking_a_slot() {
        let l = Limiter::new(3);
        let c = CancellationToken::new();
        c.cancel();
        assert!(l.acquire(Priority::Lead, &c).await.is_none());
        assert_eq!((l.in_use(), l.waiting()), (0, 0));
    }

    #[tokio::test]
    async fn dropped_pending_future_leaks_nothing() {
        let l = Limiter::new(1);
        let held = l.acquire(Priority::Lead, &never()).await;
        let c = never();
        {
            let mut fut = Box::pin(l.acquire(Priority::Child, &c));
            // Poll once so the waiter is queued, then drop the future.
            let polled = tokio::time::timeout(Duration::from_millis(5), fut.as_mut()).await;
            assert!(polled.is_err());
            assert_eq!(l.waiting(), 1);
        }
        assert_eq!(l.waiting(), 0);
        drop(held);
        assert_eq!(l.in_use(), 0);
        assert!(l.acquire(Priority::Child, &never()).await.is_some());
    }

    #[tokio::test]
    async fn dropped_after_being_chosen_returns_the_slot() {
        let l = Limiter::new(1);
        let held = l.acquire(Priority::Lead, &never()).await;
        let c = never();
        let mut fut = Box::pin(l.acquire(Priority::Child, &c));
        let polled = tokio::time::timeout(Duration::from_millis(5), fut.as_mut()).await;
        assert!(polled.is_err());
        // The release hands the slot to the queued waiter, which has not been polled again.
        drop(held);
        assert_eq!(l.in_use(), 1);
        assert_eq!(l.waiting(), 0);
        drop(fut);
        assert_eq!(l.in_use(), 0);
        assert!(l.acquire(Priority::Background, &never()).await.is_some());
    }

    #[tokio::test]
    async fn dropped_chosen_waiter_passes_slot_to_next() {
        let l = Limiter::new(1);
        let held = l.acquire(Priority::Lead, &never()).await;
        let c = never();
        let mut first = Box::pin(l.acquire(Priority::Lead, &c));
        assert!(tokio::time::timeout(Duration::from_millis(5), first.as_mut()).await.is_err());
        let (l2, c2) = (l.clone(), never());
        let second = tokio::spawn(async move { l2.acquire(Priority::Background, &c2).await.is_some() });
        settle().await;
        drop(held); // the slot goes to `first`
        drop(first); // which never resumes; it must pass to `second`
        assert_eq!(second.await.ok(), Some(true));
        assert_eq!(l.in_use(), 0);
    }

    #[tokio::test]
    async fn cancelled_after_chosen_returns_the_slot() {
        let l = Limiter::new(1);
        let held = l.acquire(Priority::Lead, &never()).await;
        let c = CancellationToken::new();
        let mut fut = Box::pin(l.acquire(Priority::Child, &c));
        assert!(tokio::time::timeout(Duration::from_millis(5), fut.as_mut()).await.is_err());
        drop(held);
        c.cancel();
        // Either outcome is allowed (a permit or None), but the slot must end up free.
        let r = fut.await;
        drop(r);
        assert_eq!(l.in_use(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn churn_of_cancellations_leaks_no_slots() {
        let l = Limiter::new(3);
        let mut tasks = Vec::new();
        for i in 0..300u64 {
            let l = l.clone();
            tasks.push(tokio::spawn(async move {
                let c = CancellationToken::new();
                let c2 = c.clone();
                let canceller = tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_micros(200 * (i % 7))).await;
                    c2.cancel();
                });
                let p = l.acquire(Priority::Child, &c).await;
                if p.is_some() {
                    tokio::time::sleep(Duration::from_micros(300)).await;
                }
                drop(p);
                let _ = canceller.await;
            }));
        }
        // Abort some tasks outright, dropping their futures wherever they happen to be.
        for (i, t) in tasks.into_iter().enumerate() {
            if i % 5 == 0 {
                t.abort();
            }
            let _ = t.await;
        }
        settle().await;
        assert_eq!((l.in_use(), l.waiting()), (0, 0));
        let a = l.acquire(Priority::Lead, &never()).await;
        let b = l.acquire(Priority::Lead, &never()).await;
        let d = l.acquire(Priority::Lead, &never()).await;
        assert!(a.is_some() && b.is_some() && d.is_some());
    }

    #[tokio::test]
    async fn set_capacity_up_wakes_waiters() {
        let l = Limiter::new(1);
        let held = l.acquire(Priority::Lead, &never()).await;
        let (l2, c2) = (l.clone(), never());
        let t = tokio::spawn(async move { l2.acquire(Priority::Lead, &c2).await });
        settle().await;
        assert_eq!(l.waiting(), 1);
        l.set_capacity(2);
        let p = t.await.ok().flatten();
        assert!(p.is_some());
        assert_eq!((l.capacity(), l.in_use(), l.waiting()), (2, 2, 0));
        drop(p);
        drop(held);
    }

    #[tokio::test]
    async fn set_capacity_down_takes_effect_as_holders_release() {
        let l = Limiter::new(3);
        let c = never();
        let a = l.acquire(Priority::Lead, &c).await;
        let b = l.acquire(Priority::Lead, &c).await;
        let d = l.acquire(Priority::Lead, &c).await;
        l.set_capacity(1);
        assert_eq!((l.capacity(), l.in_use()), (1, 3));
        let (l2, c2) = (l.clone(), never());
        let mut t = tokio::spawn(async move { l2.acquire(Priority::Lead, &c2).await });
        settle().await;
        assert_eq!(l.waiting(), 1);
        drop(a);
        drop(b);
        settle().await;
        // `d` is now the one holder the lowered limit allows, so the waiter still waits.
        assert_eq!((l.in_use(), l.waiting()), (1, 1));
        assert!(tokio::time::timeout(Duration::from_millis(5), &mut t).await.is_err());
        drop(d);
        let p = t.await.ok().flatten();
        assert!(p.is_some());
        assert_eq!(l.in_use(), 1);
    }

    #[tokio::test]
    async fn waited_ms_reports_the_wait() {
        let l = Limiter::new(1);
        let held = l.acquire(Priority::Lead, &never()).await;
        let (l2, c2) = (l.clone(), never());
        let t = tokio::spawn(async move { l2.acquire(Priority::Lead, &c2).await.map(|p| p.waited_ms) });
        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(held);
        let w = t.await.ok().flatten();
        assert!(w.is_some_and(|ms| ms >= 25));
    }

    fn assert_send<F: Future + Send>(_: &F) {}

    #[tokio::test]
    async fn acquire_future_is_send() {
        let l = Limiter::new(1);
        let c = never();
        let f = l.acquire(Priority::Lead, &c);
        assert_send(&f);
        drop(f);
    }
}
