//! Priority scan queue.
//!
//! A bounded, priority-ordered queue for scan requests. Higher-severity
//! requests are processed first.

use crate::core::{FindingSeverity, ScanTarget};
use std::collections::BinaryHeap;
use std::sync::Mutex;

/// Priority level for a scan request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ScanPriority {
    /// Critical — immediate processing (e.g. active incident).
    Critical,
    /// High — elevated priority (e.g. suspicious file flagged by another tool).
    High,
    /// Normal — standard priority (e.g. scheduled scan).
    Normal,
    /// Low — background priority (e.g. periodic sweep).
    Low,
}

impl ScanPriority {
    fn rank(self) -> u8 {
        match self {
            Self::Critical => 3,
            Self::High => 2,
            Self::Normal => 1,
            Self::Low => 0,
        }
    }
}

impl PartialOrd for ScanPriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScanPriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl From<FindingSeverity> for ScanPriority {
    fn from(sev: FindingSeverity) -> Self {
        match sev {
            FindingSeverity::Critical => Self::Critical,
            FindingSeverity::High => Self::High,
            FindingSeverity::Medium => Self::Normal,
            FindingSeverity::Low | FindingSeverity::Info => Self::Low,
        }
    }
}

/// A queued scan request.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    /// What to scan.
    pub target: ScanTarget,
    /// Priority level.
    pub priority: ScanPriority,
    /// Unique request ID.
    pub id: u64,
}

impl PartialEq for ScanRequest {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ScanRequest {}

impl PartialOrd for ScanRequest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScanRequest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.id.cmp(&self.id)) // lower ID = older = higher priority at same level
    }
}

/// Thread-safe priority scan queue.
#[derive(Debug)]
pub struct ScanQueue {
    heap: Mutex<BinaryHeap<ScanRequest>>,
    capacity: usize,
    next_id: Mutex<u64>,
}

impl ScanQueue {
    /// Create a queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            heap: Mutex::new(BinaryHeap::with_capacity(capacity)),
            capacity,
            next_id: Mutex::new(0),
        }
    }

    /// Enqueue a scan request. Returns the assigned request ID, or `None` if full.
    pub fn enqueue(&self, target: ScanTarget, priority: ScanPriority) -> Option<u64> {
        let mut heap = self.heap.lock().unwrap();
        if heap.len() >= self.capacity {
            return None;
        }
        let mut next_id = self.next_id.lock().unwrap();
        let id = *next_id;
        *next_id += 1;
        heap.push(ScanRequest {
            target,
            priority,
            id,
        });
        Some(id)
    }

    /// Dequeue the highest-priority request.
    pub fn dequeue(&self) -> Option<ScanRequest> {
        self.heap.lock().unwrap().pop()
    }

    /// Number of pending requests.
    pub fn len(&self) -> usize {
        self.heap.lock().unwrap().len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.heap.lock().unwrap().is_empty()
    }

    /// Queue capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_ordering() {
        assert!(ScanPriority::Critical > ScanPriority::High);
        assert!(ScanPriority::High > ScanPriority::Normal);
        assert!(ScanPriority::Normal > ScanPriority::Low);
    }

    #[test]
    fn priority_from_severity() {
        assert_eq!(
            ScanPriority::from(FindingSeverity::Critical),
            ScanPriority::Critical
        );
        assert_eq!(
            ScanPriority::from(FindingSeverity::High),
            ScanPriority::High
        );
        assert_eq!(
            ScanPriority::from(FindingSeverity::Medium),
            ScanPriority::Normal
        );
        assert_eq!(ScanPriority::from(FindingSeverity::Low), ScanPriority::Low);
        assert_eq!(ScanPriority::from(FindingSeverity::Info), ScanPriority::Low);
    }

    #[test]
    fn queue_basic_operations() {
        let q = ScanQueue::new(10);
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.capacity(), 10);

        let id = q.enqueue(ScanTarget::Memory, ScanPriority::Normal).unwrap();
        assert_eq!(id, 0);
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());

        let req = q.dequeue().unwrap();
        assert_eq!(req.id, 0);
        assert!(q.is_empty());
    }

    #[test]
    fn queue_priority_order() {
        let q = ScanQueue::new(10);
        q.enqueue(ScanTarget::Memory, ScanPriority::Low);
        q.enqueue(ScanTarget::Memory, ScanPriority::Critical);
        q.enqueue(ScanTarget::Memory, ScanPriority::Normal);

        assert_eq!(q.dequeue().unwrap().priority, ScanPriority::Critical);
        assert_eq!(q.dequeue().unwrap().priority, ScanPriority::Normal);
        assert_eq!(q.dequeue().unwrap().priority, ScanPriority::Low);
    }

    #[test]
    fn queue_fifo_within_same_priority() {
        let q = ScanQueue::new(10);
        let id1 = q.enqueue(ScanTarget::Memory, ScanPriority::Normal).unwrap();
        let id2 = q
            .enqueue(ScanTarget::File("/tmp/a".into()), ScanPriority::Normal)
            .unwrap();

        // Same priority: older (lower ID) comes first
        assert_eq!(q.dequeue().unwrap().id, id1);
        assert_eq!(q.dequeue().unwrap().id, id2);
    }

    #[test]
    fn queue_capacity_limit() {
        let q = ScanQueue::new(2);
        assert!(
            q.enqueue(ScanTarget::Memory, ScanPriority::Normal)
                .is_some()
        );
        assert!(
            q.enqueue(ScanTarget::Memory, ScanPriority::Normal)
                .is_some()
        );
        assert!(
            q.enqueue(ScanTarget::Memory, ScanPriority::Normal)
                .is_none()
        ); // full
    }

    #[test]
    fn queue_interleaved_operations() {
        let q = ScanQueue::new(10);
        q.enqueue(ScanTarget::Memory, ScanPriority::Low);
        q.enqueue(ScanTarget::Memory, ScanPriority::Normal);

        // Dequeue highest so far
        assert_eq!(q.dequeue().unwrap().priority, ScanPriority::Normal);

        // Add a critical while Low is still in queue
        q.enqueue(ScanTarget::Memory, ScanPriority::Critical);

        // Critical should come before the remaining Low
        assert_eq!(q.dequeue().unwrap().priority, ScanPriority::Critical);
        assert_eq!(q.dequeue().unwrap().priority, ScanPriority::Low);
        assert!(q.is_empty());
    }

    #[test]
    fn queue_dequeue_empty() {
        let q = ScanQueue::new(10);
        assert!(q.dequeue().is_none());
    }
}
