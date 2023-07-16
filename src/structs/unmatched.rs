// extern crate nix;
use nix::time;
use std::collections::VecDeque;
use std::time::{Duration};
use kernel_probes::queue_xmit::XmitEvent;


pub struct UnmatchedEvents {
    pub queue: VecDeque<XmitEvent>,
    pub timeout: Duration,
}

impl UnmatchedEvents {
    pub fn new(timeout: u64) -> UnmatchedEvents {
        UnmatchedEvents {
            queue: VecDeque::new(),
            timeout: Duration::from_secs(timeout),
        }
    }

    // Add event to the queue.
    pub fn push(&mut self, element: XmitEvent) -> Option<()> {
        self.queue.push_front(element);
        None
    }

    // Return immutable reference to the queue.
    pub fn get_queue(&self) -> &VecDeque<XmitEvent> {
        &self.queue
    }
    
    // Remove timed-out events.
    // Returns the number of events which were removed.
    pub fn check_timeouts(&mut self) -> usize {
        // Get current time since boot.
        let time = time::clock_gettime(time::ClockId::CLOCK_MONOTONIC).unwrap();
        let now = Duration::from(time);
        let mut index_to_trunc = None;
        for (i, event) in self.queue.iter().enumerate() {
            let ts = Duration::from_nanos(event.timestamp);
            // Check if now - ts is more than the timeout.
            let elapsed = now.checked_sub(ts);
            match elapsed {
                Some(dur) => {
                    if dur > self.timeout {
                        index_to_trunc = Some(i);
                        break;
                    }
                },
                None => continue,
            }
        }
        let len = self.queue.len();
        match index_to_trunc {
            Some(0) => {
                self.queue.clear();
                return len;
            },
            Some(i) => {
                self.queue.truncate(i - 1);
                return len - i;
            },
            None => return 0,
        }
    }
    
}
