use queues::{Queue, IsQueue}; 
use std::time::{Instant, Duration};
use crate::structs::matcher_frame::MatcherFrame;

pub struct DelayQueue {
    pub queue: Queue<MatcherFrame>,
    delay: Duration,
}

impl DelayQueue {
    pub fn new(delay: u64) -> DelayQueue {
        DelayQueue {
            queue: Queue::new(),
            delay: Duration::from_micros(delay),
        }
    }
    // Pop event from the queue.
    // Returns Some(event) if there is an event which has been in 
    // the queue for long enough.
    // Otherwise returns None.
    pub fn pop(&mut self) -> Option<MatcherFrame> {
        let now = Instant::now();
        if self.queue.size() == 0 {
            return None;
        }

        let first = match self.queue.peek() {
            Ok(el) => el,
            Err(_) => {
                eprintln!("DelayQueue: pop: Queue is empty.");
                return None;
            },
        };
        let elapsed = now.duration_since(first.dq_timestamp.unwrap());
        if elapsed < self.delay {
            None
        } else {
            Some(self.queue.remove().unwrap())
        }
    }
    
    // Insert element in the queue.
    pub fn push(&mut self, mut element: MatcherFrame) -> Option<()> {
        element.dq_timestamp = Some(Instant::now());
        match self.queue.add(element) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Error {} when adding element to queue.", e);
                ()
            },
        }
        None
    }
}
