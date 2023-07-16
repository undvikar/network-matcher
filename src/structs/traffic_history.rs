use dashmap::DashMap;
use dashmap::mapref::one::{Ref};
use nix::time;
use std::ops::Deref;
use std::collections::VecDeque;
use std::time::{Duration};
use crate::structs::matcher_frame::MatcherFrame;

// Uses L4 port as key or 0 if not present.
pub struct TrafficHistory {
    pub history: DashMap<u16, VecDeque<MatcherFrame>>,
    pub timeout: Duration,
}

impl<'a> TrafficHistory {
    
    // Create a new, empty Traffic History.
    pub fn new(timeout: u64) -> TrafficHistory {
        TrafficHistory {
            history: DashMap::new(),
            timeout: Duration::from_secs(timeout),
        }
    }

    // Return the specified subset.
    pub fn get_subset(&'a self, &key: &u16) -> Option<Ref<'a, u16, VecDeque<MatcherFrame>>> {
        self.history.get(&key)
    }

    // Insert an element.
    pub fn insert_in(&self, frame: MatcherFrame) {
        let key = match frame.l4_src_port {
            Some(p) => p,
            None => 0,
        };
        if self.history.contains_key(&key) {
            let mut subset = self.history.get_mut(&key).unwrap();
            subset.push_front(frame);
        } else {
            self.history.insert(key, VecDeque::from([frame]));
        }
    }

    // Remove timed out frames and empty subsets.
    pub fn check_timeouts(&self) {
        let mut subsets_to_remove = Vec::new();
        // Own scope for history reference.
        // Necessary because when removing frames and we already hold a reference
        // to the history, it might deadlock.
        {
            for mut subset in self.history.iter_mut() {
                let time = time::clock_gettime(time::ClockId::CLOCK_MONOTONIC).unwrap();
                let now = Duration::from(time);

                let mut index_to_trunc = None;
                for (i, frame) in subset.iter().enumerate() {
                    let elapsed = now.checked_sub(frame.timestamp);
                    match elapsed {
                        Some(dur) => {
                            if dur > self.timeout {
                                index_to_trunc = Some(i);
                                break;
                            }
                        }
                        None => continue,
                    }
                }
                match index_to_trunc {
                    Some(0) => {
                        subset.clear();
                        subsets_to_remove.push(subset.key().clone());
                    },
                    Some(i) => subset.truncate(i - 1),
                    None => (),
                }
            }
        }

        // Remove empty subsets.
        for entry in subsets_to_remove {
            self.history.remove(&entry);
        }
        self.history.shrink_to_fit();
    }
}

// Deref so we can so we call history.x() instead of history.history.x().
impl Deref for TrafficHistory {
    type Target = DashMap<u16, VecDeque<MatcherFrame>>;
    fn deref(&self) -> &Self::Target {
        &self.history
    }
}
