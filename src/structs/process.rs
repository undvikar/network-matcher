use std::time::{Duration, Instant};
use dashmap::DashMap;

pub struct ProcessEntry {
    pub name: String,
    pub timestamp: Instant,
}

impl ProcessEntry {
    pub fn new(name: String) -> ProcessEntry {
        ProcessEntry {
            name: name,
            timestamp: Instant::now(),
        }
    }
}

pub struct ProcessTable {
    pub table: DashMap<u32, ProcessEntry>,
    pub timeout: Duration,
}

impl ProcessTable {
    pub fn new() -> ProcessTable {
        ProcessTable {
            table: DashMap::new(),
            timeout: Duration::from_secs(4),
        }
    }

    pub fn add(&self, pid: u32, proc: ProcessEntry) {
        if self.table.contains_key(&pid) {
            let entry = self.table.get(&pid).unwrap();
            // If the existing entry does not have the same name, replace it.
            // Otherwise, leave it.
            if !entry.name.eq(&proc.name) {
                self.table.insert(pid, proc);
            }
        } else {
            self.table.insert(pid, proc);
        }
    }

    pub fn get_name(&self, pid: u32) -> Option<String> {
        match self.table.get(&pid) {
            Some(entry) => Some(entry.name.clone()),
            None => None,
        }
    }

    // Remove timed out entries.
    pub fn check_timeouts(&self) {
        let mut entries_to_remove = Vec::new();
        // Scope for table reference.
        {
            let now = Instant::now();
            for (key, entry) in self.table.iter().enumerate() {
                // let elapsed = now.checked_sub(entry.timestamp);
                let elapsed = now.checked_duration_since(entry.timestamp);
                match elapsed {
                    Some(dur) => {
                        if dur > self.timeout {
                            entries_to_remove.push(key);
                        }
                    },
                    None => continue,
                }
            }
        }
        for entry in entries_to_remove {
            self.table.remove(&(entry as u32));
        }
    }
}
