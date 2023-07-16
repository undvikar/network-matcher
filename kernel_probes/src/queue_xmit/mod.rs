pub const COMMLEN: usize = 16;
pub const BUFSIZE: usize = 128;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct XmitEvent {
    // Timestamp of when the event was recorded in the kernel function.
    pub timestamp: u64, 
    pub pid: u32,
    pub tgid: u32,
    pub len: u32,
    pub data_len: u32,
    pub copied_len: u32,
    pub command: [i8; COMMLEN],
    pub data: [u8; BUFSIZE],
}

impl Default for XmitEvent {
    fn default() -> XmitEvent {
        XmitEvent {
            timestamp: 0,
            pid: 0,
            tgid: 0,
            len: 0,
            data_len: 0,
            copied_len: 0,
            command: [0; COMMLEN],
            data: [0; BUFSIZE],
        }
    }
}
