// Thanks to @rhdxmr (collaborator on the redBPF project) on GitHub for helping with this
#![no_std]
#![no_main]

use redbpf_probes::kprobe::prelude::*;
use kernel_probes::queue_xmit::*;
use core::mem::{self, MaybeUninit};
use core::convert::TryInto;
use core::cmp::min;

program!(0xFFFFFFFE, "GPL");


// Buffer accessible by our userspace program.
#[map]
static mut KERNEL_EVENTS: PerfMap<XmitEvent> = PerfMap::with_max_entries(2048);

// Buffer for storing the event we are working on.
#[map]
static mut BUF: PerCpuArray<XmitEvent> = PerCpuArray::with_max_entries(1);

#[kprobe("__dev_queue_xmit")]
unsafe fn dev_queue_xmit(regs: Registers) {
    let event = BUF.get_mut(0).unwrap();
    event.timestamp = bpf_ktime_get_ns();
    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid as u32;
    event.tgid = (pid_tgid >> 32) as u32;
    event.command = bpf_get_current_comm();

    let skb_ptr = regs.parm1() as *const u64 as *const sk_buff;
    let mut skb = MaybeUninit::<sk_buff>::uninit();
    // Read SKB.
    if bpf_probe_read_kernel(
        skb.as_mut_ptr() as *mut _,
        mem::size_of::<sk_buff>() as u32,
        skb_ptr as *const _,
    ) < 0
    {
        bpf_trace_printk(b"error reading skb.len\0");
    }
    let skb = skb.assume_init();
    event.len = skb.len;
    event.data_len = skb.data_len;

    // Not really optimal but the validator will not allow a direct subtraction
    // skb.len - skb.data_len, even if the value is OR'd with 0xFFFFFFFF
    // or any other attempt to fix it made it panic.
    // Therefore, especially the 'else if' block is important since with a construct 
    // like len = 201, data_len = 60 => 261 % 128 = 5 would mean we read only
    // 5 bytes from the SKB when there are many more available.
    // The 'else' block was the initial approach, which lead to cases where only a few bytes
    // were read from the SKB.
    let readlen: u32 = if skb.data_len == 0 && skb.len > 128 {
        BUFSIZE.try_into().unwrap()
    } else if (skb.len - skb.data_len) % 128 < 15 && skb.len >= 128 {
        64
    } else {
        min((skb.len - skb.data_len) % 128, BUFSIZE.try_into().unwrap())
    };

    // Read SKB data.
    if bpf_probe_read_kernel(
        event.data.as_mut_ptr() as *mut _,
        readlen,
        skb.data as *const _,
    ) < 0
    {
        bpf_trace_printk(b"error reading skb.data\0");
    }

    event.copied_len = readlen;
    KERNEL_EVENTS.insert(regs.ctx, event);
}
