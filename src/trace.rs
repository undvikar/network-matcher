use futures::stream::StreamExt;
use std::ptr;
use redbpf::load::Loader;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use kernel_probes::queue_xmit::XmitEvent;
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use parking_lot::RwLock;

use crate::structs:: unmatched::UnmatchedEvents;

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),
    "/target/bpf/programs/queue_xmit/queue_xmit.elf"
    ))
}

#[tokio::main(flavor = "current_thread")]
pub async fn trace(unmatched: &Arc<RwLock<UnmatchedEvents>>, stop: &AtomicBool) {
    // For error logging.
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let mut loaded = Loader::load(probe_code()).expect("error on Loader::load");


    // Attach to kernel function __dev_queue_xmit.
    loaded
        .kprobe_mut("__dev_queue_xmit")
        .expect("error on Loaded::kprobe_mut")
        .attach_kprobe("__dev_queue_xmit", 0)
        .expect("error on KProbe::attach_kprobe");

    // Loop forever while receiving kernel events.
    // If there is no traffic at all, the program might get stuck waiting for
    // the next results from the kernel after interrupting it with Ctrl-C. 
    // As a temporary workaround, running ping or causing any other network traffic
    // will cause the program to continue and then stop.
    'outer: while let Some((map_name, events)) = loaded.events.next().await {
        if map_name == "KERNEL_EVENTS" {
            for event in events {
                if stop.load(Ordering::Relaxed) {
                    break 'outer;
                }
                let xmit_event = unsafe { ptr::read(event.as_ptr() as *const XmitEvent) };
                let mut q = unmatched.write();
                q.push(xmit_event);
            }
        }
    }

}
