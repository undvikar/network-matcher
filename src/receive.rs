use crate::structs::{
    delay_queue::DelayQueue,
    matcher_frame::{MatcherFrame, PacketTypes, MatchReason}
};

use nix::time;
use pnet::datalink;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::ethernet::{Ethernet as Eth, EthernetPacket};
use pnet::util::MacAddr;
use std::time::{Instant, Duration};
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{io, mem};
use libc;
use nix::sys::socket;
use nix::sys::socket::{LinkAddr, SockAddr};
use parking_lot::Mutex;

// Receive frames on raw socket.
// If `interface` is `None`, traffic on all interfaces is captured (default behavior).
// Returns no value.
pub fn receive(delay_queue: &Arc<Mutex<DelayQueue>>, stop: &AtomicBool, interface: Option<NetworkInterface>) {
    // Zeroed buffer for incoming frames.
    let mut buf: [u8; 4096] = [0;4096];
    // Get all interfaces.
    let all_interfaces = datalink::interfaces();
    // Open raw socket.
    let s = unsafe {
        libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (libc::ETH_P_ALL as u16).to_be() as i32)
    };
    
    // Taken from: https://docs.rs/pnet_datalink/0.29.0/src/pnet_datalink/linux.rs.html#100
    // If interface is specified, bind the socket to it so we only receive traffic on that interface.
    if let Some(i) = interface {
        let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let len = unsafe {
            let sll: *mut libc::sockaddr_ll = mem::transmute(&mut addr);
            (*sll).sll_family = libc::AF_PACKET as libc::sa_family_t;
            if let Some(MacAddr(a, b, c, d, e, f)) = i.mac {
                (*sll).sll_addr = [a, b, c, d, e, f, 0, 0];
            }
            (*sll).sll_protocol = (libc::ETH_P_ALL as u16).to_be();
            (*sll).sll_halen = 6;
            (*sll).sll_ifindex = i.index as i32;
            mem::size_of::<libc::sockaddr_ll>()
        };
        let send_addr = (&addr as *const libc::sockaddr_storage) as *const libc::sockaddr;

        // Bind to interface
        if unsafe { libc::bind(s, send_addr, len as libc::socklen_t) } == -1 {
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(s);
            }
            eprintln!("Could not bind to interface: {}", err);
            std::process::exit(1);
        }
    }

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match socket::recvfrom(s, &mut buf) {
            Ok((size, if_addr)) => {
                // Find interface.
                let if_index = { 
                    if let SockAddr::Link(LinkAddr(addr)) = if_addr.unwrap() {
                        LinkAddr(addr).ifindex() as u32
                    } else {
                        0
                    }
                };
                let iface = all_interfaces.iter().find(|i| i.index == if_index).unwrap().clone();

                // Construct Ethernet frame to put in the MatcherFrame.
                let p = EthernetPacket::new(&buf[0..size - 1]).unwrap();
                let eth = Eth {
                    destination: p.get_destination(),
                    source: p.get_source(),
                    ethertype: p.get_ethertype(),
                    payload: p.payload().to_vec(),
                };

                // Check if packet is in- or egress.
                let egress = {
                    if let SockAddr::Link(LinkAddr(sockaddr_ll)) = if_addr.unwrap() {
                        // 4 is PACKET_OUTGOING
                        match sockaddr_ll.sll_pkttype {
                            4 => true,
                            _ => false,
                        }
                    } else {
                        false
                    }
                };

                // Construct the MatcherFrame.
                let time = Duration::from(time::clock_gettime(time::ClockId::CLOCK_MONOTONIC).unwrap());
                let packet = MatcherFrame {
                    frame: eth,
                    timestamp: time,
                    direct_match_pid: None,
                    indirect_match_pid: None,
                    matched_event: None,
                    egress: egress,
                    len: size.try_into().unwrap(),
                    l4_src_port: None,
                    l4_dst_port: None,
                    l3_src_ip: None,
                    l3_dst_ip: None,
                    dq_timestamp: match egress {
                        true => Some(Instant::now()),
                        false => None,
                    },
                    packet_type: PacketTypes::Other,
                    match_reason: MatchReason::NONE,
                    match_time: Duration::new(0,0),
                    interface: iface,
                };
                // Lock is dropped immediately after q.push(packet), no need for a
                // separate scope.
                let mut q = delay_queue.lock();
                q.push(packet);

            },
            Err(e) => eprintln!("Error receiving packet: {}", e),
        }
    }
}
