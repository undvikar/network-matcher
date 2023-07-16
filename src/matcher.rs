use pnet::packet::{
    ethernet::{EtherType, EtherTypes},
    icmp::IcmpPacket,
    icmp::IcmpTypes,
    icmpv6::Icmpv6Packet,
    icmpv6::Icmpv6Types,
    ipv4::Ipv4Packet, 
    ipv6::Ipv6Packet,
    ip::{IpNextHeaderProtocols, IpNextHeaderProtocol},
    tcp::{TcpPacket, TcpFlags},
    udp::UdpPacket,
    Packet,
};

use crate::structs::{
    delay_queue::DelayQueue,
    unmatched::UnmatchedEvents,
    matcher_frame::{MatcherFrame, PacketTypes, MatchReason},
    traffic_history::TrafficHistory,
};

use kernel_probes::queue_xmit::XmitEvent;
use std::net::IpAddr;
use std::thread;
use std::time::{Duration, Instant};
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use parking_lot::{Mutex, RwLock};
use parking_lot::lock_api::RwLockUpgradableReadGuard;
use crossbeam_channel::Sender;

// All functions of the form functionv4 are the same as functionv6 regarding
// how they work. It is easier to split it up like this, otherwise we get issues
// with the Rust type system because of different sizes of Ipv4Packet and Ipv6Packet
// that need to be resolved more elaborately.

// Match frames.
// Returns no value.
pub fn matching(history: Arc<TrafficHistory>,
            delay_queue: Arc<Mutex<DelayQueue>>,
            unmatched: Arc<RwLock<UnmatchedEvents>>,
            tx: Sender<MatcherFrame>,
            stop: &AtomicBool,
            is_main_matcher: bool,
            clean: Option<Duration>,
) {

    thread::sleep(Duration::new(3,0));
    // Some statistics.
    let mut last_clean = Instant::now();
    let mut expired_events = 0;
    let mut total_history_clean_time = Duration::new(0,0);
    let mut num_history_cleans = 0;
    'main: loop {
        // Check for timeouts only if this is the 'main' matcher thread.
        if is_main_matcher {
            let now = Instant::now();
            // Main matcher thread always gets a clean value of Some(x).
            if now.duration_since(last_clean) > clean.unwrap() {
                // Clean unmatched events.
                {
                    let mut q = unmatched.write();
                    expired_events += q.check_timeouts();
                }
                // Clean traffic history.
                let start_clean = Instant::now();
                history.check_timeouts();
                total_history_clean_time += start_clean.elapsed();
                num_history_cleans += 1;
                last_clean = Instant::now();
            }
        }

        let mut frame: Option<MatcherFrame>;
        if stop.load(Ordering::Relaxed) {
            break 'main;
        }
        loop {
            // Small scope so we drop the lock immediately after
            // receiving a frame.
            {
                frame = delay_queue.lock().pop();
            }
            match frame {
                Some(_) => break,
                None => {
                    thread::sleep(Duration::from_millis(20));
                    // Check for termination.
                    if stop.load(Ordering::Relaxed) {
                        break 'main;
                    }
                    continue;
                },
            }
        }

        let mut frame = frame.unwrap();
        // Create a copy of the frame which we use to retrieve information.
        // Necessary because of borrowing rules when using libpnet.
        let framecopy = frame.clone();
        let _ptype = get_info(&mut frame, &framecopy);
        let matchtime = Instant::now();

        // Attempt direct matching if the frame is egress.
        if frame.egress {
            match direct_match(&mut frame, &unmatched) {
                Some(0) => {
                    // If matched to PID 0, return ()
                    // so indirect matching is tried next.
                    ()
                },
                // This part is commented out to avoid the wrong direct matchings 
                // caused by the eBPF helper functions. As a result, every frame is also
                // matched indirectly even if the direct matching resulted in a PID != 0.
                // While it causes a little bit of overhead, this ensures more accurate
                // matchings overall.
                Some(_) => {
                    // frame.match_time = matchtime.elapsed();
                    // let outputframe = frame.clone();
                    // history.insert_in(frame);
                    // // Send frame to the output thread.
                    // match tx.send(outputframe) {
                    //     Ok(_) => () ,
                    //     Err(e) => {
                    //         eprintln!("Error {}, no more data will be sent.", e);
                    //         ()
                    //     },
                    // }
                    // continue;
                    ()
                },
                None => {
                    // If matched to nothing, return ()
                    // so indirect matching is tried next.
                    ()
                },
            }
        }
        // Attempt indirect matching.
        match indirect_match(&mut frame, &framecopy, &history) {
            Some(_) => {
                frame.match_time = matchtime.elapsed();
                let outputframe = frame.clone();
                history.insert_in(frame);
                // Send frame to the output thread.
                match tx.send(outputframe) {
                    Ok(_) => (),
                    Err(e) => {
                        eprintln!("Error {}, no more data will be sent.", e);
                        ()
                    }
                }
                continue;
            },
            None => {
                // If matched to nothing, still insert it in 
                // traffic history because future frames may be 
                // matched to this one.
                let outputframe = frame.clone();
                frame.match_time = matchtime.elapsed();
                history.insert_in(frame);
                // Send frame to the output thread.
                match tx.send(outputframe) {
                    Ok(_) => (),
                    Err(e) => {
                        eprintln!("Error {}, no more data will be sent.", e);
                        ()
                    }
                }
            },
        }
    }
    // Thread has been stopped.
    // Currently the main matcher thread prints the expired events himself.
    // It could be implemented to send it to the output thread with a
    // wrapper type which is either MatcherFrame or the expired events count.
    // Need to synchronize to ensure the output thread receives the last message.
    if is_main_matcher {
        thread::sleep(Duration::from_millis(300));
        println!("{} events expired", expired_events);
        println!("average history cleaning time: {:?}", total_history_clean_time.checked_div(num_history_cleans));
    }
}

// Match a frame directly.
// Returns Some(pid) if match is found, None if not.
fn direct_match(frame: &mut MatcherFrame,
            unmatched: &Arc<RwLock<UnmatchedEvents>>) -> Option<u32> {

    let q = unmatched.upgradable_read();
    let qref = q.get_queue();

    for (i, event) in qref.iter().enumerate().rev() {
        if frame_matches_event(&event, &frame) {
            frame.direct_match_pid = Some(event.tgid);
            frame.match_reason = MatchReason::Direct;
            let mut w = RwLockUpgradableReadGuard::upgrade(q);
            w.queue.remove(i);
            break;
        }
    }
    frame.direct_match_pid
}

// Check if the provided frame matches the provided event.
// Returns true if the frame matches the given event, false if not.
fn frame_matches_event(event: &XmitEvent, frame: &MatcherFrame) -> bool {
    let event_ethtype = EtherType::new((event.data[12] as u16) << 8 | event.data[13] as u16);

    let (event_compare_index, payload_compare_index) = if frame.frame.payload.len() > 114 {
        ((event.copied_len - 1) as usize, (event.copied_len - 1 - 14) as usize)
    } else {
        if (event.copied_len as usize) < frame.frame.payload.len() {
            ((event.copied_len - 1) as usize, (event.copied_len - 1 - 14) as usize)
        } else {
            (frame.frame.payload.len() + 14 - 1, frame.frame.payload.len() - 1)
        }
    };
    if event.len == frame.len
        && frame.frame.destination.octets() == event.data[0..6]
        && frame.frame.source.octets() == event.data[6..12]
        && frame.frame.ethertype == event_ethtype
        && event.data[14..event_compare_index] == frame.frame.payload[0..payload_compare_index] {
            return true;
    }
    false
}

// Fill in metadata fields of the frame we received. All other functions called
// get_x_info retrieve the info specific to a protocol or layer.
// Returns the frame's packet type as Some(type) or None if unknown.
fn get_info(frame: &mut MatcherFrame, framecopy: &MatcherFrame) -> Option<PacketTypes> {
    match frame.frame.ethertype {
        EtherTypes::Arp => {
            frame.packet_type = PacketTypes::ARP;
            return Some(frame.packet_type);
        },
        EtherTypes::Ipv4 => get_ipv4_info(frame, framecopy),
        EtherTypes::Ipv6 => get_ipv6_info(frame, framecopy),
        _ => None,
    }
}

// Gets IPv4-specific info and adds it to the frame.
// Returns the frame's packet type as Some(type) or None if unknown.
fn get_ipv4_info(frame: &mut MatcherFrame, framecopy: &MatcherFrame) -> Option<PacketTypes> {
    let pack = Ipv4Packet::new(&framecopy.frame.payload)?;
    frame.l3_src_ip = Some(IpAddr::V4(pack.get_source()));
    frame.l3_dst_ip = Some(IpAddr::V4(pack.get_destination()));
    return get_transport_info(pack.get_next_level_protocol(), pack.payload(), frame);
}

// Gets IPv6-specific info and adds it to the frame.
// Returns the frame's packet type as Some(type) or None if unknown.
fn get_ipv6_info(frame: &mut MatcherFrame, framecopy: &MatcherFrame) -> Option<PacketTypes> {
    let pack = Ipv6Packet::new(&framecopy.frame.payload)?;
    frame.l3_src_ip = Some(IpAddr::V6(pack.get_source()));
    frame.l3_dst_ip = Some(IpAddr::V6(pack.get_destination()));
    return get_transport_info(pack.get_next_header(), pack.payload(), frame);
}

// Get L4-specific info and adds it to the frame.
// Returns the frame's packet type as Some(type) or None if unknown.
fn get_transport_info(prot: IpNextHeaderProtocol, packet: &[u8], frame: &mut MatcherFrame) -> Option<PacketTypes> {
    match prot {
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(packet)?;
            frame.packet_type = PacketTypes::UDP;
            frame.l4_src_port = Some(udp.get_source());
            frame.l4_dst_port = Some(udp.get_destination());
            return Some(frame.packet_type);
        }
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(packet)?;
            frame.packet_type = PacketTypes::TCP;
            frame.l4_src_port = Some(tcp.get_source());
            frame.l4_dst_port = Some(tcp.get_destination());
            return Some(frame.packet_type);
        }
        IpNextHeaderProtocols::Icmp => {
            frame.packet_type = PacketTypes::ICMP;
            return Some(frame.packet_type);
        }
        IpNextHeaderProtocols::Icmpv6 => {
            frame.packet_type = PacketTypes::ICMPv6;
            return Some(frame.packet_type);
        }
        _ => return None,
    }
}

// Match a frame indirectly.
// Returns the PID it was matched to as Some(pid) or None if not.
pub fn indirect_match(frame: &mut MatcherFrame, framecopy: &MatcherFrame, history: &Arc<TrafficHistory>) -> Option<u32> {
    if frame.interface.is_loopback() {
        return match_loopback_counterpart(frame, history);
    }

    match frame.frame.ethertype {
        EtherTypes::Ipv4 => match_ip_packet(frame, framecopy, history),
        EtherTypes::Ipv6 => match_ip_packet(frame, framecopy, history),
        EtherTypes::Arp => {
            // Outgoing ARP frames are matched directly to PID 0 and already have the `match_reason` field set.
            // Incoming ARP frames are not matched yet and need to have the following fields set so that
            // they are displayed correctly in the output.
            match frame.direct_match_pid {
                Some(_) => frame.indirect_match_pid,
                None => {
                    frame.match_reason = MatchReason::ArpIndirect;
                    frame.indirect_match_pid = Some(0);
                    frame.indirect_match_pid
                },
            }
        },
        _ => None,
    }
    
}

// Match an IP packet based on its L4 protocol.
// Returns the PID it was matched to as Some(pid) or None if not.
fn match_ip_packet(frame: &mut MatcherFrame, framecopy: &MatcherFrame, history: &Arc<TrafficHistory>) -> Option<u32> {
    match frame.packet_type {
        PacketTypes::TCP => {
            match frame.frame.ethertype {
                EtherTypes::Ipv4 => match match_tcp_ackv4(frame, framecopy, history) {
                    Some(0) => match_flow(frame, history),
                    Some(n) => Some(n),
                    None => match_flow(frame, history),
                },
                EtherTypes::Ipv6 => match match_tcp_ackv6(frame, framecopy, history) {
                    Some(0) => match_flow(frame, history),
                    Some(n) => Some(n),
                    None => match_flow(frame, history),
                },
                _ => None,
            }
        },
        PacketTypes::UDP => match_flow(frame, history),
        PacketTypes::ICMP => match_icmp(frame, framecopy, history),
        PacketTypes::ICMPv6 => match_icmpv6(frame, framecopy, history),
        _ => None,
    }
}

// Acknowledgement-based matching: find the frame which has been acknowledge if 'frame' contains an ACK flag (IPv6).
// Returns the PID it was matched to as Some(pid) or None if not.
fn match_tcp_ackv6(frame: &mut MatcherFrame, framecopy: &MatcherFrame, history: &Arc<TrafficHistory>) -> Option<u32> {
    let ip = Ipv6Packet::new(&framecopy.frame.payload)?;
    let tcp = TcpPacket::new(ip.payload())?;
    let flags = tcp.get_flags();
    if (flags & TcpFlags::ACK) != TcpFlags::ACK {
        return None;
    }
    let subset = match frame.egress {
        true => match history.get_subset(&frame.l4_src_port.unwrap()) {
            Some(s) => s,
            None => return frame.indirect_match_pid,
        }
        false => match history.get_subset(&frame.l4_dst_port.unwrap()) {
            Some(s) => s,
            None => return frame.indirect_match_pid,
        }
    };
    for f in subset.iter() {
        let ip_f = Ipv6Packet::new(&f.frame.payload)?;
        let tcp_f = TcpPacket::new(ip_f.payload())?;
        if same_flow(frame,f) {
            if tcp.get_acknowledgement()  == (tcp_f.get_sequence() + tcp_f.payload().len() as u32)  {
                apply_match(frame, f, MatchReason::TcpAck);
                break;
            }
        }
    }
    frame.indirect_match_pid
}

// Acknowledgement-based matching: find the frame which has been acknowledge if 'frame' contains an ACK flag (IPv4).
// Returns the PID it was matched to as Some(pid) or None if not.
fn match_tcp_ackv4(frame: &mut MatcherFrame, framecopy: &MatcherFrame, history: &Arc<TrafficHistory>) -> Option<u32> {
    let ip = Ipv4Packet::new(&framecopy.frame.payload)?;
    let tcp = TcpPacket::new(ip.payload())?;
    let flags = tcp.get_flags();
    if (flags & TcpFlags::ACK) != TcpFlags::ACK {
        // No ACK flag in matcher frame.
        return None;
    }
    let subset = match frame.egress {
        true => match history.get_subset(&frame.l4_src_port.unwrap()) {
            Some(s) => s,
            None => return frame.indirect_match_pid,
        },
        false => match history.get_subset(&frame.l4_dst_port.unwrap()) {
            Some(s) => s,
            None => return frame.indirect_match_pid,
        }
    };
    for f in subset.iter() {
        let ip_f = Ipv4Packet::new(&f.frame.payload)?;
        let tcp_f = TcpPacket::new(ip_f.payload())?;
        if same_flow(frame, f) {
            if tcp.get_acknowledgement()  == (tcp_f.get_sequence() + tcp_f.payload().len() as u32)  {
                apply_match(frame, f, MatchReason::TcpAck);
                break;
            }
        }
    }
    frame.indirect_match_pid
}

// Check if two frames belong to the same flow.
// Returns true if they do, false if not.
fn same_flow(f1: &MatcherFrame, f2: &MatcherFrame) -> bool {
    if f2.l4_src_port == None || f2.l4_dst_port == None {
        return false;
    }
    if f1.l4_src_port.unwrap() == f2.l4_src_port.unwrap()
        && f1.l4_dst_port.unwrap() == f2.l4_dst_port.unwrap()
        && f1.l3_src_ip.unwrap() == f2.l3_src_ip.unwrap()
        && f1.l3_dst_ip.unwrap() == f2.l3_dst_ip.unwrap()
    {
        true
    } else if
        f1.l4_src_port.unwrap() == f2.l4_dst_port.unwrap()
        && f1.l4_dst_port.unwrap() == f2.l4_src_port.unwrap()
        && f1.l3_src_ip.unwrap() == f2.l3_dst_ip.unwrap()
        && f1.l3_dst_ip.unwrap() == f2.l3_src_ip.unwrap()
    {
        true
    } else {
        false
    }
}

// Match the frame to a flow.
// Returns the PID it was matched to as Some(pid) or None if not.
fn match_flow(frame: &mut MatcherFrame, history: &Arc<TrafficHistory>) -> Option<u32> {
    let subset = match frame.egress {
        true => match history.get_subset(&frame.l4_src_port.unwrap()) {
            Some(s) => s,
            None => return frame.indirect_match_pid,
        },
        false => match history.get_subset(&frame.l4_dst_port.unwrap()){
            Some(s) => s,
            None => return frame.indirect_match_pid
        },
    };
    for f in subset.iter() {
        if same_flow(frame, f) {
            if match_on_pid_zero(f) {
                continue;
            } else {
                apply_match(frame, f, MatchReason::SameFlow);
                break;
            }
        }
    }
    frame.indirect_match_pid
}

// Match an ICMPv4 Packet.
// Returns the PID it was matched to as Some(pid) or None if not.
fn match_icmp(frame: &mut MatcherFrame, framecopy: &MatcherFrame, history: &Arc<TrafficHistory>) -> Option<u32> {
    let ip = Ipv4Packet::new(&framecopy.frame.payload)?;
    let icmp = IcmpPacket::new(ip.payload())?;
    match icmp.get_icmp_type() {
        IcmpTypes::EchoReply => match_echov4(frame, history),
        IcmpTypes::DestinationUnreachable => match_errorv4(frame, &icmp, history),
        IcmpTypes::SourceQuench => match_errorv4(frame, &icmp, history),
        IcmpTypes::RedirectMessage => match_errorv4(frame, &icmp, history),
        IcmpTypes::TimeExceeded => match_errorv4(frame, &icmp, history),
        _ => frame.indirect_match_pid,
    }
}

// Match an ICMPv6 Packet.
// Returns the PID it was matched to as Some(pid) or None if not.
fn match_icmpv6(frame: &mut MatcherFrame, framecopy: &MatcherFrame, history: &Arc<TrafficHistory>) -> Option<u32> {
    let ip = Ipv6Packet::new(&framecopy.frame.payload)?;
    let icmp = Icmpv6Packet::new(ip.payload())?;
    match icmp.get_icmpv6_type() {
        Icmpv6Types::EchoReply => match_echov6(frame, history),
        Icmpv6Types::DestinationUnreachable =>  match_errorv6(frame, &icmp, history),
        Icmpv6Types::PacketTooBig => match_errorv6(frame, &icmp, history),
        Icmpv6Types::TimeExceeded => match_errorv6(frame, &icmp, history),
        Icmpv6Types::ParameterProblem => match_errorv6(frame, &icmp, history),
        _ => frame.indirect_match_pid,
    }
}

// Match an ICMP Echo Reply to the corresponding Echo Request (IPv4).
// Returns the PID it was matched to as Some(pid) or None if not.
fn match_echov4(frame: &mut MatcherFrame, history: &Arc<TrafficHistory>) -> Option<u32> {
    'outer: for subset in history.iter() {
        for f in subset.iter() {
            let ip = Ipv4Packet::new(&f.frame.payload);
            let ip = match ip {
                None => continue,
                Some(pack) => pack,
            };
            let icmp = IcmpPacket::new(ip.payload());
            let icmp = match icmp {
                None => continue,
                Some(pack) => pack,
            };
            match icmp.get_icmp_type() {
                IcmpTypes::EchoRequest => {
                    apply_match(frame, f, MatchReason::IcmpEchoReply);
                    break 'outer;
                },
                _ => continue,
            }
        }
    }
    frame.indirect_match_pid
}

// Match an ICMP Echo Reply to the corresponding Echo Request (IPv6).
// Returns the PID it was matched to as Some(pid) or None if not.
fn match_echov6(frame: &mut MatcherFrame, history: &Arc<TrafficHistory>) -> Option<u32> {
    'outer: for subset in history.iter() {
        for f in subset.iter() {
            let ip = Ipv6Packet::new(&f.frame.payload);
            let ip = match ip {
                None => continue,
                Some(pack) => pack,
            };
            let icmpv6 = Icmpv6Packet::new(ip.payload());
            let icmpv6 = match icmpv6 {
                None => continue,
                Some(pack) => pack,
            };
            match icmpv6.get_icmpv6_type() {
                Icmpv6Types::EchoRequest => {
                    apply_match(frame, f, MatchReason::IcmpEchoReply);
                    break 'outer;
                }
                _ => continue,
            }
        }
    }
    frame.indirect_match_pid
}

// Match an ICMP Error to the frame which caused the error (IPv4).
// Returns the PID it was matched to as Some(pid) or None if not.
fn match_errorv4(frame: &mut MatcherFrame, icmp: &IcmpPacket, history: &Arc<TrafficHistory>) -> Option<u32> {
    // Construct the packet which caused the error.
    let ip = Ipv4Packet::new(icmp.payload())?;
    // If TCP/UDP was used, the source port can be retrieved,
    // doesnt matter which one we cast to, the ports are in the first 8 bytes of
    // the header.
    let pack = UdpPacket::new(ip.payload())?;
    let port = pack.get_source();
    let subset = match history.get_subset(&port) {
        Some(s) => s,
        None => return frame.indirect_match_pid,
    };
    // Compare the first 15 bytes as well as source and destination IP addresses.
    for f in subset.iter() {
        let ip_f = Ipv4Packet::new(&f.frame.payload)?;
        if ip_f.get_source() == ip.get_source()
            && ip_f.get_destination() == ip.get_destination()
            && ip_f.payload()[0..14] == ip.payload()[0..14]
        {
            apply_match(frame, f, MatchReason::IcmpErrPayload);
            break;
        }
    }
    frame.indirect_match_pid
}

// Match an ICMP Error to the frame which caused the error (IPv6).
// Returns the PID it was matched to as Some(pid) or None if not.
fn match_errorv6(frame: &mut MatcherFrame, icmp: &Icmpv6Packet, history: &Arc<TrafficHistory>) -> Option<u32> {
    let ip = Ipv6Packet::new(icmp.payload())?;
    let pack = UdpPacket::new(ip.payload())?;
    let port = pack.get_source();
    let subset = match history.get_subset(&port) {
        Some(s) => s,
        None => return frame.indirect_match_pid,
    };
    // Compare the first 15 bytes as well as source and destination IP addresses.
    for f in subset.iter() {
        let ip_f = Ipv6Packet::new(&f.frame.payload)?;
        if ip_f.get_source() == ip.get_source()
            && ip_f.get_destination() == ip.get_destination()
            && ip_f.payload()[0..14] == ip.payload()[0..14]
        {
            apply_match(frame, f, MatchReason::IcmpErrPayload);
            break;
        }
    }
    frame.indirect_match_pid
}

// Apply a matching: frame1 needs to be matched, frame2 is already matched.
// Returns no value.
fn apply_match(frame1: &mut MatcherFrame, frame2: &MatcherFrame, reason: MatchReason) {
    if let MatchReason::Direct = frame2.match_reason {
        frame1.indirect_match_pid = frame2.direct_match_pid;
    } else {
        frame1.indirect_match_pid = frame2.indirect_match_pid;
    }
    frame1.match_reason = reason;
}

// Match a loopback frame to its counterpart.
// Returns the PID it was matched to as Some(pid) or None if not.
fn match_loopback_counterpart(frame: &mut MatcherFrame, history: &Arc<TrafficHistory>) -> Option<u32> {
    let port = match frame.l4_src_port {
        Some(port) => port,
        None => 0,
    };
    let subset = match history.get_subset(&port) {
        Some(s) => s,
        None => return frame.indirect_match_pid,
    };

    for f in subset.iter() {
        if f.interface.is_loopback() {
            if is_same(frame, f) {
                apply_match(frame, f, MatchReason::LoopbackCounterpart);
                break;
            }
        }
    }
    frame.indirect_match_pid
    
}

// Check if two frames are the same, bytewise.
// Return true if they are the same, false otherwise.
fn is_same(frame1: &mut MatcherFrame, frame2: &MatcherFrame) -> bool {
    let f1len = frame1.frame.payload.len() as usize;
    let f2len = frame2.frame.payload.len() as usize;
    if frame1.len == frame2.len 
        && frame1.l3_src_ip == frame2.l3_src_ip
        && frame1.l3_dst_ip == frame2.l3_dst_ip
        && frame1.l4_src_port == frame2.l4_src_port
        && frame1.l4_dst_port == frame2.l4_dst_port
        && frame1.frame.payload[0..f1len] == frame2.frame.payload[0..f2len]
    {
        true
    } else {
        false
    }
}


// In the calling function, a frame is about to be matched to 'frame'.
// Returns true if 'frame' was matched to PID 0 or no PID, false otherwise.
//
// Done so that the calling function can search for a frame which was matched
// to a PID != 0.
fn match_on_pid_zero(frame: &MatcherFrame) -> bool {
    if let MatchReason::Direct = frame.match_reason {
        match frame.direct_match_pid {
            Some(0) => true,
            None => true,
            Some(_) => false,
        }
    } else {
        match frame.indirect_match_pid {
            Some(0) => true,
            None => true,
            Some(_) => false,
        }
    }
}
