use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::process::{Command, Stdio};
use std::time::{Instant, Duration};
use crate::structs::{
    matcher_frame::MatcherFrame,
    matcher_frame::PacketTypes,
    process::{ProcessTable, ProcessEntry},
    output::Config,
};
use pnet::util::MacAddr;
use crossbeam_channel::{Receiver, RecvError};

// Print frame information.
// Returns Result<RecvError> upon stopping to inform the main thread that the channel is closed.
pub fn output(receiver: Receiver<MatcherFrame>, stop: &AtomicBool, mut conf: Config) -> Result<(), RecvError> {
    let mut direct_matches: u64 = 0;
    let mut indirect_matches: u64 = 0;
    // first directly, then indirectly matched frames
    let mut both_matches: u64 = 0;
    let mut processed_frames: u64 = 0;
    let mut arp_frames: u64 = 0;
    let mut icmp_frames: u64 = 0;
    let mut icmpv6_frames: u64 = 0;
    let mut udp_frames: u64 = 0;
    let mut tcp_frames: u64 = 0;
    let mut other_frames: u64 = 0;
    let mut pid_zero_direct: u64 = 0;
    let mut pid_zero_indirect: u64 = 0;
    let mut unmatched: u64 = 0;
    let mut total_matching_time: Duration = Duration::new(0,0);
    let process_table = ProcessTable::new();
    let mut last_process_clean = Instant::now();

    if !conf.quiet {
            println!("{:<15} {:<10} {:<10} {:<10} {:<10} {:<11} {:<22}    {:<22} {:<7} {:<15} {:<10}",
            "TIMESTAMP", "INTERFACE", "DIRECTION", "DIRECT", "INDIRECT", "PACKET_TYPE", "SOURCE", "DESTINATION", "LENGTH", "PROCESS", "CAUSE");
    }
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        // recv call is blocking, no need to sleep at the start of the program.
        // That is why we check for stopping in the Err block; if the producer
        // end is shutdown while we are waiting for a frame, it will return an
        // error.
        let frame = receiver.recv();
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                eprintln!("Error: {}.", e);
                return Err(e);
            },
        };

        // Stats.
        processed_frames += 1;
        total_matching_time = total_matching_time.saturating_add(frame.match_time);
        // Needed to resolve PID into process name.
        let mut match_pid = None;
        if matches!(frame.direct_match_pid, Some(_)) && matches!(frame.indirect_match_pid, Some(_)) {
            both_matches += 1;
            match_pid = frame.indirect_match_pid;
        } else if matches!(frame.direct_match_pid, Some(_)) && matches!(frame.indirect_match_pid, None){
            match_pid = frame.direct_match_pid;
            match frame.direct_match_pid {
                Some(0) => pid_zero_direct += 1,
                Some(_) => direct_matches += 1,
                None => (),
            }
        } else if matches!(frame.direct_match_pid, None) && matches!(frame.indirect_match_pid, Some(_)) {
            match_pid = frame.indirect_match_pid;
            match frame.indirect_match_pid {
                Some(0) => pid_zero_indirect += 1,
                Some(_) => indirect_matches += 1,
                None => (),
            }
        } else if matches!(frame.direct_match_pid, None) && matches!(frame.indirect_match_pid, None) {
            unmatched += 1;
        }

        // Only resolve process name if output is shown.
        let process_name: String = if !conf.quiet {
            // Get process name.
            let name = match match_pid {
                Some(pid) => {
                    // First query process table.
                    match process_table.get_name(pid) {
                        Some(name) => name,
                        // If we get no result, resolve process name directly.
                        None => {
                            if let Some(proc_name) = get_process_name(&pid) {
                                let name = proc_name.clone();
                                let process = ProcessEntry::new(proc_name);
                                // add process to table
                                process_table.add(pid, process);
                                name
                            } else {
                                "".to_string()
                            }
                        },
                    }
                },
                None => String::from(""),
            };
            // Check for timeouts in our map for processes.
            let now = Instant::now();
            if now.duration_since(last_process_clean) > process_table.timeout {
                process_table.check_timeouts();
                last_process_clean = Instant::now();
            }
            name
        } else {
            String::from("")
        };

        match frame.packet_type {
            PacketTypes::ARP => arp_frames += 1,
            PacketTypes::ICMP => icmp_frames +=1,
            PacketTypes::ICMPv6 => icmpv6_frames += 1,
            PacketTypes::UDP => udp_frames += 1,
            PacketTypes::TCP => tcp_frames += 1,
            PacketTypes::Other => other_frames += 1,
        }

        let direction = match frame.egress {
            true => "egress",
            false => "ingress",
        };

        let pid_direct = match frame.direct_match_pid {
            Some(pid) => pid.to_string(),
            None => "".to_string(),
        };
        let pid_indirect = match frame.indirect_match_pid {
            Some(pid) => pid.to_string(),
            None => "".to_string(),
        };

        // Prettier formatting based on packet type.
        let src_addr = match frame.packet_type {
            PacketTypes::UDP => frame.l3_src_ip.unwrap().to_string() + ":" + &frame.l4_src_port.unwrap().to_string(),
            PacketTypes::TCP => frame.l3_src_ip.unwrap().to_string() + ":" + &frame.l4_src_port.unwrap().to_string(),
            PacketTypes::ICMP => frame.l3_src_ip.unwrap().to_string(),
            PacketTypes::ICMPv6 => frame.l3_src_ip.unwrap().to_string(),
            _ => format_mac(frame.frame.source),
        };
        let dst_addr = match frame.packet_type {
            PacketTypes::UDP => frame.l3_dst_ip.unwrap().to_string() + ":" + &frame.l4_dst_port.unwrap().to_string(),
            PacketTypes::TCP => frame.l3_dst_ip.unwrap().to_string() + ":" + &frame.l4_dst_port.unwrap().to_string(),
            PacketTypes::ICMP => frame.l3_dst_ip.unwrap().to_string(),
            PacketTypes::ICMPv6 => frame.l3_dst_ip.unwrap().to_string(),
            _ => format_mac(frame.frame.destination),
        };
        let packet_type = format!("{:?}", frame.packet_type);
        let time = frame.timestamp.as_nanos();


        if !conf.quiet {
            let formatted_output = format!("{:<15} {:<10} {:<10} {:<10} {:<10} {:11} {:<22} -> {:<22} {:<7} {:<15} {:<10} ",
                time, frame.interface.name, direction, pid_direct, pid_indirect, packet_type, src_addr, dst_addr, frame.len, 
                process_name, frame.match_reason);
            println!("{}", formatted_output);
        }
        if let Some((ref mut file, separator)) = conf.output_file {
            let file_output = format!("{}{s}{}{s}{}{s}{}{s}{}{s}{}{s}{}{s}{}{s}{}{s}{}{s}{}\n",
                time, frame.interface.name, direction, pid_direct, pid_indirect, packet_type, src_addr, dst_addr, frame.len,
                process_name, frame.match_reason,
                s=separator);
            match file.write(&file_output.as_str().as_bytes()) {
                Ok(_) => (),
                Err(e) => eprintln!("Error writing to file: {}", e),
            }
        }

    }
    let avg_matching_time = total_matching_time.as_nanos() / u128::from(processed_frames);
    println!("{} frames processed:", processed_frames);
    println!("ARP: {}", arp_frames);
    println!("ICMP: {}", icmp_frames);
    println!("ICMPv6: {}", icmpv6_frames);
    println!("UDP: {}", udp_frames);
    println!("TCP: {}", tcp_frames);
    println!("Other: {}", other_frames);
    println!("{} frames matched, {} directly, {} indirectly, {} both.",
        direct_matches + indirect_matches + both_matches,
        direct_matches,
        indirect_matches, 
        both_matches);
    println!("{} matched directly to PID 0, {} indirectly to PID 0.", pid_zero_direct, pid_zero_indirect);
    println!("{} frames unmatched", unmatched);
    println!("{} ns average matching time", avg_matching_time);
    Ok(())
}

// Returns a nicely formatted MAC.
fn format_mac(mac: MacAddr) -> String {
    let bytes = mac.octets();
    format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])

}

// Returns the process name of the provided PID.
fn get_process_name(pid: &u32) -> Option<String> {
    if *pid == 0 {
        return Some(String::from("[Kernel]"));
    }
    let ps = Command::new("ps")
        .arg("--no-headers")
        .arg("-o")
        .arg("command")
        .arg(pid.to_string())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to execute ps");
    let ps_stdout = ps.stdout.expect("Failed to open ps stdout");
    let awk = Command::new("awk")
        .arg("{print $1}")
        .stdin(Stdio::from(ps_stdout))
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start awk");
    let output = awk.wait_with_output().expect("Failed to wait on awk stdout");
    // Always appends a newline, therefore take all but the last byte.
    if output.stdout.len() == 0 {
        return None;
    }
    let len = output.stdout.len() - 1;
    Some(String::from_utf8_lossy(&output.stdout[..len]).to_string())
}
