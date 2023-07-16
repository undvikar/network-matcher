use pnet::packet::ethernet::Ethernet;
use pnet::datalink::NetworkInterface;
use kernel_probes::queue_xmit::XmitEvent;
use std::net::IpAddr;
use std::time::{Instant, Duration};
use std::fmt;
use std::option::Option;

#[derive(Clone)]
pub struct MatcherFrame {
    pub frame: Ethernet,
    // Used as timestamp for output and for traffic history timeout.
    // Generated with time::clock_gettime.
    pub timestamp: Duration,
    pub direct_match_pid: Option<u32>,
    pub indirect_match_pid: Option<u32>,
    pub matched_event: Option<XmitEvent>,
    pub egress: bool,
    pub len: u32,
    pub dq_timestamp: Option<Instant>,
    pub l4_src_port: Option<u16>,
    pub l4_dst_port: Option<u16>,
    pub l3_src_ip: Option<IpAddr>,
    pub l3_dst_ip: Option<IpAddr>,
    pub packet_type: PacketTypes,
    pub match_reason: MatchReason,
    pub match_time: Duration,
    pub interface: NetworkInterface,
}

// Print things with hex values where needed.
impl fmt::Debug for MatcherFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MatcherFrame")
            .field("frame", &format_args!("{:x?}", &self.frame))
            .field("timestamp", &format_args!("{:?}", &self.timestamp.as_nanos()))
            .field("direct_match_pid", &self.direct_match_pid)
            .field("indirect_match_pid", &self.indirect_match_pid)
            .field("matched_event", &self.matched_event)
            .field("egress", &self.egress)
            .field("len", &self.len)
            .field("dq_timestamp", &self.dq_timestamp)
            .field("l4_src_port", &self.l4_src_port)
            .field("l4_dst_port", &self.l4_dst_port)
            .field("l3_src_ip", &self.l3_src_ip)
            .field("l3_dst_ip", &self.l3_dst_ip)
            .field("packet_type", &self.packet_type)
            .field("match_reason", &self.match_reason)
            .field("match_time", &self.match_time)
            .field("interface", &self.interface)
            .finish()
    }
}

#[derive(Debug)]
pub enum PacketTypes {
    ARP,
    ICMP,
    ICMPv6,
    UDP,
    TCP,
    // Packet type is to be determined.
    Other 
}

impl Clone for PacketTypes {
    fn clone(self: &PacketTypes) -> PacketTypes {
        *self
    }
}

impl Copy for PacketTypes { }

impl fmt::Display for PacketTypes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let print = match *self {
            PacketTypes::ARP => "ARP",
            PacketTypes::ICMP => "ICMP",
            PacketTypes::ICMPv6 => "ICMPv6",
            PacketTypes::UDP => "UDP",
            PacketTypes::TCP => "TCP",
            PacketTypes::Other => "Other",
        };
        write!(f, "{}", print)
    }
}

#[derive(Debug)]
pub enum MatchReason {
    TcpAck,
    SameFlow,
    IcmpErrPayload,
    IcmpEchoReply,
    LoopbackCounterpart,
    Direct,
    ArpIndirect,
    NONE,
}
impl Copy for MatchReason { }

impl Clone for MatchReason {
    fn clone(self: &MatchReason) -> MatchReason {
        *self
    }
}

impl fmt::Display for MatchReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let print = match *self {
            MatchReason::TcpAck => "TCP_ACK",
            MatchReason::SameFlow => "SAME_FLOW",
            MatchReason::IcmpErrPayload => "ICMP_ERR_PAYLOAD",
            MatchReason::IcmpEchoReply => "ICMP_ECHO_REPLY",
            MatchReason::LoopbackCounterpart => "LOOPBACK_COUNTERPART",
            MatchReason::Direct => "DIRECT",
            MatchReason::ArpIndirect => "ARP_INDIRECT",
            MatchReason::NONE => "",
        };
        write!(f, "{}", print)
    }
}
