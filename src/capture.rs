use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::Device;
use std::net::IpAddr;
use std::sync::Arc;

use crate::model::{Attribution, Protocol, StatsMap};
use crate::parse::handle_dns_packet;

pub fn spawn_capture_thread(device: Device, stats: StatsMap, attribution: Arc<Attribution>) {
    std::thread::spawn(move || {
        let device_name = device.name.clone();
        let mut cap = pcap::Capture::from_device(device)
            .expect(&format!(
                "Could not create Capture from device {}",
                device_name
            ))
            .promisc(true)
            .immediate_mode(true)
            .open()
            .expect(&format!(
                "Could not activate Capture from device {}",
                device_name
            ));

        while let Ok(packet) = cap.next_packet() {
            let Ok(sliced) = SlicedPacket::from_ethernet(packet.data) else {
                continue;
            };

            let (src_ip, dst_ip) = match &sliced.net {
                Some(NetSlice::Ipv4(v4)) => (
                    IpAddr::V4(v4.header().source_addr()),
                    IpAddr::V4(v4.header().destination_addr()),
                ),
                Some(NetSlice::Ipv6(v6)) => (
                    IpAddr::V6(v6.header().source_addr()),
                    IpAddr::V6(v6.header().destination_addr()),
                ),
                _ => continue,
            };

            let (protocol, src_port, dst_port, payload, transport_len) = match &sliced.transport {
                Some(TransportSlice::Tcp(t)) => (
                    Protocol::Tcp,
                    t.source_port(),
                    t.destination_port(),
                    t.payload(),
                    packet.data.len(),
                ),
                Some(TransportSlice::Udp(u)) => (
                    Protocol::Udp,
                    u.source_port(),
                    u.destination_port(),
                    u.payload(),
                    packet.data.len(),
                ),
                _ => continue,
            };

            // Determine direction
            let Some(remote_ip) = attribution.remote_ip(src_ip, dst_ip) else {
                continue;
            };
            let is_outgoing = remote_ip == dst_ip;

            // Resolve hostname
            let hostname = attribution.resolve(&remote_ip).or_else(|| {
                if protocol == Protocol::Udp && (src_port == 53 || dst_port == 53) {
                    handle_dns_packet(payload, &attribution);
                }
                attribution.resolve(&remote_ip)
            });

            // Update stats
            let mut entry = stats.entry(remote_ip).or_default();
            if is_outgoing {
                entry.bytes_sent += transport_len as u64;
            } else {
                entry.bytes_received += transport_len as u64;
            }
            entry.packets += 1;
            if hostname.is_some() {
                entry.hostname = hostname;
            }
        }
    });
}
