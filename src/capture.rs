use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use std::net::IpAddr;
use std::sync::Arc;

use crate::model::{Attribution, Protocol, RemoteEndpoint, StatsMap};
use crate::parse::{extract_sni, handle_dns_packet, strip_link_layer};

pub fn spawn_capture_thread(device_name: &str, stats: StatsMap, attribution: Arc<Attribution>) {
    let device_name = device_name.to_string();
    std::thread::spawn(move || {
        let device = pcap::Device::list()
            .expect("No devices found")
            .into_iter()
            .find(|d| d.name == device_name)
            .expect(&format!("Device {} not found", device_name));

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

        let linktype = cap.get_datalink();

        while let Ok(packet) = cap.next_packet() {
            let Some(ip_data) = strip_link_layer(packet.data, linktype) else {
                continue;
            };
            let Ok(sliced) = SlicedPacket::from_ip(ip_data) else {
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

            // Feed attribution engine (as before)
            if protocol == Protocol::Udp && (src_port == 53 || dst_port == 53) {
                handle_dns_packet(payload, &attribution);
            }
            if protocol == Protocol::Tcp && dst_port == 443 && !payload.is_empty() {
                if let Some(hostname) = extract_sni(payload) {
                    attribution.record_sni(
                        RemoteEndpoint {
                            ip: dst_ip,
                            port: dst_port,
                            protocol,
                        },
                        hostname,
                    );
                }
            }

            // Determine direction + remote IP
            let Some(remote_ip) = attribution.remote_ip(src_ip, dst_ip) else {
                continue;
            };
            let is_outgoing = remote_ip == dst_ip; // we are the source

            let remote_port = if is_outgoing { dst_port } else { src_port };
            let endpoint = RemoteEndpoint {
                ip: remote_ip,
                port: remote_port,
                protocol,
            };
            let hostname = attribution.resolve(&endpoint);

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
