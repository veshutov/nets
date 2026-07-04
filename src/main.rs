use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use std::collections::HashSet;
use std::net::IpAddr;

mod model;
mod parse;

use crate::model::{Attribution, Protocol, RemoteEndpoint};
use crate::parse::{extract_sni, handle_dns_packet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device_name = "en0"; // or "en0" depending on what you're monitoring
    let device = pcap::Device::list()?
        .into_iter()
        .find(|d| d.name == device_name)
        .expect("device not found");

    // Collect this machine's own IPs so we know which side of a packet is "remote"
    let local_ips: HashSet<IpAddr> = device.addresses.iter().map(|a| a.addr).collect();
    let attribution = Attribution::new(local_ips);

    let mut cap = pcap::Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .immediate_mode(true)
        .open()?;

    let linktype = cap.get_datalink();

    while let Ok(packet) = cap.next_packet() {
        let Some(ip_data) = strip_link_layer(packet.data, linktype) else {
            continue;
        };
        let Ok(sliced) = SlicedPacket::from_ip(ip_data) else {
            continue;
        };

        let (src_ip, dst_ip) = match &sliced.net {
            Some(InternetSlice::Ipv4(ipv4)) => (
                IpAddr::V4(ipv4.header().source_addr()),
                IpAddr::V4(ipv4.header().destination_addr()),
            ),
            Some(InternetSlice::Ipv6(ipv6)) => (
                IpAddr::V6(ipv6.header().source_addr()),
                IpAddr::V6(ipv6.header().destination_addr()),
            ),
            _ => continue, // ARP or no network layer parsed — skip
        };

        let (protocol, src_port, dst_port, payload) = match &sliced.transport {
            Some(TransportSlice::Tcp(t)) => (
                Protocol::Tcp,
                t.source_port(),
                t.destination_port(),
                t.payload(), // payload is now a method, not a field
            ),
            Some(TransportSlice::Udp(u)) => (
                Protocol::Udp,
                u.source_port(),
                u.destination_port(),
                u.payload(),
            ),
            _ => continue,
        };

        // --- Feed the attribution engine ---
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

        // --- Resolve and display ---
        if let Some(remote_ip) = attribution.remote_ip(src_ip, dst_ip) {
            let remote_port = if src_ip == remote_ip {
                src_port
            } else {
                dst_port
            };
            let endpoint = RemoteEndpoint {
                ip: remote_ip,
                port: remote_port,
                protocol,
            };

            let label = attribution
                .resolve(&endpoint)
                .unwrap_or_else(|| remote_ip.to_string());
            println!("[{:?}] {}:{} -> {}", protocol, src_ip, src_port, label);
        }
    }

    Ok(())
}

fn strip_link_layer(data: &[u8], linktype: pcap::Linktype) -> Option<&[u8]> {
    match linktype {
        pcap::Linktype::ETHERNET => data.get(14..),
        pcap::Linktype::NULL | pcap::Linktype::LOOP => data.get(4..),
        pcap::Linktype::RAW => Some(data),
        _ => None,
    }
}
