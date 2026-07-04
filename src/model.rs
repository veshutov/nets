use dashmap::DashMap;
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct RemoteEndpoint {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
}

pub struct Attribution {
    /// remote_ip:port:proto -> hostname (populated by SNI extraction)
    flow_cache: DashMap<RemoteEndpoint, String>,
    /// remote_ip -> hostname (populated by DNS response parsing)
    dns_cache: DashMap<IpAddr, String>,
    /// IPs belonging to this machine, so we know which side of a packet is "remote"
    local_ips: HashSet<IpAddr>,
}

impl Attribution {
    pub fn new(local_ips: HashSet<IpAddr>) -> Self {
        Self {
            flow_cache: DashMap::new(),
            dns_cache: DashMap::new(),
            local_ips,
        }
    }

    pub fn record_sni(&self, remote: RemoteEndpoint, hostname: String) {
        self.flow_cache.insert(remote, hostname);
    }

    pub fn record_dns(&self, ip: IpAddr, hostname: String) {
        self.dns_cache.insert(ip, hostname);
    }

    pub fn resolve(&self, remote: &RemoteEndpoint) -> Option<String> {
        if let Some(h) = self.flow_cache.get(remote) {
            return Some(h.clone());
        }
        self.dns_cache.get(&remote.ip).map(|h| h.clone())
    }

    /// Given the two IPs in a packet, figure out which one is "remote"
    pub fn remote_ip(&self, src: IpAddr, dst: IpAddr) -> Option<IpAddr> {
        if self.local_ips.contains(&src) {
            Some(dst)
        } else if self.local_ips.contains(&dst) {
            Some(src)
        } else {
            None // neither side is us (multicast/broadcast, etc.) — skip
        }
    }
}
