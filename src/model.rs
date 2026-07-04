use dashmap::DashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

pub type HostName = String;

pub type StatsMap = Arc<DashMap<IpAddr, HostStats>>;

#[derive(Default, Clone)]
pub struct HostStats {
    pub hostname: Option<HostName>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets: u64,
}

impl HostStats {
    pub fn total(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub enum Protocol {
    Tcp,
    Udp,
}

pub struct Attribution {
    /// remote_ip -> hostname (populated by DNS response parsing)
    dns_cache: DashMap<IpAddr, HostName>,
    /// IPs belonging to this machine, so we know which side of a packet is "remote"
    local_ips: HashSet<IpAddr>,
}

impl Attribution {
    pub fn new(local_ips: HashSet<IpAddr>) -> Self {
        Self {
            dns_cache: DashMap::new(),
            local_ips,
        }
    }

    pub fn record_dns(&self, ip: IpAddr, hostname: HostName) {
        self.dns_cache.insert(ip, hostname);
    }

    pub fn resolve(&self, ip: &IpAddr) -> Option<HostName> {
        self.dns_cache.get(ip).map(|h| h.clone())
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
