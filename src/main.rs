use anyhow::{Result, anyhow};
use dashmap::DashMap;
use std::collections::HashSet;
use std::env;
use std::net::IpAddr;
use std::sync::Arc;

mod capture;
mod model;
mod parse;
mod render;

use crate::capture::spawn_capture_thread;
use crate::model::{Attribution, StatsMap};
use crate::render::run_ui;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err(anyhow!("Invalid arguments, provide network interface name"));
    }

    let device_name = &args[1];
    let stats: StatsMap = Arc::new(DashMap::new());

    let device = pcap::Device::list()?
        .into_iter()
        .find(|d| &d.name == device_name)
        .expect(&format!("Network interface {} not found", device_name));
    let local_ips: HashSet<IpAddr> = device.addresses.iter().map(|a| a.addr).collect();
    let attribution = Arc::new(Attribution::new(local_ips));

    spawn_capture_thread(device, stats.clone(), attribution);
    run_ui(stats)?;

    Ok(())
}
