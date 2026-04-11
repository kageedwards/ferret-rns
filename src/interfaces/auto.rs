// AutoInterface — IPv6 multicast peer discovery with UDP data transport.
//
// Ported from the Python reference: lxcf/_ref_rns/Interfaces/AutoInterface.py

use std::collections::HashMap;
use std::net::{Ipv6Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::crypto::sha256;
use crate::interfaces::base::Interface;
use crate::Result;

// Constants
pub const HW_MTU: usize = 1196;
pub const DEFAULT_DISCOVERY_PORT: u16 = 29716;
pub const DEFAULT_DATA_PORT: u16 = 42671;
pub const DEFAULT_IFAC_SIZE: usize = 16;
pub const BITRATE_GUESS: u64 = 10_000_000;
pub const PEERING_TIMEOUT: f64 = 22.0;
pub const ANNOUNCE_INTERVAL: f64 = 1.6;
pub const PEER_JOB_INTERVAL: f64 = 4.0;
pub const MCAST_ECHO_TIMEOUT: f64 = 6.5;
pub const DEFAULT_GROUP_ID: &[u8] = b"reticulum";

// Scope constants
pub const SCOPE_LINK: &str = "2";
pub const SCOPE_ADMIN: &str = "4";
pub const SCOPE_SITE: &str = "5";
pub const SCOPE_ORGANISATION: &str = "8";
pub const SCOPE_GLOBAL: &str = "e";

pub struct PeerEntry {
    pub ifname: String,
    pub last_heard: f64,
    pub last_outbound: f64,
}

pub struct AutoInterfacePeer {
    pub base: Arc<Interface>,
    pub peer_addr: String,
    pub ifname: String,
}

impl AutoInterfacePeer {
    pub fn new(owner: &str, peer_addr: String, ifname: String, data_port: u16) -> Result<Self> {
        let name = format!("AutoInterfacePeer[{ifname}/{peer_addr}]");
        let dest = format!("[{peer_addr}%{ifname}]:{data_port}");
        let sock = UdpSocket::bind("[::]:0")
            .map_err(|e| iface_err(format!("{owner} peer socket: {e}")))?;
        let transmit_fn: Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync> = Box::new(move |data| {
            sock.send_to(data, &dest).map_err(|e| iface_err(format!("AutoPeer send: {e}")))?;
            Ok(())
        });
        let mut base = Interface::new(name, Some(transmit_fn));
        base.bitrate = BITRATE_GUESS;
        base.hw_mtu = Some(HW_MTU);
        base.dir_in = true;
        base.dir_out = true;
        base.online.store(true, Ordering::Relaxed);
        Ok(Self { base: Arc::new(base), peer_addr, ifname })
    }

    pub fn detach(&self) {
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);
    }
}

pub struct AutoInterface {
    pub base: Arc<Interface>,
    pub group_id: Vec<u8>,
    pub discovery_port: u16,
    pub data_port: u16,
    pub discovery_scope: String,
    pub multicast_address_type: String,
    pub mcast_discovery_address: String,
    pub peering_timeout: f64,
    pub announce_interval: f64,
    pub allowed_interfaces: Vec<String>,
    pub ignored_interfaces: Vec<String>,
    peers: Mutex<HashMap<String, PeerEntry>>,
    adopted_interfaces: Mutex<HashMap<String, String>>,
    spawned_interfaces: Mutex<HashMap<String, AutoInterfacePeer>>,
    multicast_echoes: Mutex<HashMap<String, f64>>,
    timed_out_interfaces: Mutex<HashMap<String, bool>>,
    shutdown: AtomicBool,
}

fn iface_err(msg: String) -> crate::FerretError { crate::FerretError::InterfaceError(msg) }
fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

impl AutoInterface {
    pub fn new(
        name: String,
        group_id: Option<String>,
        discovery_scope: Option<String>,
        discovery_port: Option<u16>,
        data_port: Option<u16>,
        multicast_address_type: Option<String>,
        allowed_interfaces: Vec<String>,
        ignored_interfaces: Vec<String>,
    ) -> Result<Arc<Self>> {
        let gid = group_id.map(|g| g.into_bytes()).unwrap_or_else(|| DEFAULT_GROUP_ID.to_vec());
        let scope = match discovery_scope.as_deref() {
            Some("link") | None => SCOPE_LINK, Some("admin") => SCOPE_ADMIN,
            Some("site") => SCOPE_SITE, Some("organisation") => SCOPE_ORGANISATION,
            Some("global") => SCOPE_GLOBAL, Some(s) => s,
        }.to_string();
        let addr_type = match multicast_address_type.as_deref() {
            Some("permanent") => "0", _ => "1",
        }.to_string();
        let disc_port = discovery_port.unwrap_or(DEFAULT_DISCOVERY_PORT);
        let d_port = data_port.unwrap_or(DEFAULT_DATA_PORT);
        let group_hash = sha256(&gid);
        let mcast_addr = Self::compute_mcast_address(&group_hash, &scope, &addr_type);

        let mut base = Interface::new(name.clone(), None);
        base.bitrate = BITRATE_GUESS;
        base.hw_mtu = Some(HW_MTU);
        base.dir_in = true;
        base.online.store(true, Ordering::Relaxed);

        let iface = Arc::new(Self {
            base: Arc::new(base), group_id: gid,
            discovery_port: disc_port, data_port: d_port,
            discovery_scope: scope, multicast_address_type: addr_type,
            mcast_discovery_address: mcast_addr,
            peering_timeout: PEERING_TIMEOUT, announce_interval: ANNOUNCE_INTERVAL,
            allowed_interfaces, ignored_interfaces,
            peers: Mutex::new(HashMap::new()),
            adopted_interfaces: Mutex::new(HashMap::new()),
            spawned_interfaces: Mutex::new(HashMap::new()),
            multicast_echoes: Mutex::new(HashMap::new()),
            timed_out_interfaces: Mutex::new(HashMap::new()),
            shutdown: AtomicBool::new(false),
        });

        let c = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("auto-disc-{name}"))
            .spawn(move || c.discovery_loop())
            .map_err(|e| iface_err(format!("spawn discovery: {e}")))?;
        let c = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("auto-jobs-{name}"))
            .spawn(move || c.peer_jobs())
            .map_err(|e| iface_err(format!("spawn peer_jobs: {e}")))?;
        Ok(iface)
    }

    /// Compute IPv6 multicast address from group hash, scope, and address type.
    /// Matches the Python reference derivation of the multicast group tag.
    pub fn compute_mcast_address(group_hash: &[u8; 32], scope: &str, addr_type: &str) -> String {
        let g = group_hash;
        let s = |i: usize| format!("{:02x}", u16::from(g[i + 1]) + (u16::from(g[i]) << 8));
        format!(
            "ff{addr_type}{scope}:0:{}:{}:{}:{}:{}:{}",
            s(2), s(4), s(6), s(8), s(10), s(12)
        )
    }

    fn discovery_loop(self: &Arc<Self>) {
        let mcast_addr: Ipv6Addr = match self.mcast_discovery_address.parse() {
            Ok(a) => a, Err(_) => return,
        };
        let socket = match UdpSocket::bind(format!("[::]:{}", self.discovery_port)) {
            Ok(s) => s, Err(_) => return,
        };
        let _ = socket.join_multicast_v6(&mcast_addr, 0);
        let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));
        let mut buf = [0u8; 1024];
        let mut last_announce = 0.0_f64;

        loop {
            if self.shutdown.load(Ordering::Relaxed) { break; }
            let t = now();
            if t - last_announce >= self.announce_interval {
                self.send_discovery_announce(&socket);
                last_announce = t;
            }
            if let Ok((n, src)) = socket.recv_from(&mut buf) {
                if n >= 32 {
                    let src_ip = src.ip().to_string();
                    let src_addr = src_ip.split('%').next().unwrap_or(&src_ip);
                    let mut origin = self.group_id.clone();
                    origin.extend_from_slice(src_addr.as_bytes());
                    if buf[..32] == sha256(&origin) {
                        self.add_peer(src_addr, "auto0");
                    }
                }
            }
        }
    }

    fn send_discovery_announce(&self, socket: &UdpSocket) {
        let adopted = self.adopted_interfaces.lock().unwrap_or_else(|e| e.into_inner());
        let dest = format!("[{}]:{}", self.mcast_discovery_address, self.discovery_port);
        if adopted.is_empty() {
            let _ = socket.send_to(&sha256(&self.group_id), &dest);
        } else {
            for (_ifname, ll) in adopted.iter() {
                let mut inp = self.group_id.clone();
                inp.extend_from_slice(ll.as_bytes());
                let _ = socket.send_to(&sha256(&inp), &dest);
            }
        }
    }

    fn peer_jobs(self: &Arc<Self>) {
        loop {
            std::thread::sleep(Duration::from_secs_f64(PEER_JOB_INTERVAL));
            if self.shutdown.load(Ordering::Relaxed) { break; }
            let t = now();
            let timed_out: Vec<String> = {
                let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
                peers.iter()
                    .filter(|(_, e)| t > e.last_heard + self.peering_timeout)
                    .map(|(a, _)| a.clone())
                    .collect()
            };
            for addr in &timed_out { self.remove_peer(addr); }
            // Multicast echo timeout tracking for carrier loss/recovery
            let echoes = self.multicast_echoes.lock().unwrap_or_else(|e| e.into_inner());
            let mut timeouts = self.timed_out_interfaces.lock().unwrap_or_else(|e| e.into_inner());
            for (ifname, &last_echo) in echoes.iter() {
                timeouts.insert(ifname.clone(), t - last_echo > MCAST_ECHO_TIMEOUT);
            }
        }
    }

    pub fn add_peer(&self, addr: &str, ifname: &str) {
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = peers.get_mut(addr) {
            entry.last_heard = now();
            return;
        }
        let t = now();
        peers.insert(addr.to_string(), PeerEntry {
            ifname: ifname.to_string(), last_heard: t, last_outbound: t,
        });
        drop(peers);
        if let Ok(peer) = AutoInterfacePeer::new(&self.base.name, addr.into(), ifname.into(), self.data_port) {
            self.spawned_interfaces.lock().unwrap_or_else(|e| e.into_inner())
                .insert(addr.to_string(), peer);
        }
    }

    pub fn remove_peer(&self, addr: &str) {
        self.peers.lock().unwrap_or_else(|e| e.into_inner()).remove(addr);
        if let Some(peer) = self.spawned_interfaces.lock().unwrap_or_else(|e| e.into_inner()).remove(addr) {
            peer.detach();
        }
    }

    pub fn peer_count(&self) -> usize {
        self.spawned_interfaces.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);
        for (_, peer) in self.spawned_interfaces.lock().unwrap_or_else(|e| e.into_inner()).drain() {
            peer.detach();
        }
    }
}
