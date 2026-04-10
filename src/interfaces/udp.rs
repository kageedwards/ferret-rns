// UDPInterface — UDP datagram transport (no framing codec needed).
//
// Ported from the Python reference: lxcf/_ref_rns/Interfaces/UDPInterface.py

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use socket2::{Domain, Protocol, Socket, Type};
use crate::interfaces::base::Interface;
use crate::Result;

pub const HW_MTU: usize = 1064;
pub const BITRATE_GUESS: u64 = 10_000_000;
pub const DEFAULT_IFAC_SIZE: usize = 16;

pub struct UDPInterface {
    pub base: Arc<Interface>,
    pub bind_ip: String,
    pub bind_port: u16,
    pub forward_ip: String,
    pub forward_port: u16,
    recv_socket: Mutex<Option<UdpSocket>>,
    shutdown: AtomicBool,
}

fn iface_err(msg: String) -> crate::FerretError {
    crate::FerretError::InterfaceError(msg)
}

impl UDPInterface {
    /// Create a new UDP interface. Binds on `bind_ip:bind_port` for receiving,
    /// sends datagrams to `forward_ip:forward_port`.
    pub fn new(
        bind_ip: String,
        bind_port: u16,
        forward_ip: String,
        forward_port: u16,
        name: String,
        broadcast: bool,
    ) -> Result<Arc<Self>> {
        // Build send socket via socket2 for SO_BROADCAST support.
        let send_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| iface_err(format!("UDP socket: {e}")))?;
        if broadcast {
            send_sock.set_broadcast(true)
                .map_err(|e| iface_err(format!("SO_BROADCAST: {e}")))?;
        }
        let fwd_ip = forward_ip.clone();
        let fwd_port = forward_port;
        let send_std: std::net::UdpSocket = send_sock.into();
        let tx = Arc::new(Mutex::new(send_std));

        let transmit_fn: Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync> = {
            let tx = Arc::clone(&tx);
            Box::new(move |data: &[u8]| {
                let dest = format!("{}:{}", fwd_ip, fwd_port);
                let guard = tx.lock().unwrap_or_else(|e| e.into_inner());
                guard.send_to(data, &dest).map_err(|e| iface_err(format!("UDP send: {e}")))?;
                Ok(())
            })
        };

        let mut base = Interface::new(name, Some(transmit_fn));
        base.bitrate = BITRATE_GUESS;
        base.hw_mtu = Some(HW_MTU);
        base.dir_in = true;
        base.dir_out = true;
        base.online.store(true, Ordering::Relaxed);

        let recv_addr: std::net::SocketAddr = format!("{}:{}", bind_ip, bind_port)
            .parse()
            .map_err(|e| iface_err(format!("invalid bind address: {e}")))?;
        let recv_socket = UdpSocket::bind(recv_addr)
            .map_err(|e| iface_err(format!("UDP bind: {e}")))?;

        let iface = Arc::new(Self {
            base: Arc::new(base),
            bind_ip, bind_port, forward_ip, forward_port,
            recv_socket: Mutex::new(Some(recv_socket)),
            shutdown: AtomicBool::new(false),
        });

        let iface_clone = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("udp-read-{}", iface.base.name))
            .spawn(move || iface_clone.read_loop())
            .map_err(|e| iface_err(format!("spawn error: {e}")))?;

        Ok(iface)
    }

    /// Receive datagrams in a loop. Each datagram is a complete packet.
    fn read_loop(self: &Arc<Self>) {
        let mut buf = [0u8; HW_MTU];
        let socket = {
            let guard = self.recv_socket.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().and_then(|s| s.try_clone().ok())
        };
        let Some(socket) = socket else { return };

        loop {
            if self.shutdown.load(Ordering::Relaxed) { break; }
            match socket.recv_from(&mut buf) {
                Ok((n, _)) if n > 0 => self.base.process_incoming(&buf[..n]),
                Ok(_) => continue,
                Err(_) if self.shutdown.load(Ordering::Relaxed) => break,
                Err(_) => continue,
            }
        }
    }

    /// Detach the interface: mark offline and signal shutdown.
    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);
    }
}
