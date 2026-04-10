// TCPServerInterface — listens for incoming TCP connections and spawns
// TCPClientInterface instances for each accepted client.
//
// Ported from the Python reference: lxcf/_ref_rns/Interfaces/TCPInterface.py

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::interfaces::base::Interface;
use crate::interfaces::tcp_client::{TCPClientInterface, BITRATE_GUESS};
use crate::Result;

// ── TCPServerInterface ──

pub struct TCPServerInterface {
    pub base: Arc<Interface>,
    pub bind_ip: String,
    pub bind_port: u16,
    pub prefer_ipv6: bool,
    pub i2p_tunneled: bool,
    pub kiss_framing: bool,
    pub spawned: Mutex<Vec<Arc<TCPClientInterface>>>,
    listener: Mutex<Option<TcpListener>>,
    shutdown: AtomicBool,
}

impl TCPServerInterface {
    /// Bind a TCP listener and spawn an accept loop thread.
    pub fn bind(
        bind_ip: String,
        bind_port: u16,
        name: String,
        prefer_ipv6: bool,
        kiss_framing: bool,
        i2p_tunneled: bool,
    ) -> Result<Arc<Self>> {
        let addr = format!("{}:{}", bind_ip, bind_port);
        let listener = TcpListener::bind(&addr).map_err(|e| {
            crate::FerretError::InterfaceConnectionFailed(format!(
                "TCP server bind failed on {}: {}",
                addr, e
            ))
        })?;

        // Server doesn't transmit directly — spawned clients do.
        let mut base = Interface::new(name, None);
        base.bitrate = BITRATE_GUESS;
        base.dir_in = false;
        base.dir_out = false;
        base.online.store(true, Ordering::Relaxed);

        let iface = Arc::new(Self {
            base: Arc::new(base),
            bind_ip,
            bind_port,
            prefer_ipv6,
            i2p_tunneled,
            kiss_framing,
            spawned: Mutex::new(Vec::new()),
            listener: Mutex::new(Some(listener)),
            shutdown: AtomicBool::new(false),
        });

        let iface_clone = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("tcp-srv-{}", iface.base.name))
            .spawn(move || iface_clone.accept_loop())
            .map_err(|e| {
                crate::FerretError::InterfaceError(format!("spawn error: {}", e))
            })?;

        Ok(iface)
    }

    /// Accept incoming connections in a loop, spawning a TCPClientInterface
    /// for each one.
    fn accept_loop(self: &Arc<Self>) {
        // Take a clone of the listener so we can accept without holding the
        // mutex for the entire loop.
        let listener = {
            let guard = self.listener.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(l) => match l.try_clone() {
                    Ok(c) => c,
                    Err(_) => return,
                },
                None => return,
            }
        };

        for stream in listener.incoming() {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let stream = match stream {
                Ok(s) => s,
                Err(_) => {
                    if self.shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    continue;
                }
            };

            let client_name = format!("Client on {}", self.base.name);
            let client = match TCPClientInterface::from_socket(
                stream,
                client_name,
                self.kiss_framing,
                self.i2p_tunneled,
            ) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Inherit server settings on the spawned client's base.
            // mode and announce_cap are the available common fields.
            // (IFAC state, announce rate fields, etc. will be wired up
            // when the full config pipeline is in place.)

            let mut spawned = self.spawned.lock().unwrap_or_else(|e| e.into_inner());
            // Remove any previously-detached clients.
            spawned.retain(|c| !c.base.detached.load(Ordering::Relaxed));
            spawned.push(client);
        }
    }

    /// Shut down the server and all spawned client interfaces.
    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);

        // Drop the listener to unblock the accept loop.
        {
            let mut guard = self.listener.lock().unwrap_or_else(|e| e.into_inner());
            let _ = guard.take();
        }

        // Detach all spawned clients.
        let spawned = self.spawned.lock().unwrap_or_else(|e| e.into_inner());
        for client in spawned.iter() {
            client.detach();
        }
    }
}
