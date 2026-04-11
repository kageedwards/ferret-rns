// I2PInterface — tunnels Reticulum traffic over the I2P anonymity network
// via the SAM (Simple Anonymous Messaging) API.
//
// Ported from the Python reference: lxcf/_ref_rns/Interfaces/I2PInterface.py

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::interfaces::base::Interface;
use crate::interfaces::hdlc_codec::{self, HdlcDecoder};
use crate::interfaces::kiss_codec::{self, KissDecoder};
use crate::interfaces::tcp_client::{I2P_PROBE_AFTER, I2P_PROBE_INTERVAL};
use crate::Result;

pub const HW_MTU: usize = 1064;
pub const DEFAULT_IFAC_SIZE: usize = 16;
const BITRATE_GUESS: u64 = 256_000;
const DEFAULT_SAM_ADDRESS: &str = "127.0.0.1:7656";

pub struct I2PInterface {
    pub base: Arc<Interface>,
    pub sam_address: String,
    pub dest_key_path: Option<String>,
    pub kiss_framing: bool,
    pub peers: Vec<String>,
    pub is_server: bool,
    pub spawned: Mutex<Vec<Arc<I2PPeerInterface>>>,
    shutdown: AtomicBool,
}

pub struct I2PPeerInterface {
    pub base: Arc<Interface>,
    pub socket: Mutex<Option<TcpStream>>,
    kiss_framing: bool,
    shutdown: AtomicBool,
}

// ── SAM protocol helpers ──

fn sam_err(e: impl std::fmt::Display) -> crate::FerretError {
    crate::FerretError::InterfaceConnectionFailed(format!("SAM error: {}", e))
}

/// Read a SAM response line; return Err if it doesn't contain RESULT=OK.
fn sam_expect_ok(stream: &TcpStream, context: &str) -> Result<String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(sam_err)?);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(sam_err)?;
    if !line.contains("RESULT=OK") {
        return Err(crate::FerretError::InterfaceConnectionFailed(
            format!("SAM {} failed: {}", context, line.trim()),
        ));
    }
    Ok(line)
}

fn sam_hello(stream: &mut TcpStream) -> Result<()> {
    stream.write_all(b"HELLO VERSION MIN=3.1 MAX=3.1\n").map_err(sam_err)?;
    stream.flush().map_err(sam_err)?;
    sam_expect_ok(stream, "handshake")?;
    Ok(())
}

fn sam_session_create(stream: &mut TcpStream, dest: &str) -> Result<String> {
    let sid = format!("ferret_{}", std::process::id());
    let cmd = format!("SESSION CREATE STYLE=STREAM ID={} DESTINATION={}\n", sid, dest);
    stream.write_all(cmd.as_bytes()).map_err(sam_err)?;
    stream.flush().map_err(sam_err)?;
    sam_expect_ok(stream, "SESSION CREATE")?;
    Ok(sid)
}

fn configure_i2p_keepalive(stream: &TcpStream) -> Result<()> {
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(I2P_PROBE_AFTER as u64))
        .with_interval(Duration::from_secs(I2P_PROBE_INTERVAL as u64));
    sock.set_tcp_keepalive(&ka)?;
    Ok(())
}

fn sam_connect(addr: &str) -> Result<TcpStream> {
    let s = TcpStream::connect(addr).map_err(sam_err)?;
    s.set_nodelay(true).map_err(sam_err)?;
    Ok(s)
}

// ── I2PInterface ──

impl I2PInterface {
    /// Create a server-mode I2P interface that accepts incoming streams.
    pub fn new_server(
        sam_address: Option<&str>, dest_key_path: Option<String>,
        name: String, kiss_framing: bool,
    ) -> Result<Arc<Self>> {
        let sam_addr = sam_address.unwrap_or(DEFAULT_SAM_ADDRESS).to_string();
        let mut base = Interface::new(name, None);
        base.bitrate = BITRATE_GUESS;
        base.dir_in = true;
        base.online.store(true, Ordering::Relaxed);

        let iface = Arc::new(Self {
            base: Arc::new(base), sam_address: sam_addr, dest_key_path,
            kiss_framing, peers: Vec::new(), is_server: true,
            spawned: Mutex::new(Vec::new()), shutdown: AtomicBool::new(false),
        });
        let c = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("i2p-srv-{}", iface.base.name))
            .spawn(move || c.accept_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn: {}", e)))?;
        Ok(iface)
    }

    /// Create a client-mode I2P interface that connects to a destination.
    pub fn new_client(
        sam_address: Option<&str>, dest: String,
        name: String, kiss_framing: bool,
    ) -> Result<Arc<Self>> {
        let sam_addr = sam_address.unwrap_or(DEFAULT_SAM_ADDRESS).to_string();
        let mut sam = sam_connect(&sam_addr)?;
        sam_hello(&mut sam)?;
        let sid = sam_session_create(&mut sam, "TRANSIENT")?;

        let mut sc = sam_connect(&sam_addr)?;
        sam_hello(&mut sc)?;
        let cmd = format!("STREAM CONNECT ID={} DESTINATION={}\n", sid, dest);
        sc.write_all(cmd.as_bytes()).map_err(sam_err)?;
        sc.flush().map_err(sam_err)?;
        sam_expect_ok(&sc, "STREAM CONNECT")?;
        let _ = configure_i2p_keepalive(&sc);

        let peer = I2PPeerInterface::from_socket(sc, name.clone(), kiss_framing)?;
        Ok(Arc::new(Self {
            base: peer.base.clone(), sam_address: sam_addr, dest_key_path: None,
            kiss_framing, peers: vec![dest], is_server: false,
            spawned: Mutex::new(vec![peer]), shutdown: AtomicBool::new(false),
        }))
    }

    fn accept_loop(self: &Arc<Self>) {
        while !self.shutdown.load(Ordering::Relaxed) {
            let r = (|| -> Result<()> {
                let mut sam = sam_connect(&self.sam_address)?;
                sam_hello(&mut sam)?;
                let sid = sam_session_create(&mut sam, "TRANSIENT")?;
                loop {
                    if self.shutdown.load(Ordering::Relaxed) { break; }
                    let mut ac = sam_connect(&self.sam_address)?;
                    sam_hello(&mut ac)?;
                    let cmd = format!("STREAM ACCEPT ID={}\n", sid);
                    ac.write_all(cmd.as_bytes()).map_err(sam_err)?;
                    ac.flush().map_err(sam_err)?;
                    if sam_expect_ok(&ac, "STREAM ACCEPT").is_err() { continue; }
                    let _ = configure_i2p_keepalive(&ac);
                    let pn = format!("Peer on {}", self.base.name);
                    if let Ok(peer) = I2PPeerInterface::from_socket(ac, pn, self.kiss_framing) {
                        let mut sp = self.spawned.lock().unwrap_or_else(|e| e.into_inner());
                        sp.retain(|p| !p.base.detached.load(Ordering::Relaxed));
                        sp.push(peer);
                    }
                }
                Ok(())
            })();
            if r.is_err() && !self.shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(15));
            }
        }
    }

    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);
        for peer in self.spawned.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            peer.detach();
        }
    }
}

// ── I2PPeerInterface ──

impl I2PPeerInterface {
    /// Wrap an already-connected SAM stream socket.
    pub fn from_socket(socket: TcpStream, name: String, kiss_framing: bool) -> Result<Arc<Self>> {
        socket.set_nodelay(true).map_err(sam_err)?;
        let _ = configure_i2p_keepalive(&socket);
        let tx_sock = socket.try_clone().map_err(sam_err)?;
        let tx = Arc::new(Mutex::new(tx_sock));
        let kiss = kiss_framing;

        let transmit_fn: Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync> = {
            let tx = Arc::clone(&tx);
            Box::new(move |data: &[u8]| {
                let framed = if kiss { kiss_codec::encode_data(data) } else { hdlc_codec::encode(data) };
                let mut g = tx.lock().unwrap_or_else(|e| e.into_inner());
                g.write_all(&framed).map_err(|e| {
                    crate::FerretError::InterfaceError(format!("I2P write: {}", e))
                })
            })
        };

        let mut base = Interface::new(name, Some(transmit_fn));
        base.bitrate = BITRATE_GUESS;
        base.dir_in = true;
        base.dir_out = true;
        base.online.store(true, Ordering::Relaxed);

        let peer = Arc::new(Self {
            base: Arc::new(base), socket: Mutex::new(Some(socket)),
            kiss_framing, shutdown: AtomicBool::new(false),
        });
        let c = Arc::clone(&peer);
        std::thread::Builder::new()
            .name(format!("i2p-read-{}", peer.base.name))
            .spawn(move || c.read_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn: {}", e)))?;
        Ok(peer)
    }

    fn read_loop(self: &Arc<Self>) {
        let mut buf = [0u8; 4096];
        if self.kiss_framing {
            let mut dec = KissDecoder::new(HW_MTU);
            loop {
                if self.shutdown.load(Ordering::Relaxed) { break; }
                let n = self.socket_read(&mut buf);
                if n == 0 { self.handle_disconnect(); break; }
                for f in dec.feed(&buf[..n]) {
                    if f.command == kiss_codec::CMD_DATA && !f.data.is_empty() {
                        self.base.process_incoming(&f.data);
                    }
                }
            }
        } else {
            let mut dec = HdlcDecoder::new(HW_MTU);
            loop {
                if self.shutdown.load(Ordering::Relaxed) { break; }
                let n = self.socket_read(&mut buf);
                if n == 0 { self.handle_disconnect(); break; }
                for f in dec.feed(&buf[..n]) {
                    if !f.is_empty() { self.base.process_incoming(&f); }
                }
            }
        }
    }

    fn socket_read(&self, buf: &mut [u8]) -> usize {
        let mut g = self.socket.lock().unwrap_or_else(|e| e.into_inner());
        match g.as_mut() {
            Some(s) => s.read(buf).unwrap_or(0),
            None => 0,
        }
    }

    fn handle_disconnect(&self) {
        self.base.online.store(false, Ordering::Relaxed);
        self.detach();
    }

    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);
        if let Some(s) = self.socket.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}
