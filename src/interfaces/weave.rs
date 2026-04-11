// WeaveInterface — mesh radio devices using WDCL protocol over serial with HDLC framing.
// Ported from: lxcf/_ref_rns/Interfaces/WeaveInterface.py

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::interfaces::base::Interface;
use crate::interfaces::hdlc_codec::{self, HdlcDecoder};
use crate::Result;

pub const HW_MTU: usize = 508;
pub const DEFAULT_IFAC_SIZE: usize = 8;
pub const BITRATE_GUESS: u64 = 9600;
const RECONNECT_WAIT: u64 = 5;

// WDCL protocol packet types
const WDCL_T_DISCOVER: u8 = 0x00;
const _WDCL_T_CONNECT: u8 = 0x01;
const WDCL_T_ENDPOINT_PKT: u8 = 0x05;
const WDCL_BROADCAST: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
/// Minimum WDCL header: 4-byte switch_id + 1-byte type.
const HEADER_MINSIZE: usize = 5;
const WDCL_HANDSHAKE_TIMEOUT: u64 = 2;

/// A discovered endpoint on the Weave mesh.
pub struct WeaveEndpoint {
    pub id: Vec<u8>,
    pub last_seen: f64,
    pub reachable: bool,
}

/// Interface for Weave mesh radio devices using WDCL over serial.
pub struct WeaveInterface {
    pub base: Arc<Interface>,
    pub port_path: String,
    pub baud_rate: u32,
    pub endpoints: Mutex<HashMap<Vec<u8>, WeaveEndpoint>>,
    port: Mutex<Option<Box<dyn serialport::SerialPort>>>,
    shutdown: AtomicBool,
}

impl WeaveInterface {
    /// Open serial port, perform WDCL handshake, spawn read thread.
    pub fn new(port_path: String, baud_rate: u32, name: String) -> Result<Arc<Self>> {
        let serial = open_port(&port_path, baud_rate)?;
        let tx_port = serial.try_clone().map_err(|e| {
            crate::FerretError::InterfaceError(format!("weave serial clone: {e}"))
        })?;
        let tx_mutex: Arc<Mutex<Box<dyn serialport::SerialPort>>> = Arc::new(Mutex::new(tx_port));
        let transmit_fn: Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync> = {
            let tx = Arc::clone(&tx_mutex);
            Box::new(move |data: &[u8]| {
                let mut frame = Vec::with_capacity(HEADER_MINSIZE + data.len());
                frame.extend_from_slice(&WDCL_BROADCAST);
                frame.push(WDCL_T_ENDPOINT_PKT);
                frame.extend_from_slice(data);
                let encoded = hdlc_codec::encode(&frame);
                let mut guard = tx.lock().unwrap_or_else(|e| e.into_inner());
                guard.write_all(&encoded).map_err(|e| {
                    crate::FerretError::InterfaceError(format!("weave write: {e}"))
                })
            })
        };
        let mut base = Interface::new(name, Some(transmit_fn));
        base.bitrate = baud_rate as u64;
        base.hw_mtu = Some(HW_MTU);
        base.dir_in = true;
        base.dir_out = true;
        base.online.store(true, Ordering::Relaxed);

        let iface = Arc::new(Self {
            base: Arc::new(base),
            port_path, baud_rate,
            endpoints: Mutex::new(HashMap::new()),
            port: Mutex::new(Some(serial)),
            shutdown: AtomicBool::new(false),
        });
        iface.wdcl_handshake()?;

        let c = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("weave-read-{}", iface.base.name))
            .spawn(move || c.read_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn error: {e}")))?;
        Ok(iface)
    }

    /// Send WDCL device discovery broadcast (simplified handshake).
    pub fn wdcl_handshake(&self) -> Result<()> {
        let mut frame = Vec::with_capacity(HEADER_MINSIZE);
        frame.extend_from_slice(&WDCL_BROADCAST);
        frame.push(WDCL_T_DISCOVER);
        let encoded = hdlc_codec::encode(&frame);
        let mut guard = self.port.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut port) = *guard {
            port.write_all(&encoded).map_err(|e| {
                crate::FerretError::InterfaceError(format!("weave handshake: {e}"))
            })?;
        }
        std::thread::sleep(Duration::from_secs(WDCL_HANDSHAKE_TIMEOUT));
        Ok(())
    }

    /// Read loop — decode HDLC frames, extract WDCL endpoint packets.
    fn read_loop(self: &Arc<Self>) {
        let mut buf = [0u8; 512];
        let mut decoder = HdlcDecoder::new(HW_MTU);
        loop {
            if self.shutdown.load(Ordering::Relaxed) { break; }
            let n = {
                let mut guard = self.port.lock().unwrap_or_else(|e| e.into_inner());
                match guard.as_mut() {
                    Some(p) => match p.read(&mut buf) {
                        Ok(0) => 0,
                        Ok(n) => n,
                        Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                        Err(_) => 0,
                    },
                    None => break,
                }
            };
            if n == 0 {
                self.base.online.store(false, Ordering::Relaxed);
                if !self.shutdown.load(Ordering::Relaxed) { self.reconnect(); }
                break;
            }
            for frame in decoder.feed(&buf[..n]) {
                if frame.len() > HEADER_MINSIZE && frame[4] == WDCL_T_ENDPOINT_PKT {
                    let payload = &frame[HEADER_MINSIZE..];
                    if payload.len() > 8 {
                        let ep_id = payload[payload.len() - 8..].to_vec();
                        let data = &payload[..payload.len() - 8];
                        self.update_endpoint(&ep_id);
                        self.base.process_incoming(data);
                    }
                }
            }
        }
    }

    /// Update endpoint liveness tracking.
    fn update_endpoint(&self, ep_id: &[u8]) {
        let mut eps = self.endpoints.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_f64();
        eps.entry(ep_id.to_vec())
            .and_modify(|ep| { ep.last_seen = now; ep.reachable = true; })
            .or_insert(WeaveEndpoint { id: ep_id.to_vec(), last_seen: now, reachable: true });
    }

    /// Reopen serial port and restart read loop.
    fn reconnect(self: &Arc<Self>) {
        while !self.shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(RECONNECT_WAIT));
            if self.shutdown.load(Ordering::Relaxed) { break; }
            match open_port(&self.port_path, self.baud_rate) {
                Ok(serial) => {
                    *self.port.lock().unwrap_or_else(|e| e.into_inner()) = Some(serial);
                    self.base.online.store(true, Ordering::Relaxed);
                    let _ = self.wdcl_handshake();
                    let c = Arc::clone(self);
                    let _ = std::thread::Builder::new()
                        .name(format!("weave-read-{}", self.base.name))
                        .spawn(move || c.read_loop());
                    return;
                }
                Err(_) => continue,
            }
        }
    }

    /// Shut down the interface.
    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);
    }
}

fn open_port(path: &str, baud_rate: u32) -> Result<Box<dyn serialport::SerialPort>> {
    serialport::new(path, baud_rate)
        .data_bits(serialport::DataBits::Eight)
        .parity(serialport::Parity::None)
        .stop_bits(serialport::StopBits::One)
        .timeout(Duration::from_millis(100))
        .open()
        .map_err(|e| crate::FerretError::InterfaceConnectionFailed(
            format!("weave serial port {path}: {e}"),
        ))
}

fn now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
