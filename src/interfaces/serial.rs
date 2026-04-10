// SerialInterface — serial port with HDLC framing.
// Ported from: lxcf/_ref_rns/Interfaces/SerialInterface.py

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::interfaces::base::Interface;
use crate::interfaces::hdlc_codec::{self, HdlcDecoder};
use crate::Result;

pub const HW_MTU: usize = 564;
pub const DEFAULT_IFAC_SIZE: usize = 8;
const RECONNECT_WAIT: u64 = 5;

pub struct SerialInterface {
    pub base: Arc<Interface>,
    pub port_path: String,
    pub baud_rate: u32,
    pub data_bits: serialport::DataBits,
    pub parity: serialport::Parity,
    pub stop_bits: serialport::StopBits,
    port: Mutex<Option<Box<dyn serialport::SerialPort>>>,
    shutdown: AtomicBool,
}

impl SerialInterface {
    /// Open a serial port and start the read loop.
    pub fn new(
        port_path: String,
        baud_rate: u32,
        data_bits: serialport::DataBits,
        parity: serialport::Parity,
        stop_bits: serialport::StopBits,
        name: String,
    ) -> Result<Arc<Self>> {
        let serial = open_port(&port_path, baud_rate, data_bits, parity, stop_bits)?;

        let tx_port = serial.try_clone().map_err(|e| {
            crate::FerretError::InterfaceError(format!("serial clone: {}", e))
        })?;
        let tx_mutex: Arc<Mutex<Box<dyn serialport::SerialPort>>> = Arc::new(Mutex::new(tx_port));
        let transmit_fn: Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync> = {
            let tx = Arc::clone(&tx_mutex);
            Box::new(move |data: &[u8]| {
                let framed = hdlc_codec::encode(data);
                let mut guard = tx.lock().unwrap_or_else(|e| e.into_inner());
                guard.write_all(&framed).map_err(|e| {
                    crate::FerretError::InterfaceError(format!("serial write: {}", e))
                })?;
                Ok(())
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
            port_path,
            baud_rate,
            data_bits,
            parity,
            stop_bits,
            port: Mutex::new(Some(serial)),
            shutdown: AtomicBool::new(false),
        });
        let iface_clone = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("serial-read-{}", iface.base.name))
            .spawn(move || iface_clone.read_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn error: {}", e)))?;
        Ok(iface)
    }

    /// Read loop — read bytes, decode HDLC frames, deliver to base.
    fn read_loop(self: &Arc<Self>) {
        let mut buf = [0u8; 512];
        let mut decoder = HdlcDecoder::new(HW_MTU);

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
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
                if !frame.is_empty() {
                    self.base.process_incoming(&frame);
                }
            }
        }
    }

    /// Reopen the serial port and restart the read loop.
    fn reconnect(self: &Arc<Self>) {
        while !self.shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(RECONNECT_WAIT));
            if self.shutdown.load(Ordering::Relaxed) { break; }
            match open_port(&self.port_path, self.baud_rate, self.data_bits, self.parity, self.stop_bits) {
                Ok(serial) => {
                    *self.port.lock().unwrap_or_else(|e| e.into_inner()) = Some(serial);
                    self.base.online.store(true, Ordering::Relaxed);
                    let c = Arc::clone(self);
                    let _ = std::thread::Builder::new()
                        .name(format!("serial-read-{}", self.base.name))
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

// ── Helper ──

fn open_port(
    path: &str,
    baud_rate: u32,
    data_bits: serialport::DataBits,
    parity: serialport::Parity,
    stop_bits: serialport::StopBits,
) -> Result<Box<dyn serialport::SerialPort>> {
    serialport::new(path, baud_rate)
        .data_bits(data_bits)
        .parity(parity)
        .stop_bits(stop_bits)
        .timeout(Duration::from_millis(100))
        .open()
        .map_err(|e| crate::FerretError::InterfaceConnectionFailed(
            format!("serial port {}: {}", path, e),
        ))
}
