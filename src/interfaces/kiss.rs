// KISSInterface — serial KISS TNC interface.
// Ported from: lxcf/_ref_rns/Interfaces/KISSInterface.py

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::interfaces::base::Interface;
use crate::interfaces::kiss_codec::{self, KissDecoder, CMD_DATA, CMD_READY,
    CMD_TXDELAY, CMD_P, CMD_SLOTTIME, CMD_TXTAIL, FEND};
use crate::Result;

pub const HW_MTU: usize = 564;
pub const BITRATE_GUESS: u64 = 1200;
pub const DEFAULT_IFAC_SIZE: usize = 8;

pub struct KISSInterface {
    pub base: Arc<Interface>,
    pub port_path: String,
    pub baud_rate: u32,
    pub preamble: u8,
    pub txtail: u8,
    pub persistence: u8,
    pub slottime: u8,
    pub flow_control: bool,
    pub beacon_interval: Option<u64>,
    pub beacon_data: Option<Vec<u8>>,
    port: Mutex<Option<Box<dyn serialport::SerialPort>>>,
    shutdown: AtomicBool,
    interface_ready: Arc<AtomicBool>,
}

impl KISSInterface {
    pub fn new(
        port_path: String, baud_rate: u32,
        preamble: u8, txtail: u8, persistence: u8, slottime: u8,
        flow_control: bool, beacon_interval: Option<u64>,
        beacon_data: Option<Vec<u8>>, name: String,
    ) -> Result<Arc<Self>> {
        let serial = open_port(&port_path, baud_rate)?;
        let tx_port = serial.try_clone().map_err(|e|
            crate::FerretError::InterfaceError(format!("serial clone: {e}")))?;
        let tx = Arc::new(Mutex::new(tx_port));
        let ready = Arc::new(AtomicBool::new(true));
        let transmit_fn: Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync> = {
            let tx = Arc::clone(&tx);
            let rdy = Arc::clone(&ready);
            Box::new(move |data: &[u8]| {
                if flow_control && !rdy.load(Ordering::Relaxed) { return Ok(()); }
                tx.lock().unwrap_or_else(|e| e.into_inner())
                    .write_all(&kiss_codec::encode_data(data))
                    .map_err(|e| crate::FerretError::InterfaceError(format!("kiss write: {e}")))?;
                if flow_control { rdy.store(false, Ordering::Relaxed); }
                Ok(())
            })
        };
        let mut base = Interface::new(name, Some(transmit_fn));
        base.bitrate = BITRATE_GUESS;
        base.hw_mtu = Some(HW_MTU);
        base.dir_in = true;
        base.dir_out = true;
        base.online.store(true, Ordering::Relaxed);
        let iface = Arc::new(Self {
            base: Arc::new(base), port_path, baud_rate,
            preamble, txtail, persistence, slottime, flow_control,
            beacon_interval, beacon_data,
            port: Mutex::new(Some(serial)),
            shutdown: AtomicBool::new(false),
            interface_ready: ready,
        });
        std::thread::sleep(Duration::from_secs(2));
        iface.configure_kiss()?;
        let c = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("kiss-read-{}", iface.base.name))
            .spawn(move || c.read_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn: {e}")))?;
        Ok(iface)
    }

    fn configure_kiss(&self) -> Result<()> {
        let mut guard = self.port.lock().unwrap_or_else(|e| e.into_inner());
        let p = guard.as_mut().ok_or_else(||
            crate::FerretError::InterfaceError("port not open".into()))?;
        let w = |p: &mut Box<dyn serialport::SerialPort>, cmd: u8, v: u8| -> Result<()> {
            p.write_all(&[FEND, cmd, v, FEND])
                .map_err(|e| crate::FerretError::InterfaceError(format!("kiss cfg: {e}")))
        };
        w(p, CMD_TXDELAY, (self.preamble as u16 / 10).min(255) as u8)?;
        w(p, CMD_P, self.persistence)?;
        w(p, CMD_SLOTTIME, (self.slottime as u16 / 10).min(255) as u8)?;
        w(p, CMD_TXTAIL, (self.txtail as u16 / 10).min(255) as u8)?;
        Ok(())
    }

    fn read_loop(self: &Arc<Self>) {
        let mut buf = [0u8; 512];
        let mut decoder = KissDecoder::new(HW_MTU);
        let mut first_tx: Option<f64> = None;
        let fc_locked = std::sync::Mutex::new(now());
        loop {
            if self.shutdown.load(Ordering::Relaxed) { break; }
            let n = {
                let mut g = self.port.lock().unwrap_or_else(|e| e.into_inner());
                match g.as_mut() {
                    Some(p) => match p.read(&mut buf) {
                        Ok(0) => 0,
                        Ok(n) => n,
                        Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                            // Flow control timeout recovery
                            if self.flow_control && !self.interface_ready.load(Ordering::Relaxed) {
                                let locked = *fc_locked.lock().unwrap_or_else(|e| e.into_inner());
                                if now() > locked + 5.0 {
                                    self.interface_ready.store(true, Ordering::Relaxed);
                                }
                            }
                            // Beacon check
                            if let (Some(iv), Some(ref bd)) = (self.beacon_interval, &self.beacon_data) {
                                if let Some(ft) = first_tx {
                                    if now() > ft + iv as f64 {
                                        first_tx = None;
                                        let mut f = bd.clone();
                                        while f.len() < 15 { f.push(0x00); }
                                        let _ = self.base.process_outgoing(&f);
                                    }
                                }
                            }
                            continue;
                        }
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
                match frame.command {
                    CMD_DATA if !frame.data.is_empty() => {
                        self.base.process_incoming(&frame.data);
                        if first_tx.is_none() { first_tx = Some(now()); }
                    }
                    CMD_READY => {
                        self.interface_ready.store(true, Ordering::Relaxed);
                        *fc_locked.lock().unwrap_or_else(|e| e.into_inner()) = now();
                    }
                    _ => {}
                }
            }
        }
    }

    fn reconnect(self: &Arc<Self>) {
        while !self.shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(5));
            if self.shutdown.load(Ordering::Relaxed) { break; }
            if let Ok(serial) = open_port(&self.port_path, self.baud_rate) {
                *self.port.lock().unwrap_or_else(|e| e.into_inner()) = Some(serial);
                self.base.online.store(true, Ordering::Relaxed);
                if self.configure_kiss().is_err() { continue; }
                self.interface_ready.store(true, Ordering::Relaxed);
                let c = Arc::clone(self);
                let _ = std::thread::Builder::new()
                    .name(format!("kiss-read-{}", self.base.name))
                    .spawn(move || c.read_loop());
                return;
            }
        }
    }

    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);
    }
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn open_port(path: &str, baud: u32) -> Result<Box<dyn serialport::SerialPort>> {
    serialport::new(path, baud)
        .data_bits(serialport::DataBits::Eight)
        .parity(serialport::Parity::None)
        .stop_bits(serialport::StopBits::One)
        .timeout(Duration::from_millis(100))
        .open()
        .map_err(|e| crate::FerretError::InterfaceConnectionFailed(
            format!("KISS port {path}: {e}")))
}
