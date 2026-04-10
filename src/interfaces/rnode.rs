// RNodeInterface — LoRa radio via RNode hardware with KISS framing.
// Ported from: lxcf/_ref_rns/Interfaces/RNodeInterface.py

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::interfaces::base::Interface;
use crate::interfaces::kiss_codec::{
    self, KissDecoder, CMD_BANDWIDTH, CMD_CR, CMD_DATA, CMD_DETECT, CMD_FREQUENCY,
    CMD_RADIO_STATE, CMD_READY, CMD_SF, CMD_STAT_RSSI, CMD_STAT_SNR, CMD_TXPOWER,
};
use crate::Result;

pub const HW_MTU: usize = 508;
pub const DEFAULT_IFAC_SIZE: usize = 8;
pub const FREQ_MIN: u32 = 137_000_000;
pub const FREQ_MAX: u32 = 3_000_000_000;
pub const TXPOWER_MIN: u8 = 0;
pub const TXPOWER_MAX: u8 = 37;
pub const BW_MIN: u32 = 7_800;
pub const BW_MAX: u32 = 1_625_000;
pub const SF_MIN: u8 = 5;
pub const SF_MAX: u8 = 12;
pub const CR_MIN: u8 = 5;
pub const CR_MAX: u8 = 8;

const DETECT_REQ: u8 = 0x73;
const BAUD_RATE: u32 = 115_200;
const RECONNECT_WAIT: u64 = 5;
const RSSI_OFFSET: i16 = 157;

pub struct RNodeInterface {
    pub base: Arc<Interface>,
    pub port_path: String,
    pub frequency: u32,
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: u8,
    flow_control: Arc<AtomicBool>,
    pub st_airl_limit: f64,
    pub lt_airl_limit: f64,
    last_rssi: Mutex<Option<i16>>,
    last_snr: Mutex<Option<i8>>,
    #[allow(dead_code)]
    last_q: Mutex<Option<u8>>,
    port: Mutex<Option<Box<dyn serialport::SerialPort>>>,
    shutdown: AtomicBool,
}

/// Validate radio parameters against allowed ranges.
pub fn validate_params(freq: u32, bw: u32, sf: u8, cr: u8, txp: u8) -> Result<()> {
    let err = |msg: String| crate::FerretError::InterfaceError(msg);
    if freq < FREQ_MIN || freq > FREQ_MAX {
        return Err(err(format!("frequency {} out of range [{}, {}]", freq, FREQ_MIN, FREQ_MAX)));
    }
    if bw < BW_MIN || bw > BW_MAX {
        return Err(err(format!("bandwidth {} out of range [{}, {}]", bw, BW_MIN, BW_MAX)));
    }
    if sf < SF_MIN || sf > SF_MAX {
        return Err(err(format!("SF {} out of range [{}, {}]", sf, SF_MIN, SF_MAX)));
    }
    if cr < CR_MIN || cr > CR_MAX {
        return Err(err(format!("CR {} out of range [{}, {}]", cr, CR_MIN, CR_MAX)));
    }
    if txp > TXPOWER_MAX {
        return Err(err(format!("tx_power {} out of range [{}, {}]", txp, TXPOWER_MIN, TXPOWER_MAX)));
    }
    Ok(())
}

/// Compute on-air bitrate from LoRa parameters.
/// Formula (Python ref): sf * (4.0 / cr) / (2^sf / (bw / 1000)) * 1000
pub fn compute_bitrate(sf: u8, cr: u8, bw: u32) -> u64 {
    let (sf_f, cr_f, bw_f) = (sf as f64, cr as f64, bw as f64);
    (sf_f * (4.0 / cr_f) / (f64::powf(2.0, sf_f) / (bw_f / 1000.0)) * 1000.0) as u64
}

impl RNodeInterface {
    pub fn new(
        port_path: String, frequency: u32, bandwidth: u32,
        spreading_factor: u8, coding_rate: u8, tx_power: u8, name: String,
    ) -> Result<Arc<Self>> {
        validate_params(frequency, bandwidth, spreading_factor, coding_rate, tx_power)?;
        let serial = open_port(&port_path)?;
        let tx_port = serial.try_clone().map_err(|e|
            crate::FerretError::InterfaceError(format!("serial clone: {e}")))?;
        let tx_mutex: Arc<Mutex<Box<dyn serialport::SerialPort>>> = Arc::new(Mutex::new(tx_port));
        let flow = Arc::new(AtomicBool::new(true));
        let flow_tx = Arc::clone(&flow);

        let transmit_fn: Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync> = {
            let tx = Arc::clone(&tx_mutex);
            Box::new(move |data: &[u8]| {
                for _ in 0..50 {
                    if flow_tx.load(Ordering::Relaxed) { break; }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let frame = kiss_codec::encode_data(data);
                tx.lock().unwrap_or_else(|e| e.into_inner())
                    .write_all(&frame)
                    .map_err(|e| crate::FerretError::InterfaceError(format!("rnode write: {e}")))?;
                Ok(())
            })
        };

        let bitrate = compute_bitrate(spreading_factor, coding_rate, bandwidth);
        let mut base = Interface::new(name, Some(transmit_fn));
        base.bitrate = bitrate;
        base.hw_mtu = Some(HW_MTU);
        base.dir_in = true;
        base.dir_out = true;
        base.online.store(true, Ordering::Relaxed);

        let iface = Arc::new(Self {
            base: Arc::new(base), port_path, frequency, bandwidth,
            spreading_factor, coding_rate, tx_power,
            flow_control: flow,
            st_airl_limit: 0.0, lt_airl_limit: 0.0,
            last_rssi: Mutex::new(None), last_snr: Mutex::new(None), last_q: Mutex::new(None),
            port: Mutex::new(Some(serial)), shutdown: AtomicBool::new(false),
        });
        iface.detect_rnode()?;
        iface.configure_radio()?;

        let c = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("rnode-read-{}", iface.base.name))
            .spawn(move || c.read_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn: {e}")))?;
        Ok(iface)
    }

    fn detect_rnode(&self) -> Result<()> {
        let cmd = kiss_codec::encode_command(CMD_DETECT, &[DETECT_REQ]);
        let mut guard = self.port.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut p) = *guard {
            p.write_all(&cmd).map_err(|e|
                crate::FerretError::InterfaceError(format!("detect write: {e}")))?;
        }
        Ok(())
    }

    fn configure_radio(&self) -> Result<()> {
        let mut guard = self.port.lock().unwrap_or_else(|e| e.into_inner());
        let port = guard.as_mut()
            .ok_or_else(|| crate::FerretError::InterfaceError("port closed".into()))?;
        let w = |p: &mut Box<dyn serialport::SerialPort>, d: &[u8]| -> Result<()> {
            p.write_all(d).map_err(|e| crate::FerretError::InterfaceError(format!("cfg: {e}")))
        };
        w(port, &kiss_codec::encode_command(CMD_FREQUENCY, &self.frequency.to_be_bytes()))?;
        w(port, &kiss_codec::encode_command(CMD_BANDWIDTH, &self.bandwidth.to_be_bytes()))?;
        w(port, &kiss_codec::encode_command(CMD_TXPOWER, &[self.tx_power]))?;
        w(port, &kiss_codec::encode_command(CMD_SF, &[self.spreading_factor]))?;
        w(port, &kiss_codec::encode_command(CMD_CR, &[self.coding_rate]))?;
        w(port, &kiss_codec::encode_command(CMD_RADIO_STATE, &[0x01]))?;
        Ok(())
    }

    fn read_loop(self: &Arc<Self>) {
        let mut buf = [0u8; 512];
        let mut decoder = KissDecoder::new(HW_MTU);
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
                match frame.command {
                    CMD_DATA if !frame.data.is_empty() => self.base.process_incoming(&frame.data),
                    CMD_STAT_RSSI => if let Some(&b) = frame.data.first() {
                        *self.last_rssi.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some((b as i16) - RSSI_OFFSET);
                    },
                    CMD_STAT_SNR => if let Some(&b) = frame.data.first() {
                        *self.last_snr.lock().unwrap_or_else(|e| e.into_inner()) = Some(b as i8);
                    },
                    CMD_READY => self.flow_control.store(true, Ordering::Relaxed),
                    _ => {}
                }
            }
        }
    }

    fn reconnect(self: &Arc<Self>) {
        while !self.shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(RECONNECT_WAIT));
            if self.shutdown.load(Ordering::Relaxed) { break; }
            match open_port(&self.port_path) {
                Ok(serial) => {
                    *self.port.lock().unwrap_or_else(|e| e.into_inner()) = Some(serial);
                    if self.detect_rnode().is_err() || self.configure_radio().is_err() { continue; }
                    self.base.online.store(true, Ordering::Relaxed);
                    let c = Arc::clone(self);
                    let _ = std::thread::Builder::new()
                        .name(format!("rnode-read-{}", self.base.name))
                        .spawn(move || c.read_loop());
                    return;
                }
                Err(_) => continue,
            }
        }
    }

    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);
    }
}

fn open_port(path: &str) -> Result<Box<dyn serialport::SerialPort>> {
    serialport::new(path, BAUD_RATE)
        .data_bits(serialport::DataBits::Eight)
        .parity(serialport::Parity::None)
        .stop_bits(serialport::StopBits::One)
        .timeout(Duration::from_millis(100))
        .open()
        .map_err(|e| crate::FerretError::InterfaceConnectionFailed(format!("rnode {path}: {e}")))
}
