// PipeInterface — spawns an external process, communicates via stdin/stdout with HDLC framing.
// Ported from: lxcf/_ref_rns/Interfaces/PipeInterface.py

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::interfaces::base::Interface;
use crate::interfaces::hdlc_codec::{self, HdlcDecoder};
use crate::Result;

pub const HW_MTU: usize = 1064;
pub const BITRATE_GUESS: u64 = 1_000_000;
pub const DEFAULT_IFAC_SIZE: usize = 8;
pub const DEFAULT_RESPAWN_DELAY: u64 = 5;

pub struct PipeInterface {
    pub base: Arc<Interface>,
    pub command: String,
    pub respawn_delay: u64,
    process_stdin: Arc<Mutex<Option<std::process::ChildStdin>>>,
    process: Mutex<Option<Child>>,
    shutdown: AtomicBool,
}

impl PipeInterface {
    /// Spawn the external process and start the read loop.
    pub fn new(command: String, name: String, respawn_delay: u64) -> Result<Arc<Self>> {
        let mut child = spawn_command(&command)?;
        let child_stdin = child.stdin.take().ok_or_else(|| {
            crate::FerretError::InterfaceError("failed to capture process stdin".into())
        })?;
        let child_stdout = child.stdout.take().ok_or_else(|| {
            crate::FerretError::InterfaceError("failed to capture process stdout".into())
        })?;
        let stdin_handle: Arc<Mutex<Option<std::process::ChildStdin>>> =
            Arc::new(Mutex::new(Some(child_stdin)));

        let transmit_fn: Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync> = {
            let tx = Arc::clone(&stdin_handle);
            Box::new(move |data: &[u8]| {
                let framed = hdlc_codec::encode(data);
                let mut guard = tx.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(ref mut w) = *guard {
                    w.write_all(&framed).map_err(|e| {
                        crate::FerretError::InterfaceError(format!("pipe write: {e}"))
                    })?;
                    w.flush().map_err(|e| {
                        crate::FerretError::InterfaceError(format!("pipe flush: {e}"))
                    })?;
                }
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
            base: Arc::new(base),
            command,
            respawn_delay,
            process_stdin: stdin_handle,
            process: Mutex::new(Some(child)),
            shutdown: AtomicBool::new(false),
        });
        let c = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("pipe-read-{}", iface.base.name))
            .spawn(move || c.read_loop_with(child_stdout))
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn error: {e}")))?;
        Ok(iface)
    }

    /// Read from process stdout, decode HDLC frames, deliver to base.
    fn read_loop_with(self: &Arc<Self>, mut stdout: std::process::ChildStdout) {
        let mut buf = [0u8; 512];
        let mut decoder = HdlcDecoder::new(HW_MTU);
        loop {
            if self.shutdown.load(Ordering::Relaxed) { break; }
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    for frame in decoder.feed(&buf[..n]) {
                        if !frame.is_empty() { self.base.process_incoming(&frame); }
                    }
                }
            }
        }
        self.base.online.store(false, Ordering::Relaxed);
        self.kill_process();
        if !self.shutdown.load(Ordering::Relaxed) { self.reconnect(); }
    }

    /// Respawn the process after a delay and restart the read loop.
    fn reconnect(self: &Arc<Self>) {
        while !self.shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(self.respawn_delay));
            if self.shutdown.load(Ordering::Relaxed) { break; }
            if let Ok(mut child) = spawn_command(&self.command) {
                let (stdin, stdout) = match (child.stdin.take(), child.stdout.take()) {
                    (Some(i), Some(o)) => (i, o),
                    _ => continue,
                };
                *self.process_stdin.lock().unwrap_or_else(|e| e.into_inner()) = Some(stdin);
                *self.process.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);
                self.base.online.store(true, Ordering::Relaxed);
                let c = Arc::clone(self);
                let _ = std::thread::Builder::new()
                    .name(format!("pipe-read-{}", self.base.name))
                    .spawn(move || c.read_loop_with(stdout));
                return;
            }
        }
    }

    fn kill_process(&self) {
        *self.process_stdin.lock().unwrap_or_else(|e| e.into_inner()) = None;
        if let Some(ref mut child) = *self.process.lock().unwrap_or_else(|e| e.into_inner()) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Shut down the interface.
    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);
        self.kill_process();
    }
}

fn spawn_command(command: &str) -> Result<Child> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return Err(crate::FerretError::InterfaceError("empty pipe command".into()));
    }
    Command::new(parts[0])
        .args(&parts[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| crate::FerretError::InterfaceConnectionFailed(
            format!("pipe command '{command}': {e}"),
        ))
}
