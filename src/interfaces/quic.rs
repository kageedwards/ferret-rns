// QUICInterface — QUIC transport via quinn. Bridges async/sync with a
// per-interface tokio runtime. Ferret-original (not in Python reference).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use quinn::{Connection, Endpoint};
use tokio::runtime::Runtime;

use crate::interfaces::base::Interface;
use crate::Result;

pub const HW_MTU: usize = 1200;
pub const BITRATE_GUESS: u64 = 10_000_000;
pub const DEFAULT_IFAC_SIZE: usize = 16;
const RECONNECT_WAIT: u64 = 5;

pub struct QUICInterface {
    pub base: Arc<Interface>,
    pub target_host: String,
    pub target_port: u16,
    pub initiator: bool,
    pub reconnecting: AtomicBool,
    pub shutdown: AtomicBool,
    connection: Mutex<Option<Connection>>,
    endpoint: Mutex<Option<Endpoint>>,
    runtime: Arc<Runtime>,
}

fn err(msg: String) -> crate::FerretError { crate::FerretError::InterfaceError(msg) }

// ── TLS helpers ──

fn make_server_config() -> Result<quinn::ServerConfig> {
    let ck = rcgen::generate_simple_self_signed(vec!["rns".into()])
        .map_err(|e| err(format!("rcgen: {e}")))?;
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone().into()], key.into())
        .map_err(|e| err(format!("rustls: {e}")))?;
    tls.alpn_protocols = vec![b"rns".to_vec()];
    let qc = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| err(format!("quic cfg: {e}")))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(qc)))
}

fn make_client_config() -> quinn::ClientConfig {
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let qc = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .expect("rustls client config");
    quinn::ClientConfig::new(Arc::new(qc))
}

/// Dummy cert verifier — Reticulum authenticates via IFAC/Identity.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self, _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>, _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms.supported_schemes()
    }
}

// ── Transmit helper ──

fn make_transmit_fn(conn: Connection) -> Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync> {
    Box::new(move |data: &[u8]| {
        match conn.send_datagram(Bytes::copy_from_slice(data)) {
            Ok(()) => Ok(()),
            Err(_) => {
                // Datagram too large — fall back to uni stream.
                let c = conn.clone();
                let buf = data.to_vec();
                std::thread::spawn(move || {
                    if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                        .enable_io().build()
                    {
                        let _ = rt.block_on(async {
                            if let Ok(mut s) = c.open_uni().await {
                                let _ = s.write_all(&buf).await;
                                let _ = s.finish();
                            }
                        });
                    }
                });
                Ok(())
            }
        }
    })
}

// ── QUICInterface ──

fn new_base(name: String, tx: Option<Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync>>) -> Interface {
    let mut b = Interface::new(name, tx);
    b.bitrate = BITRATE_GUESS;
    b.hw_mtu = Some(HW_MTU);
    b
}

impl QUICInterface {
    /// Connect as a QUIC client.
    pub fn connect(target_host: String, target_port: u16, name: String) -> Result<Arc<Self>> {
        let rt = Runtime::new().map_err(|e| err(format!("tokio: {e}")))?;
        let addr: std::net::SocketAddr = format!("{target_host}:{target_port}")
            .parse().map_err(|e| err(format!("bad addr: {e}")))?;

        let mut ep = rt.block_on(async {
            Endpoint::client("0.0.0.0:0".parse().unwrap())
                .map_err(|e| err(format!("endpoint: {e}")))
        })?;
        ep.set_default_client_config(make_client_config());

        let conn = rt.block_on(async {
            ep.connect(addr, "rns").map_err(|e| err(format!("connect: {e}")))?
                .await.map_err(|e| err(format!("handshake: {e}")))
        })?;

        let mut base = new_base(name.clone(), Some(make_transmit_fn(conn.clone())));
        base.dir_in = true;
        base.dir_out = true;
        base.online.store(true, Ordering::Relaxed);

        let runtime = Arc::new(rt);
        let iface = Arc::new(Self {
            base: Arc::new(base), target_host, target_port,
            initiator: true, reconnecting: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            connection: Mutex::new(Some(conn)),
            endpoint: Mutex::new(Some(ep)), runtime,
        });
        let c = Arc::clone(&iface);
        std::thread::Builder::new().name(format!("quic-read-{name}"))
            .spawn(move || c.read_loop()).map_err(|e| err(format!("spawn: {e}")))?;
        Ok(iface)
    }

    /// Start a QUIC server.
    pub fn serve(bind_ip: String, bind_port: u16, name: String) -> Result<Arc<Self>> {
        let rt = Runtime::new().map_err(|e| err(format!("tokio: {e}")))?;
        let addr: std::net::SocketAddr = format!("{bind_ip}:{bind_port}")
            .parse().map_err(|e| err(format!("bad addr: {e}")))?;
        let ep = rt.block_on(async {
            Endpoint::server(make_server_config()?, addr)
                .map_err(|e| err(format!("bind: {e}")))
        })?;

        let base = new_base(name.clone(), None);
        base.online.store(true, Ordering::Relaxed);

        let runtime = Arc::new(rt);
        let ep2 = ep.clone();
        let iface = Arc::new(Self {
            base: Arc::new(base), target_host: bind_ip, target_port: bind_port,
            initiator: false, reconnecting: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            connection: Mutex::new(None),
            endpoint: Mutex::new(Some(ep)), runtime: Arc::clone(&runtime),
        });
        let srv = Arc::clone(&iface);
        let rt2 = Arc::clone(&runtime);
        std::thread::Builder::new().name(format!("quic-srv-{name}"))
            .spawn(move || rt2.block_on(async {
                while let Some(inc) = ep2.accept().await {
                    if srv.shutdown.load(Ordering::Relaxed) { break; }
                    if let Ok(conn) = inc.await {
                        let child = format!("Client on {}", srv.base.name);
                        std::thread::spawn(move || { let _ = QUICInterface::from_connection(conn, child); });
                    }
                }
            })).map_err(|e| err(format!("spawn: {e}")))?;
        Ok(iface)
    }

    /// Wrap an accepted QUIC connection.
    pub fn from_connection(connection: Connection, name: String) -> Result<Arc<Self>> {
        let rt = Runtime::new().map_err(|e| err(format!("tokio: {e}")))?;
        let peer = connection.remote_address();
        let mut base = new_base(name.clone(), Some(make_transmit_fn(connection.clone())));
        base.dir_in = true;
        base.dir_out = true;
        base.online.store(true, Ordering::Relaxed);

        let iface = Arc::new(Self {
            base: Arc::new(base),
            target_host: peer.ip().to_string(), target_port: peer.port(),
            initiator: false, reconnecting: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            connection: Mutex::new(Some(connection)),
            endpoint: Mutex::new(None), runtime: Arc::new(rt),
        });
        let c = Arc::clone(&iface);
        std::thread::Builder::new().name(format!("quic-read-{name}"))
            .spawn(move || c.read_loop()).map_err(|e| err(format!("spawn: {e}")))?;
        Ok(iface)
    }

    fn read_loop(self: &Arc<Self>) {
        let conn = match self.connection.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            Some(c) => c,
            None => return,
        };
        self.runtime.block_on(async {
            loop {
                if self.shutdown.load(Ordering::Relaxed) { break; }
                tokio::select! {
                    dg = conn.read_datagram() => match dg {
                        Ok(data) => self.base.process_incoming(&data),
                        Err(_) => { self.handle_disconnect(); break; }
                    },
                    uni = conn.accept_uni() => match uni {
                        Ok(mut recv) => {
                            if let Ok(data) = recv.read_to_end(HW_MTU * 16).await {
                                if !data.is_empty() { self.base.process_incoming(&data); }
                            }
                        }
                        Err(_) => { self.handle_disconnect(); break; }
                    },
                }
            }
        });
    }

    fn handle_disconnect(self: &Arc<Self>) {
        self.base.online.store(false, Ordering::Relaxed);
        if self.initiator && !self.shutdown.load(Ordering::Relaxed) {
            self.reconnect();
        } else {
            self.detach();
        }
    }

    fn reconnect(self: &Arc<Self>) {
        if !self.initiator || self.shutdown.load(Ordering::Relaxed) { return; }
        if self.reconnecting.swap(true, Ordering::SeqCst) { return; }

        let addr: std::net::SocketAddr = match format!("{}:{}", self.target_host, self.target_port).parse() {
            Ok(a) => a,
            Err(_) => { self.reconnecting.store(false, Ordering::Relaxed); self.detach(); return; }
        };
        while !self.base.online.load(Ordering::Relaxed) && !self.shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(RECONNECT_WAIT));
            let ep = self.endpoint.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(ep) = ep {
                if let Ok(conn) = self.runtime.block_on(async {
                    ep.connect(addr, "rns").map_err(|e| err(format!("{e}")))?
                        .await.map_err(|e| err(format!("{e}")))
                }) {
                    *self.connection.lock().unwrap_or_else(|e| e.into_inner()) = Some(conn);
                    self.base.online.store(true, Ordering::Relaxed);
                }
            } else { break; }
        }
        self.reconnecting.store(false, Ordering::Relaxed);
        if self.base.online.load(Ordering::Relaxed) && !self.shutdown.load(Ordering::Relaxed) {
            let c = Arc::clone(self);
            let _ = std::thread::Builder::new()
                .name(format!("quic-read-{}", self.base.name))
                .spawn(move || c.read_loop());
        }
    }

    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);
        if let Some(c) = self.connection.lock().unwrap_or_else(|e| e.into_inner()).take() {
            c.close(0u32.into(), b"detach");
        }
    }
}
