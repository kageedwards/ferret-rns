// Address validation helpers: is_ip_address, is_hostname

use std::net::IpAddr;
use std::str::FromStr;

/// Check if a string is a valid IP address (IPv4 or IPv6).
pub fn is_ip_address(address: &str) -> bool {
    IpAddr::from_str(address).is_ok()
}

/// Check if a string is a valid hostname per RFC 952/1123.
///
/// Rules:
/// - Total length <= 253 characters
/// - At least 2 labels separated by dots
/// - Each label 1–63 characters
/// - Labels contain only alphanumeric characters and hyphens
/// - Labels must not start or end with a hyphen
pub fn is_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    let labels: Vec<&str> = hostname.split('.').collect();

    // Must have at least 2 labels (e.g., "example.com")
    if labels.len() < 2 {
        return false;
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ipv4() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("0.0.0.0"));
        assert!(is_ip_address("255.255.255.255"));
        assert!(is_ip_address("127.0.0.1"));
    }

    #[test]
    fn test_valid_ipv6() {
        assert!(is_ip_address("::1"));
        assert!(is_ip_address("fe80::1"));
        assert!(is_ip_address("2001:db8::1"));
    }

    #[test]
    fn test_invalid_ip() {
        assert!(!is_ip_address(""));
        assert!(!is_ip_address("not-an-ip"));
        assert!(!is_ip_address("256.1.1.1"));
        assert!(!is_ip_address("192.168.1"));
    }

    #[test]
    fn test_valid_hostname() {
        assert!(is_hostname("example.com"));
        assert!(is_hostname("sub.example.com"));
        assert!(is_hostname("my-host.example.org"));
        assert!(is_hostname("a1.b2"));
    }

    #[test]
    fn test_invalid_hostname() {
        assert!(!is_hostname(""));
        assert!(!is_hostname("localhost")); // single label
        assert!(!is_hostname("-bad.com"));
        assert!(!is_hostname("bad-.com"));
        assert!(!is_hostname("too..many.dots"));
        assert!(!is_hostname("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.\
            a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.\
            a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.\
            a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.\
            a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.\
            a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.\
            a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.\
            a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.\
            a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.\
            a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.com"));
    }
}
