/// Hex formatting utilities matching RNS.hexrep / RNS.prettyhexrep.

/// Colon-delimited lowercase hex: "de:ad:be:ef"
/// Empty input returns "".
pub fn hexrep(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Non-delimited lowercase hex: "deadbeef"
/// Empty input returns "".
pub fn hexrep_no_delimit(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Pretty hex in angle brackets: "<deadbeef>"
/// Empty input returns "<>".
pub fn prettyhexrep(data: &[u8]) -> String {
    format!("<{}>", hexrep_no_delimit(data))
}
