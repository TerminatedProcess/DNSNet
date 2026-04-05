//! TLS ClientHello SNI inspector.
//!
//! Parses the Server Name Indication (SNI) extension from TLS ClientHello
//! messages in TCP packets. The SNI is sent in plaintext even in HTTPS
//! connections, revealing which server the client is connecting to.
//!
//! This enables a second layer of visibility beyond DNS: we can see the
//! actual TLS connections being established, catch connections to servers
//! resolved via cached DNS or hardcoded IPs, and detect ad/tracker
//! connections that bypass DNS-level blocking.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use lru::LruCache;
use log::info;

use crate::tracker_list::{TrackerList, TrackerResult};

/// Extracted SNI information from a TLS ClientHello.
#[derive(Debug, Clone)]
pub struct SniInfo {
    /// The server name from the SNI extension.
    pub server_name: String,
    /// Destination port (usually 443).
    pub dest_port: u16,
}

/// Result of SNI inspection for logging/blocking.
#[derive(Debug, Clone)]
pub struct SniResult {
    pub server_name: String,
    pub is_tracker: bool,
    pub tracker_category: &'static str,
    pub tracker_service: &'static str,
    pub should_block: bool,
}

/// Inspects TLS ClientHello packets for SNI and cross-references
/// against the tracker list for visibility and optional blocking.
pub struct SniInspector {
    tracker_list: TrackerList,
    block_trackers: bool,
    /// Track SNI connections we've already logged to avoid spam.
    /// Key: server_name, Value: last log timestamp.
    seen_cache: LruCache<String, u64>,
    /// Count connections per SNI for reporting.
    connection_counts: LruCache<String, u32>,
}

impl SniInspector {
    pub fn new(block_trackers: bool) -> Self {
        SniInspector {
            tracker_list: TrackerList::new(),
            block_trackers,
            seen_cache: LruCache::new(NonZeroUsize::new(5000).unwrap()),
            connection_counts: LruCache::new(NonZeroUsize::new(5000).unwrap()),
        }
    }

    /// Try to extract SNI from a raw IP packet payload.
    /// Returns None if the packet is not a TLS ClientHello or has no SNI.
    pub fn extract_sni_from_packet(&self, packet_data: &[u8]) -> Option<SniInfo> {
        // Parse IP header to find TCP payload
        let tcp_payload = self.get_tcp_payload(packet_data)?;
        let dest_port = self.get_tcp_dest_port(packet_data)?;

        // Only inspect port 443 (HTTPS)
        if dest_port != 443 {
            return None;
        }

        // Parse TLS ClientHello and extract SNI
        let server_name = parse_tls_client_hello_sni(tcp_payload)?;

        Some(SniInfo {
            server_name,
            dest_port,
        })
    }

    /// Inspect a packet and return an SniResult if it contains a TLS ClientHello with SNI.
    /// Logs new SNI connections and checks against the tracker list.
    pub fn inspect(&mut self, packet_data: &[u8]) -> Option<SniResult> {
        let sni_info = self.extract_sni_from_packet(packet_data)?;

        // Update connection count
        let count = self.connection_counts
            .get_or_insert_mut(sni_info.server_name.clone(), || 0);
        *count += 1;

        // Check tracker list
        let tracker_result = self.tracker_list.check(&sni_info.server_name);

        // Only log if we haven't seen this SNI recently (within 60s)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let should_log = match self.seen_cache.get(&sni_info.server_name) {
            Some(&last_seen) => now - last_seen >= 60,
            None => true,
        };

        if should_log {
            self.seen_cache.put(sni_info.server_name.clone(), now);

            if tracker_result.is_tracker {
                info!(
                    "SNI: tracker connection to {} — {} ({}){}",
                    sni_info.server_name,
                    tracker_result.service_name,
                    tracker_result.category,
                    if self.block_trackers { " [BLOCKED]" } else { "" },
                );
            } else {
                info!("SNI: connection to {}", sni_info.server_name);
            }
        }

        Some(SniResult {
            server_name: sni_info.server_name,
            is_tracker: tracker_result.is_tracker,
            tracker_category: tracker_result.category,
            tracker_service: tracker_result.service_name,
            should_block: tracker_result.is_tracker && self.block_trackers,
        })
    }

    /// Extract TCP payload from a raw IP packet.
    fn get_tcp_payload<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        use etherparse::SlicedPacket;
        let packet = SlicedPacket::from_ip(data).ok()?;
        match packet.transport {
            Some(etherparse::TransportSlice::Tcp(tcp)) => {
                let payload = tcp.payload();
                if payload.is_empty() {
                    None
                } else {
                    Some(payload)
                }
            }
            _ => None,
        }
    }

    /// Extract TCP destination port from a raw IP packet.
    fn get_tcp_dest_port(&self, data: &[u8]) -> Option<u16> {
        use etherparse::SlicedPacket;
        let packet = SlicedPacket::from_ip(data).ok()?;
        match packet.transport {
            Some(etherparse::TransportSlice::Tcp(tcp)) => Some(tcp.destination_port()),
            _ => None,
        }
    }
}

/// Parse a TLS ClientHello message and extract the SNI server name.
///
/// TLS Record format:
///   byte 0: content_type (0x16 = handshake)
///   byte 1-2: version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
///   byte 3-4: length
///   byte 5+: handshake message
///
/// Handshake message:
///   byte 0: handshake_type (0x01 = ClientHello)
///   byte 1-3: length
///   byte 4-5: client version
///   byte 6-37: random (32 bytes)
///   then: session_id, cipher_suites, compression_methods, extensions
///
/// SNI extension type: 0x0000
fn parse_tls_client_hello_sni(data: &[u8]) -> Option<String> {
    // Minimum TLS record header: 5 bytes
    if data.len() < 5 {
        return None;
    }

    // Check content type: handshake (0x16)
    if data[0] != 0x16 {
        return None;
    }

    // TLS version check (we accept any)
    // data[1..3] is the version

    // Record length
    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_length {
        return None;
    }

    let handshake = &data[5..5 + record_length];

    // Check handshake type: ClientHello (0x01)
    if handshake.is_empty() || handshake[0] != 0x01 {
        return None;
    }

    // Handshake length (3 bytes)
    if handshake.len() < 4 {
        return None;
    }
    let hs_length = ((handshake[1] as usize) << 16)
        | ((handshake[2] as usize) << 8)
        | (handshake[3] as usize);

    if handshake.len() < 4 + hs_length {
        return None;
    }

    let hello = &handshake[4..4 + hs_length];

    // Client version (2 bytes) + random (32 bytes) = 34 bytes
    if hello.len() < 34 {
        return None;
    }
    let mut pos = 34;

    // Session ID
    if pos >= hello.len() {
        return None;
    }
    let session_id_len = hello[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > hello.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods
    if pos >= hello.len() {
        return None;
    }
    let compression_len = hello[pos] as usize;
    pos += 1 + compression_len;

    // Extensions
    if pos + 2 > hello.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > hello.len() {
        return None;
    }

    // Walk through extensions looking for SNI (type 0x0000)
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            return parse_sni_extension(&hello[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    None
}

/// Parse the SNI extension data to extract the server name.
///
/// SNI extension format:
///   byte 0-1: server_name_list_length
///   byte 2: server_name_type (0x00 = hostname)
///   byte 3-4: server_name_length
///   byte 5+: server_name (ASCII)
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // Server name list length
    let _list_len = u16::from_be_bytes([data[0], data[1]]) as usize;

    // Server name type (0x00 = hostname)
    if data[2] != 0x00 {
        return None;
    }

    // Server name length
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + name_len {
        return None;
    }

    // Extract hostname
    let name_bytes = &data[5..5 + name_len];
    String::from_utf8(name_bytes.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello with the given SNI hostname.
    fn build_client_hello(hostname: &str) -> Vec<u8> {
        let hostname_bytes = hostname.as_bytes();

        // SNI extension
        let sni_ext_data = {
            let mut d = Vec::new();
            let name_len = hostname_bytes.len() as u16;
            let list_len = name_len + 3; // type(1) + length(2) + name
            d.extend_from_slice(&list_len.to_be_bytes());
            d.push(0x00); // type: hostname
            d.extend_from_slice(&name_len.to_be_bytes());
            d.extend_from_slice(hostname_bytes);
            d
        };

        // Extensions block
        let extensions = {
            let mut e = Vec::new();
            // SNI extension type = 0x0000
            e.extend_from_slice(&0u16.to_be_bytes());
            e.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
            e.extend_from_slice(&sni_ext_data);
            e
        };

        // ClientHello body
        let hello = {
            let mut h = Vec::new();
            h.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
            h.extend_from_slice(&[0u8; 32]);     // random
            h.push(0);                            // session_id length = 0
            h.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length = 2
            h.extend_from_slice(&[0x00, 0xff]);   // one cipher suite
            h.push(1);                            // compression methods length = 1
            h.push(0);                            // null compression
            h.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            h.extend_from_slice(&extensions);
            h
        };

        // Handshake message
        let handshake = {
            let mut hs = Vec::new();
            hs.push(0x01); // ClientHello
            let len = hello.len();
            hs.push((len >> 16) as u8);
            hs.push((len >> 8) as u8);
            hs.push(len as u8);
            hs.extend_from_slice(&hello);
            hs
        };

        // TLS record
        let mut record = Vec::new();
        record.push(0x16); // content type: handshake
        record.extend_from_slice(&[0x03, 0x01]); // version TLS 1.0
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn test_parse_sni_google() {
        let hello = build_client_hello("www.google.com");
        let sni = parse_tls_client_hello_sni(&hello);
        assert_eq!(sni, Some("www.google.com".to_string()));
    }

    #[test]
    fn test_parse_sni_facebook_tracker() {
        let hello = build_client_hello("graph.facebook.com");
        let sni = parse_tls_client_hello_sni(&hello);
        assert_eq!(sni, Some("graph.facebook.com".to_string()));
    }

    #[test]
    fn test_parse_sni_empty_data() {
        let sni = parse_tls_client_hello_sni(&[]);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_parse_sni_not_tls() {
        let sni = parse_tls_client_hello_sni(&[0x17, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_parse_sni_not_client_hello() {
        // content_type = handshake, but handshake_type = 0x02 (ServerHello)
        let mut data = vec![0x16, 0x03, 0x01, 0x00, 0x05];
        data.push(0x02); // ServerHello, not ClientHello
        data.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]);
        let sni = parse_tls_client_hello_sni(&data);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_inspector_tracker_detection() {
        let mut inspector = SniInspector::new(false);
        let tracker = inspector.tracker_list.check("graph.facebook.com");
        assert!(tracker.is_tracker);
        assert_eq!(tracker.service_name, "Facebook SDK");
    }

    #[test]
    fn test_inspector_not_tracker() {
        let inspector = SniInspector::new(false);
        let result = inspector.tracker_list.check("www.google.com");
        assert!(!result.is_tracker);
    }

    #[test]
    fn test_long_hostname() {
        let long_name = "a".repeat(200) + ".example.com";
        let hello = build_client_hello(&long_name);
        let sni = parse_tls_client_hello_sni(&hello);
        assert_eq!(sni, Some(long_name));
    }
}
