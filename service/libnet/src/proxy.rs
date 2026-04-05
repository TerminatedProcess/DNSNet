/* Copyright (C) 2025 Charles Lombardo <clombardo169@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

use core::str;
use std::sync::Arc;

use ahash::RandomState;
use lru::LruCache;

use simple_dns::{Name, PacketFlag, ResourceRecord, rdata::RData};

use log::{debug, error, info, warn};

use crate::{
    ai_classifier::AiClassifier,
    backend::{DnsBackend, DnsBackendError, DnsResponseHandler, SocketProtector},
    beaconing_detector::BeaconingDetector,
    database::RuleDatabase,
    log::{BlockLogger, BlockSource},
    packet::GenericIpPacket,
    tracker_list::TrackerList,
    tunneling_detector::TunnelingDetector,
    vpn::VpnError,
};

/// Cached AI classification result
struct CachedAiResult {
    is_dga: bool,
    confidence: f32,
}

/// Handler for DNS packets that accepts or blocks them based on our [RuleDatabase],
/// AI classifier for DGA detection, and additional threat detectors.
pub struct DnsPacketProxy<'a> {
    socket_protector: &'a Box<&'a dyn SocketProtector>,
    block_logger: Option<Box<&'a dyn BlockLogger>>,
    rule_database: Arc<dyn RuleDatabase>,
    ai_classifier: Option<Arc<AiClassifier>>,
    ai_cache: LruCache<String, CachedAiResult, RandomState>,
    tunneling_detector: TunnelingDetector,
    beaconing_detector: BeaconingDetector,
    tracker_list: TrackerList,
    block_trackers: bool,
    upstream_dns_servers: Vec<Vec<u8>>,
    negative_cache_record: ResourceRecord<'a>,
}

impl<'a> DnsPacketProxy<'a> {
    const INVALID_HOST_NAME: &'static str = "dnsnet.dnsnet.invalid.";
    const NEGATIVE_CACHE_TTL_SECONDS: u32 = 5;

    pub fn new(
        socket_protector: &'a Box<&'a dyn SocketProtector>,
        block_logger_callback: Option<Box<&'a dyn BlockLogger>>,
        rule_database: Arc<dyn RuleDatabase>,
        ai_classifier: Option<Arc<AiClassifier>>,
        block_trackers: bool,
        upstream_dns_servers: Vec<Vec<u8>>,
    ) -> Self {
        let name = match Name::new(Self::INVALID_HOST_NAME) {
            Ok(value) => value,
            Err(error) => {
                panic!("Failed to parse our invalid host name! - {:?}", error);
            }
        };
        let soa_record = RData::SOA(simple_dns::rdata::SOA {
            mname: name.clone(),
            rname: name.clone(),
            serial: 0,
            refresh: 0,
            retry: 0,
            expire: 0,
            minimum: Self::NEGATIVE_CACHE_TTL_SECONDS,
        });
        let negative_cache_record = ResourceRecord::new(
            name,
            simple_dns::CLASS::IN,
            Self::NEGATIVE_CACHE_TTL_SECONDS,
            soa_record,
        );
        DnsPacketProxy {
            socket_protector,
            block_logger: block_logger_callback,
            rule_database,
            ai_classifier,
            ai_cache: LruCache::with_hasher(
                std::num::NonZeroUsize::new(10_000).unwrap(),
                RandomState::new(),
            ),
            tunneling_detector: TunnelingDetector::new(0.5),
            beaconing_detector: BeaconingDetector::new(60, 30),
            tracker_list: TrackerList::new(),
            block_trackers,
            upstream_dns_servers,
            negative_cache_record,
        }
    }

    /// Parses a packet, extracts a DNS request, and forwards it to the real DNS server if it's allowed
    pub fn handle_dns_request(
        &mut self,
        response_handler: &mut Box<&mut dyn DnsResponseHandler>,
        backend: &mut Box<dyn DnsBackend>,
        // dns_cache: Arc<DnsCacheBinding>,
        packet_data: &[u8],
    ) -> Result<(), VpnError> {
        let packet = match GenericIpPacket::from_ip_packet(packet_data) {
            Some(value) => value,
            None => {
                warn!(
                    "handle_dns_request: Failed to parse packet data - {:?}",
                    packet_data
                );
                return Ok(());
            }
        };

        let udp_packet = match packet.get_udp_packet() {
            Some(value) => value,
            None => {
                debug!("handle_dns_request: IP packet did not contain UDP payload");
                return Ok(());
            }
        };

        let destination_address = match packet.get_destination_address() {
            Some(value) => value,
            None => {
                warn!(
                    "handle_dns_request: Failed to get destination address for packet - {:?}",
                    packet
                );
                return Ok(());
            }
        };
        let translated_destination_address =
            match self.translate_destination_address(&destination_address) {
                Some(value) => value,
                None => {
                    warn!(
                        "handle_dns_request: Failed to translate destination address - {:?}",
                        destination_address
                    );
                    return Ok(());
                }
            };

        let destination_port = udp_packet.destination_port();
        let mut dns_packet = match simple_dns::Packet::parse(udp_packet.payload()) {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    "handle_dns_request: Discarding non-DNS or invalid packet - {:?}",
                    error
                );
                return Ok(());
            }
        };

        if dns_packet.questions.is_empty() {
            warn!(
                "handle_dns_request: Discarding DNS packet with no questions - {:?}",
                dns_packet
            );
            return Ok(());
        }

        let dns_query_name = dns_packet
            .questions
            .first()
            .unwrap()
            .qname
            .to_string()
            .to_lowercase();
        let blocked_by_list = self.rule_database.is_blocked(&dns_query_name);

        // AI classification: if not blocked by static list, check with AI classifier
        let mut ai_confidence: f32 = 0.0;
        let blocked_by_ai = if !blocked_by_list {
            // Check cache first
            if let Some(cached) = self.ai_cache.get(&dns_query_name) {
                ai_confidence = cached.confidence;
                cached.is_dga
            } else if let Some(ref classifier) = self.ai_classifier {
                if let Some(result) = classifier.classify(&dns_query_name) {
                    ai_confidence = result.dga_probability;
                    // Cache the result
                    self.ai_cache.put(dns_query_name.clone(), CachedAiResult {
                        is_dga: result.is_dga,
                        confidence: result.dga_probability,
                    });
                    if result.is_dga {
                        info!(
                            "handle_dns_request: AI blocked {} (DGA probability: {:.1}%)",
                            dns_query_name,
                            result.dga_probability * 100.0
                        );
                    }
                    result.is_dga
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        // DNS tunneling detection: check for encoded data in subdomains
        let blocked_by_tunneling = if !blocked_by_list && !blocked_by_ai {
            let tunnel_result = self.tunneling_detector.check(&dns_query_name);
            if tunnel_result.is_tunneling {
                info!(
                    "handle_dns_request: Tunneling detected {} (score: {:.1}%, entropy: {:.2}, subdomain len: {})",
                    dns_query_name,
                    tunnel_result.score * 100.0,
                    tunnel_result.entropy,
                    tunnel_result.subdomain_length,
                );
            }
            tunnel_result.is_tunneling
        } else {
            false
        };

        // Tracker detection: check against known tracker domains
        let tracker_result = self.tracker_list.check(&dns_query_name);
        let blocked_by_tracker = if tracker_result.is_tracker {
            info!(
                "handle_dns_request: Tracker detected {} — {} ({})",
                dns_query_name, tracker_result.service_name, tracker_result.category,
            );
            self.block_trackers
        } else {
            false
        };

        // Beaconing detection: track query frequency (flag only, don't block)
        let beacon_result = self.beaconing_detector.record_and_check(&dns_query_name);
        if beacon_result.is_beaconing {
            info!(
                "handle_dns_request: Beaconing detected {} ({} queries in {}s)",
                dns_query_name, beacon_result.query_count, beacon_result.window_seconds,
            );
        }

        let is_blocked = blocked_by_list || blocked_by_ai || blocked_by_tunneling || blocked_by_tracker;
        let block_source = if blocked_by_tunneling {
            BlockSource::Tunneling
        } else if blocked_by_ai {
            BlockSource::Ai
        } else if blocked_by_tracker {
            BlockSource::Tracker
        } else if blocked_by_list {
            BlockSource::Blocklist
        } else if tracker_result.is_tracker {
            BlockSource::Tracker
        } else if beacon_result.is_beaconing {
            BlockSource::Beaconing
        } else {
            BlockSource::None
        };

        if !is_blocked {
            info!(
                "handle_dns_request: DNS Name {} allowed. Sending to {:?}",
                dns_query_name,
                str::from_utf8(&translated_destination_address),
            );

            if let Some(block_logger) = &self.block_logger {
                block_logger.log_with_ai(dns_query_name.clone(), true, block_source, ai_confidence);
            }

            if let Err(error) = backend.forward_packet(
                self.socket_protector,
                udp_packet.payload(),
                packet_data,
                translated_destination_address,
                destination_port,
            ) {
                error!("handle_dns_request: Failed to forward packet - {:?}", error);
                match error {
                    DnsBackendError::SocketFailure => return Err(VpnError::SocketFailure),
                    _ => return Ok(()),
                }
            }
        } else {
            let source = if blocked_by_tunneling { "tunneling detector" } else if blocked_by_tracker { "tracker blocker" } else if blocked_by_ai { "AI" } else { "blocklist" };
            info!("handle_dns_request: DNS Name {} blocked by {}!", dns_query_name, source);

            if let Some(block_logger) = &self.block_logger {
                block_logger.log_with_ai(dns_query_name.clone(), false, block_source, ai_confidence);
            }

            dns_packet.set_flags(PacketFlag::RESPONSE);
            *dns_packet.rcode_mut() = simple_dns::RCODE::NoError;
            dns_packet
                .additional_records
                .push(self.negative_cache_record.clone());

            let mut wire = Vec::<u8>::new();
            if let Err(error) = dns_packet.write_to(&mut wire) {
                error!("Failed to write DNS packet to wire! - {:?}", error);
                return Ok(());
            }

            response_handler.handle(packet_data, &wire);
        }
        return Ok(());
    }

    /// Translates the destination address using our upstream servers as configured by the VpnThread
    fn translate_destination_address(&self, destination_address: &Vec<u8>) -> Option<Vec<u8>> {
        return if !self.upstream_dns_servers.is_empty() {
            let index = match destination_address.get(destination_address.len() - 1) {
                Some(value) => value,
                None => {
                    debug!(
                        "translate_destination_address: Failed to get upstream index from destination address"
                    );
                    return None;
                }
            };

            self.upstream_dns_servers
                .get((*index - 2) as usize)
                .cloned()
        } else {
            Some(destination_address.clone())
        };
    }
}
