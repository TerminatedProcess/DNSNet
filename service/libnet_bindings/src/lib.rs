/* Copyright (C) 2025 Charles Lombardo <clombardo169@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

mod cache;
mod database;
mod validation;
mod vpn;

use std::{
    fs::File,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    os::fd::FromRawFd,
    str::FromStr,
    sync::Arc,
};

use android_logger::Config;
use database::RuleDatabaseBinding;
use log::{LevelFilter, debug, error, info};
use mio::net::UdpSocket;
use net::{backend::SocketProtector, file::FileHelper, log::{BlockLogger, BlockSource}};
use vpn::{Vpn, VpnConfigurationResult, VpnResultBinding};

use crate::{
    cache::DnsCacheBinding,
    vpn::{VpnControllerBinding, VpnErrorBinding},
};

uniffi::setup_scaffolding!();

/// Initializes the logger for the Rust side of the VPN
///
/// This should be called before any other Rust functions in the Kotlin code
#[uniffi::export]
pub fn rust_init(debug: bool) {
    android_logger::init_once(
        Config::default()
            .with_max_level(if debug {
                LevelFilter::Trace
            } else {
                LevelFilter::Info
            }) // limit log level
            .with_tag("DNSNet Native"), // logs will show under mytag tag
    );
}

/// Entrypoint for starting the VPN from Kotlin
///
/// Runs the main loop for the service based on the descriptor given
/// by the Android system.
#[uniffi::export]
pub fn run_vpn_native(
    ad_vpn_callback: Box<dyn VpnCallback>,
    block_logger_callback: Option<Box<dyn BlockLoggerBinding>>,
    vpn_controller: Arc<VpnControllerBinding>,
    rule_database: Arc<RuleDatabaseBinding>,
    android_file_helper: Box<dyn FileHelperBinding>,
    is_doh3: bool,
    is_ai_enabled: bool,
    is_block_trackers_enabled: bool,
) -> Result<VpnResultBinding, VpnErrorBinding> {
    let mut vpn = Vpn::new(vpn_controller);
    let result = vpn.run(
        ad_vpn_callback,
        block_logger_callback,
        rule_database,
        android_file_helper,
        is_doh3,
        is_ai_enabled,
        is_block_trackers_enabled,
    );
    info!("run_vpn_native: Stopped");
    return result;
}

#[uniffi::export]
pub fn network_has_ipv6_support() -> bool {
    let socket = match UdpSocket::bind(SocketAddr::new(
        std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        0,
    )) {
        Ok(value) => value,
        Err(error) => {
            error!("has_ipv6_support: Failed to create socket! - {:?}", error);
            return false;
        }
    };

    let target_socket_address = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from_str("2001:2::").unwrap(),
        53,
        0,
        0,
    ));
    if let Err(error) = socket.send_to(&mut vec![1; 1], target_socket_address) {
        debug!("has_ipv6_support: Error during IPv6 test - {:?}", error);
        return false;
    }

    return true;
}

/// Callback interface to be implemented by a Kotlin class and then passed into the main loop
#[uniffi::export(callback_interface)]
pub trait VpnCallback: Send + Sync {
    fn configure(
        &self,
        vpn_controller: Arc<VpnControllerBinding>,
        dns_cache: Arc<DnsCacheBinding>,
    ) -> VpnConfigurationResult;

    fn protect_raw_socket_fd(&self, socket_fd: i32) -> bool;

    fn update_status(&self, native_status: i32);
}

impl SocketProtector for Box<dyn VpnCallback> {
    fn protect_fd(&self, fd: i32) -> bool {
        self.protect_raw_socket_fd(fd)
    }
}

/// Callback interface for accessing our filter files from the Android system
#[uniffi::export(callback_interface)]
pub trait FileHelperBinding {
    fn get_fd(&self, path: String) -> Option<i32>;
    fn get_dns_cache_file_fd(&self) -> Option<i32>;
    /// Returns the AI classifier model binary data, or None if unavailable
    fn get_ai_model_data(&self) -> Option<Vec<u8>>;

    /// Get user-whitelisted domains (policy = "allow")
    fn get_allowed_domains(&self) -> Option<Vec<String>>;

    /// Get user-blacklisted domains (policy = "block")
    fn get_blocked_domains(&self) -> Option<Vec<String>>;
}

impl FileHelper for &Box<dyn FileHelperBinding> {
    fn get_file(&self, path: String) -> Option<File> {
        let fd = self.get_fd(path)?;
        return Some(unsafe { File::from_raw_fd(fd) });
    }
}

/// Callback interface for logging connections that we've blocked for the block logger
#[uniffi::export(callback_interface)]
pub trait BlockLoggerBinding: Send + Sync {
    fn log_connection(&self, connection_name: String, allowed: bool);

    /// Extended log with AI classification data
    /// block_source: "none", "blocklist", "ai", "tunneling", "tracker", or "beaconing"
    /// ai_confidence: 0.0-1.0 DGA probability (0.0 if not AI-classified)
    fn log_connection_with_ai(
        &self,
        connection_name: String,
        allowed: bool,
        block_source: String,
        ai_confidence: f32,
    );
}

impl BlockLogger for Box<dyn BlockLoggerBinding> {
    fn log(&self, connection_name: String, allowed: bool) {
        self.log_connection(connection_name, allowed);
    }

    fn log_with_ai(
        &self,
        connection_name: String,
        allowed: bool,
        block_source: BlockSource,
        ai_confidence: f32,
    ) {
        let source_str = match block_source {
            BlockSource::Blocklist => "blocklist",
            BlockSource::Ai => "ai",
            BlockSource::Tunneling => "tunneling",
            BlockSource::Tracker => "tracker",
            BlockSource::Beaconing => "beaconing",
            BlockSource::UserPolicy => "user_policy",
            BlockSource::None => "none",
        };
        self.log_connection_with_ai(connection_name, allowed, source_str.to_string(), ai_confidence);
    }
}
