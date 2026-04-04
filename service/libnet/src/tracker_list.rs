//! Known tracker domain matching.
//!
//! Embeds a curated list of tracking/analytics domains that are used for
//! surveillance, fingerprinting, and cross-app data collection. These are
//! legitimate-looking domains that bypass both static blocklists and DGA detection.

use std::collections::HashSet;

/// Result of a tracker check.
#[derive(Debug, Clone, PartialEq)]
pub struct TrackerResult {
    /// Whether the domain matched a known tracker.
    pub is_tracker: bool,
    /// Category of the tracker (e.g., "analytics", "advertising", "fingerprinting").
    pub category: &'static str,
    /// Human-readable name of the tracking service.
    pub service_name: &'static str,
}

impl TrackerResult {
    fn not_tracker() -> Self {
        TrackerResult {
            is_tracker: false,
            category: "",
            service_name: "",
        }
    }
}

/// Entry in the tracker database.
struct TrackerEntry {
    /// Domain or suffix to match (e.g., "demdex.net" matches "dpm.demdex.net").
    domain: &'static str,
    category: &'static str,
    service_name: &'static str,
}

/// Known tracker domain database.
///
/// Matches domains against a curated list using both exact match and
/// suffix match (so "dpm.demdex.net" matches the entry "demdex.net").
pub struct TrackerList {
    /// Set of exact/suffix domains for fast lookup.
    domains: HashSet<&'static str>,
    /// Full entries with metadata.
    entries: Vec<TrackerEntry>,
}

impl TrackerList {
    /// Create a new tracker list with the built-in database.
    pub fn new() -> Self {
        let entries = built_in_trackers();
        let domains: HashSet<&'static str> = entries.iter().map(|e| e.domain).collect();
        TrackerList { domains, entries }
    }

    /// Check if a domain is a known tracker.
    ///
    /// Performs suffix matching: "foo.bar.demdex.net" matches "demdex.net".
    pub fn check(&self, domain: &str) -> TrackerResult {
        let domain = domain.to_lowercase();
        let domain = domain.strip_suffix('.').unwrap_or(&domain);

        // Try exact match first, then progressively strip subdomains.
        let mut candidate = domain;
        loop {
            if self.domains.contains(candidate) {
                // Found a match — get the metadata.
                if let Some(entry) = self.entries.iter().find(|e| e.domain == candidate) {
                    return TrackerResult {
                        is_tracker: true,
                        category: entry.category,
                        service_name: entry.service_name,
                    };
                }
            }

            // Strip leftmost label.
            match candidate.find('.') {
                Some(pos) => candidate = &candidate[pos + 1..],
                None => break,
            }
        }

        TrackerResult::not_tracker()
    }
}

/// Built-in tracker database.
/// Sources: Disconnect.me, EasyPrivacy, DuckDuckGo Tracker Radar.
fn built_in_trackers() -> Vec<TrackerEntry> {
    vec![
        // -- Advertising --
        TrackerEntry { domain: "doubleclick.net", category: "advertising", service_name: "Google DoubleClick" },
        TrackerEntry { domain: "googlesyndication.com", category: "advertising", service_name: "Google Ads" },
        TrackerEntry { domain: "googleadservices.com", category: "advertising", service_name: "Google Ads" },
        TrackerEntry { domain: "google-analytics.com", category: "advertising", service_name: "Google Analytics" },
        TrackerEntry { domain: "googletagmanager.com", category: "advertising", service_name: "Google Tag Manager" },
        TrackerEntry { domain: "googlesyndication.com", category: "advertising", service_name: "Google Ads" },
        TrackerEntry { domain: "moatads.com", category: "advertising", service_name: "Moat (Oracle)" },
        TrackerEntry { domain: "serving-sys.com", category: "advertising", service_name: "Sizmek" },
        TrackerEntry { domain: "adnxs.com", category: "advertising", service_name: "AppNexus (Xandr)" },
        TrackerEntry { domain: "adsrvr.org", category: "advertising", service_name: "The Trade Desk" },
        TrackerEntry { domain: "rubiconproject.com", category: "advertising", service_name: "Rubicon Project" },
        TrackerEntry { domain: "pubmatic.com", category: "advertising", service_name: "PubMatic" },
        TrackerEntry { domain: "openx.net", category: "advertising", service_name: "OpenX" },
        TrackerEntry { domain: "casalemedia.com", category: "advertising", service_name: "Index Exchange" },
        TrackerEntry { domain: "criteo.com", category: "advertising", service_name: "Criteo" },
        TrackerEntry { domain: "criteo.net", category: "advertising", service_name: "Criteo" },
        TrackerEntry { domain: "taboola.com", category: "advertising", service_name: "Taboola" },
        TrackerEntry { domain: "outbrain.com", category: "advertising", service_name: "Outbrain" },
        TrackerEntry { domain: "smartadserver.com", category: "advertising", service_name: "Smart AdServer" },
        TrackerEntry { domain: "bidswitch.net", category: "advertising", service_name: "BidSwitch" },
        TrackerEntry { domain: "amazon-adsystem.com", category: "advertising", service_name: "Amazon Ads" },
        TrackerEntry { domain: "media.net", category: "advertising", service_name: "Media.net" },
        TrackerEntry { domain: "unity3d.com", category: "advertising", service_name: "Unity Ads" },
        TrackerEntry { domain: "applovin.com", category: "advertising", service_name: "AppLovin" },
        TrackerEntry { domain: "mopub.com", category: "advertising", service_name: "MoPub" },
        TrackerEntry { domain: "inmobi.com", category: "advertising", service_name: "InMobi" },
        TrackerEntry { domain: "admob.com", category: "advertising", service_name: "AdMob (Google)" },

        // -- Analytics / Telemetry --
        TrackerEntry { domain: "app-measurement.com", category: "analytics", service_name: "Firebase Analytics" },
        TrackerEntry { domain: "firebase-settings.crashlytics.com", category: "analytics", service_name: "Crashlytics" },
        TrackerEntry { domain: "settings.crashlytics.com", category: "analytics", service_name: "Crashlytics" },
        TrackerEntry { domain: "amplitude.com", category: "analytics", service_name: "Amplitude" },
        TrackerEntry { domain: "mixpanel.com", category: "analytics", service_name: "Mixpanel" },
        TrackerEntry { domain: "segment.io", category: "analytics", service_name: "Segment" },
        TrackerEntry { domain: "segment.com", category: "analytics", service_name: "Segment" },
        TrackerEntry { domain: "braze.com", category: "analytics", service_name: "Braze" },
        TrackerEntry { domain: "appboy.com", category: "analytics", service_name: "Braze (legacy)" },
        TrackerEntry { domain: "branch.io", category: "analytics", service_name: "Branch" },
        TrackerEntry { domain: "app.link", category: "analytics", service_name: "Branch Links" },
        TrackerEntry { domain: "adjust.com", category: "analytics", service_name: "Adjust" },
        TrackerEntry { domain: "appsflyer.com", category: "analytics", service_name: "AppsFlyer" },
        TrackerEntry { domain: "kochava.com", category: "analytics", service_name: "Kochava" },
        TrackerEntry { domain: "flurry.com", category: "analytics", service_name: "Flurry (Yahoo)" },
        TrackerEntry { domain: "newrelic.com", category: "analytics", service_name: "New Relic" },
        TrackerEntry { domain: "bugsnag.com", category: "analytics", service_name: "Bugsnag" },
        TrackerEntry { domain: "sentry.io", category: "analytics", service_name: "Sentry" },
        TrackerEntry { domain: "instabug.com", category: "analytics", service_name: "Instabug" },

        // -- Fingerprinting / Cross-device tracking --
        TrackerEntry { domain: "demdex.net", category: "fingerprinting", service_name: "Adobe Audience Manager" },
        TrackerEntry { domain: "omtrdc.net", category: "fingerprinting", service_name: "Adobe Analytics" },
        TrackerEntry { domain: "2o7.net", category: "fingerprinting", service_name: "Adobe Analytics (legacy)" },
        TrackerEntry { domain: "everesttech.net", category: "fingerprinting", service_name: "Adobe Advertising" },
        TrackerEntry { domain: "scorecardresearch.com", category: "fingerprinting", service_name: "comScore" },
        TrackerEntry { domain: "quantserve.com", category: "fingerprinting", service_name: "Quantcast" },
        TrackerEntry { domain: "rlcdn.com", category: "fingerprinting", service_name: "LiveRamp" },
        TrackerEntry { domain: "tapad.com", category: "fingerprinting", service_name: "Tapad (Experian)" },
        TrackerEntry { domain: "agkn.com", category: "fingerprinting", service_name: "Neustar" },
        TrackerEntry { domain: "krxd.net", category: "fingerprinting", service_name: "Salesforce DMP" },
        TrackerEntry { domain: "bluekai.com", category: "fingerprinting", service_name: "Oracle BlueKai" },
        TrackerEntry { domain: "exelator.com", category: "fingerprinting", service_name: "Nielsen eXelate" },
        TrackerEntry { domain: "adsymptotic.com", category: "fingerprinting", service_name: "Conversant" },

        // -- Social media trackers (embedded SDKs) --
        TrackerEntry { domain: "graph.facebook.com", category: "social_tracking", service_name: "Facebook SDK" },
        TrackerEntry { domain: "web.facebook.com", category: "social_tracking", service_name: "Facebook SDK" },
        TrackerEntry { domain: "connect.facebook.net", category: "social_tracking", service_name: "Facebook Connect" },
        TrackerEntry { domain: "pixel.facebook.com", category: "social_tracking", service_name: "Facebook Pixel" },
        TrackerEntry { domain: "analytics.twitter.com", category: "social_tracking", service_name: "Twitter Analytics" },
        TrackerEntry { domain: "t.co", category: "social_tracking", service_name: "Twitter Link Tracking" },
        TrackerEntry { domain: "ads-api.twitter.com", category: "social_tracking", service_name: "Twitter Ads" },
        TrackerEntry { domain: "snap.licdn.com", category: "social_tracking", service_name: "LinkedIn Tracking" },
        TrackerEntry { domain: "px.ads.linkedin.com", category: "social_tracking", service_name: "LinkedIn Ads Pixel" },
        TrackerEntry { domain: "analytics.tiktok.com", category: "social_tracking", service_name: "TikTok Analytics" },
        TrackerEntry { domain: "log.byteoversea.com", category: "social_tracking", service_name: "TikTok/ByteDance Logging" },
        TrackerEntry { domain: "log16-applog.tiktokv.com", category: "social_tracking", service_name: "TikTok App Logging" },

        // -- Data brokers / Surveillance --
        TrackerEntry { domain: "dotomi.com", category: "data_broker", service_name: "Conversant (ValueClick)" },
        TrackerEntry { domain: "contextweb.com", category: "data_broker", service_name: "PulsePoint" },
        TrackerEntry { domain: "adform.net", category: "data_broker", service_name: "Adform" },
        TrackerEntry { domain: "mathtag.com", category: "data_broker", service_name: "MediaMath" },
        TrackerEntry { domain: "eyeota.net", category: "data_broker", service_name: "Eyeota" },
        TrackerEntry { domain: "liadm.com", category: "data_broker", service_name: "LiveIntent" },
        TrackerEntry { domain: "intentiq.com", category: "data_broker", service_name: "Intent IQ" },
        TrackerEntry { domain: "id5-sync.com", category: "data_broker", service_name: "ID5" },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let list = TrackerList::new();
        let result = list.check("app-measurement.com");
        assert!(result.is_tracker);
        assert_eq!(result.category, "analytics");
        assert_eq!(result.service_name, "Firebase Analytics");
    }

    #[test]
    fn test_subdomain_match() {
        let list = TrackerList::new();
        let result = list.check("dpm.demdex.net");
        assert!(result.is_tracker);
        assert_eq!(result.category, "fingerprinting");
        assert_eq!(result.service_name, "Adobe Audience Manager");
    }

    #[test]
    fn test_deep_subdomain_match() {
        let list = TrackerList::new();
        let result = list.check("foo.bar.baz.doubleclick.net");
        assert!(result.is_tracker);
        assert_eq!(result.service_name, "Google DoubleClick");
    }

    #[test]
    fn test_not_tracker() {
        let list = TrackerList::new();
        let result = list.check("google.com");
        assert!(!result.is_tracker);
        assert_eq!(result.category, "");
    }

    #[test]
    fn test_not_tracker_similar_name() {
        let list = TrackerList::new();
        // "demdex.com" is not in the list — only "demdex.net" is.
        let result = list.check("demdex.com");
        assert!(!result.is_tracker);
    }

    #[test]
    fn test_case_insensitive() {
        let list = TrackerList::new();
        let result = list.check("DPM.Demdex.NET");
        assert!(result.is_tracker);
    }

    #[test]
    fn test_trailing_dot() {
        let list = TrackerList::new();
        let result = list.check("app-measurement.com.");
        assert!(result.is_tracker);
    }

    #[test]
    fn test_facebook_sdk_tracker() {
        let list = TrackerList::new();
        let result = list.check("graph.facebook.com");
        assert!(result.is_tracker);
        assert_eq!(result.category, "social_tracking");
        assert_eq!(result.service_name, "Facebook SDK");
    }

    #[test]
    fn test_tiktok_tracker() {
        let list = TrackerList::new();
        let result = list.check("log.byteoversea.com");
        assert!(result.is_tracker);
        assert_eq!(result.service_name, "TikTok/ByteDance Logging");
    }

    #[test]
    fn test_empty_domain() {
        let list = TrackerList::new();
        let result = list.check("");
        assert!(!result.is_tracker);
    }
}
