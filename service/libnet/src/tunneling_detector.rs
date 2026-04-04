/* Copyright (C) 2025 Charles Lombardo <clombardo169@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/// DNS tunneling detector.
///
/// DNS tunneling encodes arbitrary data inside subdomain labels. This module
/// uses lightweight heuristics (no ML model) to flag queries that look like
/// encoded payloads rather than legitimate hostnames.

/// Result of a tunneling check on a single domain.
#[derive(Debug, Clone)]
pub struct TunnelingResult {
    pub is_tunneling: bool,
    /// Combined score in 0.0-1.0, where higher means more likely tunneling.
    pub score: f32,
    /// Total character length of the subdomain portion (dots excluded).
    pub subdomain_length: usize,
    /// Shannon entropy (bits) of the subdomain portion.
    pub entropy: f32,
}

/// Stateless DNS tunneling detector.
pub struct TunnelingDetector {
    threshold: f32,
}

// ---------------------------------------------------------------------------
// Heuristic weights — must sum to 1.0
// ---------------------------------------------------------------------------
const W_LENGTH: f32 = 0.25;
const W_ENTROPY: f32 = 0.20;
const W_HEX_BASE64: f32 = 0.25;
const W_LABEL_COUNT: f32 = 0.10;
const W_LONGEST_LABEL: f32 = 0.20;

impl TunnelingDetector {
    /// Create a new detector with the given combined-score threshold (0.0-1.0).
    pub fn new(threshold: f32) -> Self {
        Self {
            threshold: threshold.clamp(0.0, 1.0),
        }
    }

    /// Analyse a single domain name and return a tunneling verdict.
    ///
    /// The check is entirely stateless — no caching, no cross-query tracking.
    pub fn check(&self, domain: &str) -> TunnelingResult {
        let domain = domain.trim().trim_end_matches('.');

        let subdomain = match extract_subdomain(domain) {
            Some(s) if !s.is_empty() => s,
            _ => {
                return TunnelingResult {
                    is_tunneling: false,
                    score: 0.0,
                    subdomain_length: 0,
                    entropy: 0.0,
                };
            }
        };

        // Characters in the subdomain excluding dots.
        let subdomain_chars: String = subdomain.chars().filter(|&c| c != '.').collect();
        let subdomain_length = subdomain_chars.len();

        let entropy = shannon_entropy(&subdomain_chars);

        // --- individual signal scores (each 0.0-1.0) ---

        // 1. Subdomain length: ramp linearly from 0 at 15 chars to 1 at 60 chars.
        let length_score = ((subdomain_length as f32 - 15.0) / 45.0).clamp(0.0, 1.0);

        // 2. Shannon entropy: ramp from 0 at 2.5 bits to 1 at 4.5 bits.
        let entropy_score = ((entropy - 2.5) / 2.0).clamp(0.0, 1.0);

        // 3. Hex/base64 ratio.
        let hex_b64_score = hex_base64_score(&subdomain_chars);

        // 4. Label count: ramp from 0 at 2 labels to 1 at 7 labels.
        let label_count = subdomain.split('.').count();
        let label_score = ((label_count as f32 - 2.0) / 5.0).clamp(0.0, 1.0);

        // 5. Longest label: ramp from 0 at 12 chars to 1 at 45 chars.
        let longest = subdomain.split('.').map(|l| l.len()).max().unwrap_or(0);
        let longest_score = ((longest as f32 - 12.0) / 33.0).clamp(0.0, 1.0);

        let score = (W_LENGTH * length_score
            + W_ENTROPY * entropy_score
            + W_HEX_BASE64 * hex_b64_score
            + W_LABEL_COUNT * label_score
            + W_LONGEST_LABEL * longest_score)
            .clamp(0.0, 1.0);

        TunnelingResult {
            is_tunneling: score >= self.threshold,
            score,
            subdomain_length,
            entropy,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the subdomain portion of a domain name.
///
/// Simplification: the "registered domain" is the last two labels (e.g.
/// `evil.com`).  If the second-to-last label is <= 2 chars (like `co` in
/// `co.uk`) we treat the last three labels as the registered domain.
///
/// Returns `None` if the domain has no subdomain (e.g. `google.com`).
fn extract_subdomain(domain: &str) -> Option<String> {
    let labels: Vec<&str> = domain.split('.').collect();

    let reg_labels = if labels.len() >= 3 {
        let second_to_last = labels[labels.len() - 2];
        if second_to_last.len() <= 2 {
            3 // e.g. foo.co.uk
        } else {
            2 // e.g. foo.evil.com
        }
    } else {
        // Two labels or fewer — no subdomain at all.
        return None;
    };

    if labels.len() <= reg_labels {
        return None;
    }

    let subdomain_labels = &labels[..labels.len() - reg_labels];
    Some(subdomain_labels.join("."))
}

/// Shannon entropy (bits) of a byte string. Same algorithm as
/// `ai_classifier::shannon_entropy`.
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let len = s.len() as f32;
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            p * p.log2()
        })
        .sum::<f32>()
}

/// Score (0.0-1.0) indicating how much the string looks like hex or base64
/// encoded data rather than normal words.
fn hex_base64_score(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f32;

    // Count hex-only chars (0-9, a-f, A-F).
    let hex_count = s
        .bytes()
        .filter(|b| b.is_ascii_hexdigit())
        .count() as f32;
    let hex_ratio = hex_count / len;

    // Digit density — tunneling payloads tend to have many digits mixed in.
    let digit_count = s.bytes().filter(|b| b.is_ascii_digit()).count() as f32;
    let digit_ratio = digit_count / len;

    // Vowel scarcity — real words have vowels; encoded data usually doesn't.
    let vowel_count = s
        .bytes()
        .filter(|&b| matches!(b, b'a' | b'e' | b'i' | b'o' | b'u' | b'A' | b'E' | b'I' | b'O' | b'U'))
        .count() as f32;
    let vowel_ratio = vowel_count / len;

    // Uppercase mixing — base64 uses mixed case, normal subdomains rarely do.
    let upper_count = s.bytes().filter(|b| b.is_ascii_uppercase()).count() as f32;
    let has_mixed_case = upper_count > 0.0 && upper_count < len;

    // Combine signals. Pure hex (all hex chars, many digits, few vowels)
    // should score high. Base64 (mixed case, alphanumeric) should also score
    // high.
    let case_bonus: f32 = if has_mixed_case { 0.15 } else { 0.0 };

    let raw = if hex_ratio > 0.95 && digit_ratio > 0.2 {
        // Looks like a pure hex-encoded string.
        0.85
    } else {
        0.30 * hex_ratio
            + 0.25 * digit_ratio
            + 0.25 * (1.0 - vowel_ratio)
            + case_bonus
    };

    // Normal subdomains ("www", "mail", "cdn01") score roughly 0.2-0.4.
    // Encoded payloads score 0.6+. Rescale into 0-1.
    ((raw - 0.25) / 0.55).clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> TunnelingDetector {
        TunnelingDetector::new(0.5)
    }

    // ---- normal domains ----

    #[test]
    fn test_bare_domain() {
        let r = detector().check("google.com");
        assert!(!r.is_tunneling);
        assert_eq!(r.subdomain_length, 0);
        assert!(r.score < 0.1, "score {} too high for bare domain", r.score);
    }

    #[test]
    fn test_simple_subdomain() {
        let r = detector().check("www.google.com");
        assert!(!r.is_tunneling);
        assert!(r.score < 0.15, "score {} too high for www", r.score);
    }

    #[test]
    fn test_mail_subdomain() {
        let r = detector().check("mail.google.com");
        assert!(!r.is_tunneling);
        assert!(r.score < 0.15, "score {} too high for mail", r.score);
    }

    #[test]
    fn test_multi_label_normal() {
        let r = detector().check("a.b.cdn.example.com");
        assert!(!r.is_tunneling);
        assert!(r.score < 0.3, "score {} too high for short multi-label", r.score);
    }

    // ---- clear tunneling ----

    #[test]
    fn test_long_base64_subdomain() {
        let domain = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.evil.com";
        let r = detector().check(domain);
        assert!(r.is_tunneling, "should detect tunneling, score={}", r.score);
        assert!(r.score >= 0.5);
        assert!(r.entropy > 3.0);
    }

    #[test]
    fn test_hex_encoded_subdomain() {
        let domain = "68656c6c6f776f726c6468656c6c6f776f726c64.evil.com";
        let r = detector().check(domain);
        assert!(r.is_tunneling, "should detect hex tunneling, score={}", r.score);
        assert!(r.score >= 0.5);
    }

    #[test]
    fn test_multi_label_tunneling() {
        let domain = "a1b2c3d4e5.f6g7h8i9j0.k1l2m3n4o5.p6q7r8s9t0.evil.com";
        let r = detector().check(domain);
        assert!(r.is_tunneling, "should detect multi-label tunneling, score={}", r.score);
    }

    #[test]
    fn test_very_long_subdomain() {
        // 80+ random chars
        let domain = "xk4mz9q7pw2jf8bn3y6tr1cs5dg0hvalexk4mz9q7pw2jf8bn3y6tr1cs5dg0hvale.evil.com";
        let r = detector().check(domain);
        assert!(r.is_tunneling, "should detect very long subdomain, score={}", r.score);
        assert!(r.subdomain_length > 50);
    }

    // ---- edge cases ----

    #[test]
    fn test_single_label() {
        let r = detector().check("localhost");
        assert!(!r.is_tunneling);
        assert_eq!(r.subdomain_length, 0);
    }

    #[test]
    fn test_empty_string() {
        let r = detector().check("");
        assert!(!r.is_tunneling);
        assert_eq!(r.subdomain_length, 0);
    }

    #[test]
    fn test_trailing_dot() {
        let r = detector().check("www.google.com.");
        assert!(!r.is_tunneling);
        assert!(r.score < 0.15);
    }

    #[test]
    fn test_co_uk_domain() {
        // co.uk — second-to-last label is 2 chars, so registered domain = "bbc.co.uk"
        let r = detector().check("www.bbc.co.uk");
        assert!(!r.is_tunneling);
        assert!(r.score < 0.15, "score {} too high for www.bbc.co.uk", r.score);
    }

    #[test]
    fn test_co_uk_tunneling() {
        let domain = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.bbc.co.uk";
        let r = detector().check(domain);
        assert!(r.is_tunneling, "should detect tunneling under co.uk, score={}", r.score);
    }

    // ---- helper tests ----

    #[test]
    fn test_extract_subdomain_simple() {
        assert_eq!(extract_subdomain("www.google.com"), Some("www".to_string()));
    }

    #[test]
    fn test_extract_subdomain_multi() {
        assert_eq!(
            extract_subdomain("a.b.c.example.com"),
            Some("a.b.c".to_string())
        );
    }

    #[test]
    fn test_extract_subdomain_co_uk() {
        assert_eq!(extract_subdomain("www.bbc.co.uk"), Some("www".to_string()));
    }

    #[test]
    fn test_extract_subdomain_bare() {
        assert_eq!(extract_subdomain("google.com"), None);
    }

    #[test]
    fn test_extract_subdomain_bare_co_uk() {
        assert_eq!(extract_subdomain("bbc.co.uk"), None);
    }

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_shannon_entropy_ordering() {
        assert!(shannon_entropy("aaaa") < shannon_entropy("abcd"));
        assert!(shannon_entropy("xk4mz9q7p") > shannon_entropy("www"));
    }
}
