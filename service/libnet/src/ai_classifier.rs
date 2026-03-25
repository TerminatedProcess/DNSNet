//! DNSAI — On-device DGA classifier
//!
//! Evaluates DNS domain names against a pre-trained XGBoost model (binary format)
//! to detect Domain Generation Algorithm (DGA) domains.
//!
//! Model: 300 decision trees, 26 features, ~935KB binary

use log::info;

/// A single node in a decision tree
#[derive(Clone)]
struct TreeNode {
    split_index: u16,
    split_condition: f32,
    left_child: i32,
    right_child: i32,
    is_leaf: bool,
    weight: f32,
}

/// A single decision tree
struct Tree {
    nodes: Vec<TreeNode>,
}

impl Tree {
    /// Evaluate this tree with the given features
    fn predict(&self, features: &[f32]) -> f32 {
        let mut node_idx: usize = 0;
        loop {
            let node = &self.nodes[node_idx];
            if node.is_leaf {
                return node.weight;
            }
            let feature_val = features.get(node.split_index as usize).copied().unwrap_or(0.0);
            node_idx = if feature_val < node.split_condition {
                node.left_child as usize
            } else {
                node.right_child as usize
            };
        }
    }
}

/// Classification result from the AI classifier
#[derive(Debug, Clone)]
pub struct AiClassification {
    /// Probability that the domain is DGA (0.0 = definitely legit, 1.0 = definitely DGA)
    pub dga_probability: f32,
    /// Whether we classify this as DGA based on the threshold
    pub is_dga: bool,
}

/// The AI DGA classifier
pub struct AiClassifier {
    trees: Vec<Tree>,
    base_score: f32,
    threshold: f32,
}

// Common English bigrams for feature extraction
const ENGLISH_BIGRAMS: &[&str] = &[
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
    "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
    "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
    "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
    "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
];

const ENGLISH_TRIGRAMS: &[&str] = &[
    "the", "and", "ing", "her", "hat", "his", "tha", "ere", "for", "ent",
    "ion", "ter", "was", "you", "ith", "ver", "all", "wit", "thi", "tio",
    "con", "are", "ess", "not", "com", "man", "our", "pro", "pre", "ect",
    "rea", "ble", "str", "ate", "ous", "ove", "ine", "ame",
];

const HIGH_RISK_TLDS: &[&str] = &[
    "xyz", "top", "buzz", "tk", "ml", "ga", "cf", "gq", "pw",
    "cc", "ws", "click", "link", "info", "win", "bid", "stream",
    "racing", "download", "review", "country", "science", "party",
    "date", "faith", "cricket", "accountant", "loan",
];

const MEDIUM_RISK_TLDS: &[&str] = &[
    "net", "org", "biz", "online", "site", "tech", "space",
    "website", "store", "pro", "club", "life", "world",
];

impl AiClassifier {
    /// Load the classifier from a binary model file
    pub fn from_bytes(data: &[u8], threshold: f32) -> Result<Self, String> {
        if data.len() < 16 {
            return Err("Model data too short".into());
        }

        // Check magic
        if &data[0..4] != b"XGBR" {
            return Err("Invalid model magic".into());
        }

        let mut offset = 4;
        let num_trees = read_u32(data, &mut offset);
        let num_features = read_u32(data, &mut offset);
        let base_score = read_f32(data, &mut offset);

        info!(
            "Loading AI classifier: {} trees, {} features, base_score={}",
            num_trees, num_features, base_score
        );

        let mut trees = Vec::with_capacity(num_trees as usize);
        for _ in 0..num_trees {
            let num_nodes = read_u32(data, &mut offset);
            let mut nodes = Vec::with_capacity(num_nodes as usize);
            for _ in 0..num_nodes {
                let split_index = read_u16(data, &mut offset);
                let split_condition = read_f32(data, &mut offset);
                let left_child = read_i32(data, &mut offset);
                let right_child = read_i32(data, &mut offset);
                let is_leaf = data[offset] != 0;
                offset += 1;
                // Padding byte from struct packing
                offset += 3;
                let weight = read_f32(data, &mut offset);
                nodes.push(TreeNode {
                    split_index,
                    split_condition,
                    left_child,
                    right_child,
                    is_leaf,
                    weight,
                });
            }
            trees.push(Tree { nodes });
        }

        info!("AI classifier loaded successfully");
        Ok(AiClassifier {
            trees,
            base_score,
            threshold,
        })
    }

    /// Classify a domain name. Returns None if classification fails.
    pub fn classify(&self, domain: &str) -> Option<AiClassification> {
        let features = extract_features(domain);
        let raw_score: f32 = self.trees.iter().map(|t| t.predict(&features)).sum::<f32>() + self.base_score;
        let probability = sigmoid(raw_score);

        Some(AiClassification {
            dga_probability: probability,
            is_dga: probability > self.threshold,
        })
    }

    /// Update the classification threshold
    pub fn set_threshold(&mut self, threshold: f32) {
        self.threshold = threshold;
    }
}

/// Sigmoid function for converting XGBoost raw score to probability
fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// Extract 26 features from a domain name (must match training pipeline order)
fn extract_features(domain: &str) -> Vec<f32> {
    let domain = domain.to_lowercase();
    let domain = domain.trim_end_matches('.');

    let parts: Vec<&str> = domain.split('.').collect();
    let sld = if parts.len() >= 2 { parts[0] } else { &domain };
    let tld = if parts.len() >= 2 { parts[parts.len() - 1] } else { "" };
    let subdomain_parts: Vec<&str> = if parts.len() > 2 { parts[..parts.len() - 2].to_vec() } else { vec![] };

    let domain_len = domain.len() as f32;
    let sld_len = sld.len() as f32;
    let sld_bytes = sld.as_bytes();

    // Shannon entropy
    let entropy = shannon_entropy(sld);
    let entropy_per_char = entropy / sld_len.max(1.0);

    // Character composition
    let digit_count = sld_bytes.iter().filter(|b| b.is_ascii_digit()).count() as f32;
    let digit_ratio = digit_count / sld_len.max(1.0);
    let hyphen_count = sld_bytes.iter().filter(|&&b| b == b'-').count() as f32;
    let vowel_count = sld_bytes.iter().filter(|b| b"aeiou".contains(b)).count() as f32;
    let consonant_count = sld_bytes.iter().filter(|b| b"bcdfghjklmnpqrstvwxyz".contains(b)).count() as f32;
    let consonant_vowel_ratio = consonant_count / vowel_count.max(1.0);

    // Bigram features
    let bigrams: Vec<&str> = (0..sld.len().saturating_sub(1))
        .filter_map(|i| sld.get(i..i + 2))
        .collect();
    let english_bigram_count = bigrams.iter().filter(|bg| ENGLISH_BIGRAMS.contains(bg)).count() as f32;
    let english_bigram_ratio = english_bigram_count / (bigrams.len() as f32).max(1.0);

    // Trigram features
    let trigrams: Vec<&str> = (0..sld.len().saturating_sub(2))
        .filter_map(|i| sld.get(i..i + 3))
        .collect();
    let english_trigram_count = trigrams.iter().filter(|tg| ENGLISH_TRIGRAMS.contains(tg)).count() as f32;
    let english_trigram_ratio = english_trigram_count / (trigrams.len() as f32).max(1.0);

    // Unique character ratio
    let mut seen = [false; 256];
    let unique_chars = sld_bytes.iter().filter(|&&b| {
        let idx = b as usize;
        if seen[idx] { false } else { seen[idx] = true; true }
    }).count() as f32;
    let unique_char_ratio = unique_chars / sld_len.max(1.0);

    // Subdomain features
    let subdomain_count = subdomain_parts.len() as f32;
    let max_subdomain_len = subdomain_parts.iter().map(|s| s.len()).max().unwrap_or(0) as f32;
    let total_subdomain_len = subdomain_parts.iter().map(|s| s.len()).sum::<usize>() as f32;

    // TLD risk
    let tld_risk = if HIGH_RISK_TLDS.contains(&tld) {
        2.0
    } else if MEDIUM_RISK_TLDS.contains(&tld) {
        1.0
    } else {
        0.0
    };

    // Longest consonant sequence
    let longest_consonant_seq = longest_sequence(sld_bytes, b"bcdfghjklmnpqrstvwxyz") as f32;
    let longest_vowel_seq = longest_sequence(sld_bytes, b"aeiou") as f32;

    // Alternation ratio (vowel-consonant switches)
    let alternation_count = sld_bytes.windows(2).filter(|w| {
        let a_vowel = b"aeiou".contains(&w[0]);
        let b_vowel = b"aeiou".contains(&w[1]);
        a_vowel != b_vowel && w[0].is_ascii_alphabetic() && w[1].is_ascii_alphabetic()
    }).count() as f32;
    let alternation_ratio = alternation_count / (sld_len - 1.0).max(1.0);

    // Numeric sequences
    let numeric_sequences = count_numeric_sequences(sld) as f32;

    // Character class transition ratio
    let char_class_transitions = sld_bytes.windows(2).filter(|w| {
        char_class(w[0]) != char_class(w[1])
    }).count() as f32;
    let char_class_transition_ratio = char_class_transitions / (sld_len - 1.0).max(1.0);

    // Repeated character ratio
    let mut char_counts = [0u32; 256];
    for &b in sld_bytes { char_counts[b as usize] += 1; }
    let max_repeated = *char_counts.iter().max().unwrap_or(&0) as f32;
    let repeated_char_ratio = max_repeated / sld_len.max(1.0);

    // Hex-like ratio
    let hex_count = sld_bytes.iter().filter(|b| b"0123456789abcdef".contains(b)).count() as f32;
    let hex_ratio = hex_count / sld_len.max(1.0);
    let is_hex_like = if hex_ratio > 0.9 && sld_len > 6.0 { 1.0 } else { 0.0 };

    // Dot count
    let dot_count = domain.matches('.').count() as f32;

    // Return features in exact training order
    vec![
        domain_len,                    // 0: domain_len
        sld_len,                       // 1: sld_len
        entropy,                       // 2: entropy
        entropy_per_char,              // 3: entropy_per_char
        digit_count,                   // 4: digit_count
        digit_ratio,                   // 5: digit_ratio
        hyphen_count,                  // 6: hyphen_count
        vowel_count,                   // 7: vowel_count
        consonant_count,               // 8: consonant_count
        consonant_vowel_ratio,         // 9: consonant_vowel_ratio
        english_bigram_ratio,          // 10: english_bigram_ratio
        english_trigram_ratio,         // 11: english_trigram_ratio
        unique_char_ratio,             // 12: unique_char_ratio
        subdomain_count,               // 13: subdomain_count
        max_subdomain_len,             // 14: max_subdomain_len
        total_subdomain_len,           // 15: total_subdomain_len
        tld_risk,                      // 16: tld_risk
        longest_consonant_seq,         // 17: longest_consonant_seq
        longest_vowel_seq,             // 18: longest_vowel_seq
        alternation_ratio,             // 19: alternation_ratio
        numeric_sequences,             // 20: numeric_sequences
        char_class_transition_ratio,   // 21: char_class_transition_ratio
        repeated_char_ratio,           // 22: repeated_char_ratio
        hex_ratio,                     // 23: hex_ratio
        is_hex_like,                   // 24: is_hex_like
        dot_count,                     // 25: dot_count
    ]
}

fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let len = s.len() as f32;
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    -counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            p * p.log2()
        })
        .sum::<f32>()
}

fn longest_sequence(bytes: &[u8], char_set: &[u8]) -> usize {
    let mut max_len = 0;
    let mut current = 0;
    for &b in bytes {
        if char_set.contains(&b) {
            current += 1;
            if current > max_len {
                max_len = current;
            }
        } else {
            current = 0;
        }
    }
    max_len
}

fn count_numeric_sequences(s: &str) -> usize {
    let mut count = 0;
    let mut in_digit = false;
    for b in s.bytes() {
        if b.is_ascii_digit() {
            if !in_digit {
                count += 1;
                in_digit = true;
            }
        } else {
            in_digit = false;
        }
    }
    count
}

fn char_class(b: u8) -> u8 {
    if b.is_ascii_alphabetic() { 0 }
    else if b.is_ascii_digit() { 1 }
    else { 2 }
}

fn read_u32(data: &[u8], offset: &mut usize) -> u32 {
    let val = u32::from_le_bytes([data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]]);
    *offset += 4;
    val
}

fn read_u16(data: &[u8], offset: &mut usize) -> u16 {
    let val = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
    *offset += 2;
    val
}

fn read_i32(data: &[u8], offset: &mut usize) -> i32 {
    let val = i32::from_le_bytes([data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]]);
    *offset += 4;
    val
}

fn read_f32(data: &[u8], offset: &mut usize) -> f32 {
    let val = f32::from_le_bytes([data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]]);
    *offset += 4;
    val
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_extraction() {
        let features = extract_features("google.com");
        assert_eq!(features.len(), 26);
        assert!(features[2] > 0.0); // entropy should be positive
    }

    #[test]
    fn test_shannon_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert!(shannon_entropy("aaaa") < shannon_entropy("abcd"));
        assert!(shannon_entropy("xk4mz9q7p") > shannon_entropy("google"));
    }

    #[test]
    fn test_longest_sequence() {
        assert_eq!(longest_sequence(b"aeiou", b"aeiou"), 5);
        assert_eq!(longest_sequence(b"bcdfg", b"aeiou"), 0);
        assert_eq!(longest_sequence(b"abcde", b"bcd"), 3);
    }
}
