/// Source of a blocking or flagging decision
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlockSource {
    /// Domain was on a static blocklist
    Blocklist,
    /// Domain was flagged by the AI DGA classifier
    Ai,
    /// Domain was flagged as DNS tunneling
    Tunneling,
    /// Domain matched a known tracker
    Tracker,
    /// Domain is beaconing (high-frequency queries)
    Beaconing,
    /// Domain was not blocked or flagged
    None,
}

pub trait BlockLogger {
    fn log(&self, connection_name: String, allowed: bool);

    /// Extended log with AI classification metadata
    fn log_with_ai(
        &self,
        connection_name: String,
        allowed: bool,
        _block_source: BlockSource,
        _ai_confidence: f32,
    ) {
        // Default implementation falls back to basic log for backward compatibility
        self.log(connection_name, allowed);
    }
}
