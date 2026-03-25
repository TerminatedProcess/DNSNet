/// Source of a blocking decision
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlockSource {
    /// Domain was on a static blocklist
    Blocklist,
    /// Domain was flagged by the AI classifier
    Ai,
    /// Domain was not blocked
    None,
}

pub trait BlockLogger {
    fn log(&self, connection_name: String, allowed: bool);

    /// Extended log with AI classification metadata
    fn log_with_ai(
        &self,
        connection_name: String,
        allowed: bool,
        block_source: BlockSource,
        ai_confidence: f32,
    ) {
        // Default implementation falls back to basic log for backward compatibility
        self.log(connection_name, allowed);
    }
}
