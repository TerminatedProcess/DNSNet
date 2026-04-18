package dev.clombardo.dnsnet.service.ai

/**
 * Common interface for all LLM providers used by the troubleshooter.
 */
interface LlmProvider {
    suspend fun chat(messages: List<ChatMessage>, context: TroubleshootContext): String
    fun isAvailable(): Boolean
    fun name(): String
}

data class ChatMessage(val role: String, val content: String)

data class TroubleshootContext(
    val appName: String,
    val recentBlocks: List<BlockedDomain>,
    val recentAllowed: List<String>,
)

data class BlockedDomain(
    val domain: String,
    val source: String,
    val count: Int,
    val confidence: Float,
)
