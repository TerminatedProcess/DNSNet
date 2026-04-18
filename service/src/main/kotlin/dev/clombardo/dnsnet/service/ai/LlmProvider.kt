package dev.clombardo.dnsnet.service.ai

/**
 * Common interface for all LLM providers used by the AI assistant.
 */
interface LlmProvider {
    suspend fun chat(messages: List<ChatMessage>, context: AiContext): String
    fun isAvailable(): Boolean
    fun name(): String
}

data class ChatMessage(
    val role: String,
    val content: String,
    val imageData: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ChatMessage) return false
        return role == other.role && content == other.content &&
            imageData.contentEquals(other.imageData)
    }

    override fun hashCode(): Int {
        var result = role.hashCode()
        result = 31 * result + content.hashCode()
        result = 31 * result + (imageData?.contentHashCode() ?: 0)
        return result
    }
}

data class AiContext(
    val screenName: String,
    val screenDescription: String,
    val liveData: String,
    val availableActions: List<String> = emptyList(),
    // Backward compat for HeuristicProvider troubleshooting
    val appName: String = "",
    val recentBlocks: List<BlockedDomain> = emptyList(),
    val recentAllowed: List<String> = emptyList(),
)

data class BlockedDomain(
    val domain: String,
    val source: String,
    val count: Int,
    val confidence: Float,
)
