package dev.clombardo.dnsnet.service.ai

import com.llamatik.library.platform.LlamaBridge
import dev.clombardo.dnsnet.common.logError
import dev.clombardo.dnsnet.common.logInfo

/**
 * On-device LLM provider using Gemma 4 E4B via Llamatik.
 * Runs entirely on-device — no cloud, no API keys.
 */
class GemmaProvider(private val modelManager: ModelManager) : LlmProvider {

    private val fallback = HeuristicProvider()
    private var modelLoaded = false

    override suspend fun chat(messages: List<ChatMessage>, context: AiContext): String {
        if (!modelManager.isModelReady()) {
            return "AI model not downloaded yet. Tap the download button to get started.\n\n" +
                "In the meantime, here's what I can tell you:\n\n" +
                fallback.chat(messages, context)
        }

        val modelPath = modelManager.modelPath()
            ?: return fallback.chat(messages, context)

        try {
            // Load model if not already loaded
            if (!modelLoaded) {
                logInfo("GemmaProvider: Loading model from $modelPath")
                val loaded = LlamaBridge.initGenerateModel(modelPath)
                if (!loaded) {
                    logError("GemmaProvider: Failed to load model")
                    return "Failed to load AI model. The file may be corrupted. Try deleting and re-downloading.\n\n" +
                        fallback.chat(messages, context)
                }
                // Set inference params: temperature, topK, topP, maxTokens, repeatPenalty
                LlamaBridge.updateGenerateParams(0.7f, 40, 0.9f, 512, 1.1f)
                modelLoaded = true
                logInfo("GemmaProvider: Model loaded successfully")
            }

            // Build prompts
            val systemPrompt = buildSystemPrompt(context)
            val conversationContext = buildConversationContext(messages)
            val lastUserMessage = messages.lastOrNull { it.role == "user" }?.content ?: ""

            // Generate response using context-aware API
            logInfo("GemmaProvider: Generating response for: ${lastUserMessage.take(50)}...")
            val response = LlamaBridge.generateWithContext(
                systemPrompt,
                conversationContext,
                lastUserMessage,
            )

            return if (response.isNullOrBlank()) {
                logError("GemmaProvider: Empty response from model")
                fallback.chat(messages, context)
            } else {
                response.trim()
            }
        } catch (e: Exception) {
            logError("GemmaProvider: Inference failed", e)
            modelLoaded = false
            return "AI model error: ${e.message}\n\nFalling back to built-in help:\n\n" +
                fallback.chat(messages, context)
        }
    }

    private fun buildConversationContext(messages: List<ChatMessage>): String {
        // Build prior conversation (excluding the last user message which goes separately)
        val prior = messages.dropLast(1)
        if (prior.isEmpty()) return ""

        return prior.joinToString("\n") { msg ->
            when (msg.role) {
                "user" -> "User: ${msg.content}"
                "assistant" -> "Assistant: ${msg.content}"
                else -> ""
            }
        }
    }

    private fun buildSystemPrompt(context: AiContext): String {
        return """You are the DNSAI AI assistant built into a DNS threat detection Android app.
You help users understand their DNS traffic, blocked domains, trackers, and security settings.
You can analyze data and give actionable advice.

The user is viewing the ${context.screenName} screen.
${context.screenDescription}

Current live data:
${context.liveData}

When you think a domain should be allowed by the user, include [ALLOW:domain.com] in your response.
When you think a domain should be blocked, include [BLOCK:domain.com] in your response.
These will become tappable action buttons for the user.

Be concise, direct, and helpful. Explain DNS concepts simply when asked.
If asked about blocking ads in social media apps like Facebook or TikTok, explain that DNS blocking can block third-party ad networks and trackers but cannot block first-party in-feed ads that come from the same domain as regular content."""
    }

    override fun isAvailable(): Boolean = modelManager.isModelReady()

    override fun name(): String = "Gemma 4 E4B (On-Device)"
}
