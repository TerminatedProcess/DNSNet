package dev.clombardo.dnsnet.service.ai

import dev.clombardo.dnsnet.common.logError
import dev.clombardo.dnsnet.common.logInfo

/**
 * On-device LLM provider using Gemma 4 E4B via Llamatik.
 *
 * TODO: Integrate Llamatik library once dependency resolves.
 * Currently falls back to HeuristicProvider with a note about model status.
 */
class GemmaProvider(private val modelManager: ModelManager) : LlmProvider {

    private val fallback = HeuristicProvider()

    // TODO: Replace with Llamatik model instance
    // private var llamaModel: LlamaBridge? = null

    override suspend fun chat(messages: List<ChatMessage>, context: AiContext): String {
        if (!modelManager.isModelReady()) {
            return "AI model not downloaded yet. Tap the download button to get started.\n\n" +
                "In the meantime, here's what I can tell you:\n\n" +
                fallback.chat(messages, context)
        }

        // TODO: Implement Llamatik inference when dependency is available
        // val modelPath = modelManager.modelPath() ?: return fallback.chat(messages, context)
        // try {
        //     if (llamaModel == null) {
        //         llamaModel = LlamaBridge.create(modelPath)
        //         logInfo("Gemma model loaded from $modelPath")
        //     }
        //     val systemPrompt = buildSystemPrompt(context)
        //     val result = llamaModel!!.generate(
        //         systemPrompt = systemPrompt,
        //         messages = messages.map { ... },
        //         temperature = 0.7f,
        //         topK = 40,
        //         maxTokens = 512,
        //     )
        //     return result
        // } catch (e: Exception) {
        //     logError("Gemma inference failed", e)
        //     return "AI model error: ${e.message}\n\nFalling back to built-in help:\n\n" +
        //         fallback.chat(messages, context)
        // }

        // For now, use heuristic with a note that LLM is pending
        logInfo("GemmaProvider: model ready but Llamatik not yet integrated, using heuristic fallback")
        return fallback.chat(messages, context)
    }

    @Suppress("unused")
    private fun buildSystemPrompt(context: AiContext): String {
        return """
            You are the DNSAI AI assistant, an intelligent helper for a DNS-based threat detection app.

            The user is currently viewing the ${context.screenName} screen.
            ${context.screenDescription}

            Current data:
            ${context.liveData}

            Available actions you can suggest: ${context.availableActions.joinToString(", ")}

            When suggesting a domain should be allowed, include [ALLOW:domain.com] in your response.
            When suggesting a domain should be blocked, include [BLOCK:domain.com] in your response.
            Be concise and helpful. Explain DNS concepts in simple terms.
        """.trimIndent()
    }

    override fun isAvailable(): Boolean = modelManager.isModelReady()

    override fun name(): String = "Gemma 4 E4B (On-Device)"
}
