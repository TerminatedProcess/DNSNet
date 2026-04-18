package dev.clombardo.dnsnet.service.ai

/**
 * Stub provider for local on-device LLM inference.
 * TODO: Integrate Llamatik / Gemma 4 E4B when ready.
 * TODO: Add model download UI in Settings.
 * TODO: Wire up llama.cpp or MediaPipe LLM Inference API.
 */
class LocalLlmProvider : LlmProvider {

    override suspend fun chat(messages: List<ChatMessage>, context: TroubleshootContext): String =
        "Local LLM not configured. Download a model in Settings."

    override fun isAvailable(): Boolean = false

    override fun name(): String = "Local LLM"
}
