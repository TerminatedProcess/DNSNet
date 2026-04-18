package dev.clombardo.dnsnet.service.ai.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.clombardo.dnsnet.service.ai.AiContext
import dev.clombardo.dnsnet.service.ai.ChatMessage
import dev.clombardo.dnsnet.service.ai.GemmaProvider
import dev.clombardo.dnsnet.service.ai.HeuristicProvider
import dev.clombardo.dnsnet.service.ai.LlmProvider
import dev.clombardo.dnsnet.service.ai.ModelManager
import javax.inject.Singleton

/**
 * Delegating provider that routes to GemmaProvider when the model is ready,
 * falling back to HeuristicProvider otherwise. Re-evaluates on each call.
 */
private class DelegatingProvider(
    private val modelManager: ModelManager,
) : LlmProvider {
    private val gemma by lazy { GemmaProvider(modelManager) }
    private val heuristic = HeuristicProvider()

    private fun current(): LlmProvider =
        if (modelManager.isModelReady()) gemma else heuristic

    override suspend fun chat(messages: List<ChatMessage>, context: AiContext): String =
        current().chat(messages, context)

    override fun isAvailable(): Boolean = current().isAvailable()

    override fun name(): String = current().name()
}

@Module
@InstallIn(SingletonComponent::class)
object AiModule {
    @Provides
    @Singleton
    fun provideLlmProvider(modelManager: ModelManager): LlmProvider =
        DelegatingProvider(modelManager)
}
