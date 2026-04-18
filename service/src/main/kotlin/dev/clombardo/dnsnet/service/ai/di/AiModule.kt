package dev.clombardo.dnsnet.service.ai.di

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import dev.clombardo.dnsnet.service.ai.ClaudeProvider
import dev.clombardo.dnsnet.service.ai.HeuristicProvider
import dev.clombardo.dnsnet.service.ai.LlmProvider
import dev.clombardo.dnsnet.service.ai.LocalLlmProvider
import dev.clombardo.dnsnet.settings.ConfigurationManager
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AiModule {
    @Provides
    @Singleton
    fun provideLlmProvider(configuration: ConfigurationManager): LlmProvider {
        val providerType = configuration.read { aiProviderType }
        val apiKey = configuration.read { claudeApiKey }
        return when (providerType) {
            "claude" -> if (apiKey.isNotBlank()) ClaudeProvider(apiKey) else HeuristicProvider()
            "local" -> LocalLlmProvider()
            else -> HeuristicProvider()
        }
    }
}
