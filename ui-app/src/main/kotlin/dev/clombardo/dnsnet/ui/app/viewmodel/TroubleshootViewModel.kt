package dev.clombardo.dnsnet.ui.app.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import dev.clombardo.dnsnet.blocklogger.DomainPolicy
import dev.clombardo.dnsnet.blocklogger.ThreatLog
import dev.clombardo.dnsnet.service.ai.BlockedDomain
import dev.clombardo.dnsnet.service.ai.ChatMessage
import dev.clombardo.dnsnet.service.ai.ClaudeProvider
import dev.clombardo.dnsnet.service.ai.HeuristicProvider
import dev.clombardo.dnsnet.service.ai.LlmProvider
import dev.clombardo.dnsnet.service.ai.LocalLlmProvider
import dev.clombardo.dnsnet.service.ai.TroubleshootContext
import dev.clombardo.dnsnet.settings.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class TroubleshootViewModel @Inject constructor(
    private val threatLog: ThreatLog,
    private val settings: Settings,
    @ApplicationContext private val context: Context,
) : ViewModel() {

    private val _messages = MutableStateFlow<List<ChatMessage>>(emptyList())
    val messages = _messages.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading = _isLoading.asStateFlow()

    private val _allowedDomains = MutableStateFlow<Set<String>>(emptySet())
    val allowedDomains = _allowedDomains.asStateFlow()

    private var provider: LlmProvider = HeuristicProvider()
    private var troubleshootContext: TroubleshootContext? = null

    init {
        refreshProvider()
    }

    private fun refreshProvider() {
        val providerType = settings.aiProviderType.get()
        val apiKey = settings.claudeApiKey.get()
        provider = when (providerType) {
            "claude" -> if (apiKey.isNotBlank()) ClaudeProvider(apiKey) else HeuristicProvider()
            "local" -> LocalLlmProvider()
            else -> HeuristicProvider()
        }
    }

    fun selectApp(appName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _isLoading.value = true

            val recentBlocks = threatLog.recentBlocks(minutes = 5)
            val recentAllowed = threatLog.recentAllowed(minutes = 5)

            val ctx = TroubleshootContext(
                appName = appName,
                recentBlocks = recentBlocks.map { rb ->
                    BlockedDomain(
                        domain = rb.domain,
                        source = rb.source,
                        count = rb.count,
                        confidence = rb.maxConfidence,
                    )
                },
                recentAllowed = recentAllowed,
            )
            troubleshootContext = ctx

            val userMsg = ChatMessage("user", "My app $appName isn't working.")
            val currentMessages = listOf(userMsg)
            _messages.value = currentMessages

            refreshProvider()
            val response = provider.chat(currentMessages, ctx)
            _messages.value = currentMessages + ChatMessage("assistant", response)
            _isLoading.value = false
        }
    }

    fun sendMessage(text: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _isLoading.value = true
            val userMsg = ChatMessage("user", text)
            val currentMessages = _messages.value + userMsg
            _messages.value = currentMessages

            // Refresh context with latest data
            val appName = troubleshootContext?.appName ?: "Unknown"
            val recentBlocks = threatLog.recentBlocks(minutes = 10)
            val recentAllowed = threatLog.recentAllowed(minutes = 10)
            val ctx = TroubleshootContext(
                appName = appName,
                recentBlocks = recentBlocks.map { rb ->
                    BlockedDomain(rb.domain, rb.source, rb.count, rb.maxConfidence)
                },
                recentAllowed = recentAllowed,
            )
            troubleshootContext = ctx

            val response = provider.chat(currentMessages, ctx)
            _messages.value = currentMessages + ChatMessage("assistant", response)
            _isLoading.value = false
        }
    }

    fun allowDomain(domain: String) {
        viewModelScope.launch(Dispatchers.IO) {
            threatLog.setPolicy(domain, DomainPolicy.ALLOW)
            _allowedDomains.value = _allowedDomains.value + domain
        }
    }
}
