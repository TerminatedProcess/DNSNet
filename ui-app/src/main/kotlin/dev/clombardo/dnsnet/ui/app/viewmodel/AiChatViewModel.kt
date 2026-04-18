package dev.clombardo.dnsnet.ui.app.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.clombardo.dnsnet.blocklogger.DomainPolicy
import dev.clombardo.dnsnet.blocklogger.ThreatLog
import dev.clombardo.dnsnet.service.ai.AiContext
import dev.clombardo.dnsnet.service.ai.AiContextBuilders
import dev.clombardo.dnsnet.service.ai.BlockedDomain
import dev.clombardo.dnsnet.service.ai.ChatMessage
import dev.clombardo.dnsnet.service.ai.LlmProvider
import dev.clombardo.dnsnet.service.ai.ModelManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class AiChatViewModel @Inject constructor(
    private val provider: LlmProvider,
    private val threatLog: ThreatLog,
    val modelManager: ModelManager,
) : ViewModel() {

    private val _messages = MutableStateFlow<List<ChatMessage>>(emptyList())
    val messages: StateFlow<List<ChatMessage>> = _messages.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _allowedDomains = MutableStateFlow<Set<String>>(emptySet())
    val allowedDomains: StateFlow<Set<String>> = _allowedDomains.asStateFlow()

    private val _isSheetVisible = MutableStateFlow(false)
    val isSheetVisible: StateFlow<Boolean> = _isSheetVisible.asStateFlow()

    val modelState: StateFlow<ModelManager.DownloadState> = modelManager.state

    private var currentContext: AiContext = AiContext(
        screenName = "Settings",
        screenDescription = "Main settings screen",
        liveData = "",
    )

    fun updateContext(context: AiContext) {
        currentContext = context
    }

    fun toggleSheet() {
        _isSheetVisible.value = !_isSheetVisible.value
    }

    fun showSheet() {
        _isSheetVisible.value = true
    }

    fun hideSheet() {
        _isSheetVisible.value = false
    }

    fun sendMessage(text: String, imageData: ByteArray? = null) {
        viewModelScope.launch(Dispatchers.IO) {
            _isLoading.value = true
            val userMsg = ChatMessage("user", text, imageData)
            val currentMessages = _messages.value + userMsg
            _messages.value = currentMessages

            // Enrich context with recent threat data
            val recentBlocks = threatLog.recentBlocks(minutes = 10)
            val recentAllowed = threatLog.recentAllowed(minutes = 10)
            val enrichedContext = currentContext.copy(
                recentBlocks = recentBlocks.map { rb ->
                    BlockedDomain(rb.domain, rb.source, rb.count, rb.maxConfidence)
                },
                recentAllowed = recentAllowed,
            )

            val response = provider.chat(currentMessages, enrichedContext)
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

    fun startModelDownload() {
        viewModelScope.launch(Dispatchers.IO) {
            modelManager.startDownload()
        }
    }

    fun deleteModel() {
        modelManager.deleteModel()
    }
}
