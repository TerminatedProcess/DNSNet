package dev.clombardo.dnsnet.ui.app.viewmodel

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.navigation.toRoute
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.clombardo.dnsnet.blocklogger.DomainDetail
import dev.clombardo.dnsnet.blocklogger.DomainPolicy
import dev.clombardo.dnsnet.blocklogger.HourlyCount
import dev.clombardo.dnsnet.blocklogger.ThreatLog
import dev.clombardo.dnsnet.ui.app.TopLevelDestination
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class ThreatDetailViewModel @Inject constructor(
    private val savedStateHandle: SavedStateHandle,
    private val threatLog: ThreatLog,
) : ViewModel() {
    val domain: String = savedStateHandle.toRoute<TopLevelDestination.ThreatDetail>().domain

    private val _detail = MutableStateFlow<DomainDetail?>(null)
    val detail = _detail.asStateFlow()

    private val _hourlyActivity = MutableStateFlow<List<HourlyCount>>(emptyList())
    val hourlyActivity = _hourlyActivity.asStateFlow()

    private val _policy = MutableStateFlow(DomainPolicy.AUTO)
    val policy = _policy.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        viewModelScope.launch(Dispatchers.IO) {
            _detail.value = threatLog.domainDetail(domain)
            _hourlyActivity.value = threatLog.domainHourlyActivity(domain)
            _policy.value = threatLog.getPolicy(domain)
        }
    }

    fun setPolicy(newPolicy: DomainPolicy) {
        viewModelScope.launch(Dispatchers.IO) {
            threatLog.setPolicy(domain, newPolicy)
            _policy.value = newPolicy
        }
    }
}
