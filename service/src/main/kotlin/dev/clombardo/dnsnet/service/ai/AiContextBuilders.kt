package dev.clombardo.dnsnet.service.ai

import dev.clombardo.dnsnet.blocklogger.ThreatSummary
import dev.clombardo.dnsnet.blocklogger.TopDomain

object AiContextBuilders {
    fun forDashboard(summary: ThreatSummary, topDomains: List<TopDomain>): AiContext {
        val topStr = topDomains.take(5).joinToString("\n") {
            "- ${it.domain}: ${it.source}, ${it.action}, ${it.count} hits, ${(it.maxConfidence * 100).toInt()}% confidence"
        }
        return AiContext(
            screenName = "Dashboard",
            screenDescription = "Shows threat statistics, hourly block chart, and top threats",
            liveData = """
                Today: ${summary.totalBlocked} blocked, ${summary.aiBlocks} AI blocks,
                ${summary.trackerFlags} trackers flagged, ${summary.tunnelingBlocks} tunneling blocks,
                ${summary.blocklistBlocks} blocklist blocks.
                Top threats:
                $topStr
            """.trimIndent(),
            availableActions = listOf("[ALLOW:domain]", "[BLOCK:domain]"),
        )
    }

    fun forStart(aiEnabled: Boolean, blockTrackers: Boolean, blockLog: Boolean): AiContext = AiContext(
        screenName = "Settings",
        screenDescription = "Main settings for DNSAI -- toggle AI classification, tracker blocking, block logging, import/export, etc.",
        liveData = """
            AI classification: ${if (aiEnabled) "ON" else "OFF"} -- Uses XGBoost ML model to detect DGA (domain generation algorithm) malware domains
            Block known trackers: ${if (blockTrackers) "ON" else "OFF"} -- Blocks 80+ known advertising, analytics, fingerprinting, and social media tracking domains
            Block log: ${if (blockLog) "ON" else "OFF"} -- Records each DNS connection for viewing and analysis
            Resume on startup: ON
        """.trimIndent(),
        availableActions = listOf("Explain any setting"),
    )

    fun forFilters(filterCount: Int, singleCount: Int): AiContext = AiContext(
        screenName = "Filters",
        screenDescription = "Manage DNS filter/blocklist files and individual domain rules",
        liveData = "Filter files: $filterCount, Single filters: $singleCount",
        availableActions = listOf("Explain filter states (Deny/Allow/Ignore)"),
    )

    fun forApps(appCount: Int): AiContext = AiContext(
        screenName = "Apps",
        screenDescription = "Choose which apps use the VPN (DNS filtering) and which bypass it",
        liveData = "Apps configured: $appCount",
        availableActions = listOf("Explain app bypass"),
    )

    fun forDns(customEnabled: Boolean, doh3: Boolean, serverCount: Int): AiContext = AiContext(
        screenName = "DNS",
        screenDescription = "Configure DNS servers and protocols (Standard DNS vs DNS-over-HTTP/3)",
        liveData = """
            Custom DNS servers: ${if (customEnabled) "ON" else "OFF"}
            DNS over HTTP/3: ${if (doh3) "ON" else "OFF"} -- Note: Most home routers don't support DoH3. If apps can't connect, try turning this OFF.
            Configured servers: $serverCount
        """.trimIndent(),
        availableActions = listOf("Explain DNS protocols"),
    )
}
