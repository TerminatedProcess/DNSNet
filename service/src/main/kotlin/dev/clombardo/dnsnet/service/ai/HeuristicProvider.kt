package dev.clombardo.dnsnet.service.ai

/**
 * Rule-based provider that works without any LLM model.
 * Handles both troubleshooting (when appName is set) and
 * screen-aware contextual help (when screenName is set).
 */
class HeuristicProvider : LlmProvider {

    override suspend fun chat(messages: List<ChatMessage>, context: AiContext): String {
        val lastUserMessage = messages.lastOrNull { it.role == "user" }?.content?.lowercase() ?: ""
        val messageCount = messages.count { it.role == "user" }

        // Screen-aware help mode (no troubleshooting app specified)
        if (context.appName.isBlank() && context.screenName.isNotBlank()) {
            return handleScreenHelp(lastUserMessage, context)
        }

        // Handle conversational follow-ups
        if (messageCount > 1 && context.recentBlocks.isEmpty()) {
            return handleFollowUp(lastUserMessage, context)
        }

        // First interaction with app name
        if (messageCount == 1) {
            return analyzeInitial(context)
        }

        // Follow-up after initial analysis
        return handleFollowUp(lastUserMessage, context)
    }

    private fun handleScreenHelp(message: String, context: AiContext): String {
        return when {
            message.contains("help") || message.contains("what") && message.contains("screen") -> {
                "You're on the **${context.screenName}** screen.\n\n" +
                "${context.screenDescription}\n\n" +
                "**Current state:**\n${context.liveData}\n\n" +
                "I can help with: ${context.availableActions.joinToString(", ")}"
            }
            context.screenName == "Settings" -> handleSettingsHelp(message, context)
            context.screenName == "Dashboard" -> handleDashboardHelp(message, context)
            context.screenName == "Filters" -> handleFiltersHelp(message, context)
            context.screenName == "Apps" -> handleAppsHelp(message, context)
            context.screenName == "DNS" -> handleDnsHelp(message, context)
            else -> {
                "You're on the **${context.screenName}** screen. ${context.screenDescription}\n\n" +
                "**Current state:**\n${context.liveData}\n\n" +
                "Ask me anything about what you see here, or type **help** for an overview."
            }
        }
    }

    private fun handleSettingsHelp(message: String, context: AiContext): String {
        return when {
            message.contains("ai") || message.contains("classification") || message.contains("dga") -> {
                "**AI Classification** uses a machine learning model (XGBoost with 300 trees) running " +
                "entirely on your device to detect DGA (Domain Generation Algorithm) domains.\n\n" +
                "DGA domains are used by malware to generate random-looking domain names (like `xk3jf8.net`) " +
                "that bypass static blocklists. The AI analyzes 26 features of each domain including entropy, " +
                "character patterns, and n-grams.\n\n" +
                "The model runs in under 5ms per domain and doesn't send any data off your device."
            }
            message.contains("tracker") -> {
                "**Block Known Trackers** blocks 80+ domains used for advertising, analytics, " +
                "fingerprinting, and social media tracking. This works alongside your filter lists " +
                "but covers the most common trackers even without any filter files configured."
            }
            message.contains("block log") || message.contains("logging") -> {
                "**Block Log** records every DNS connection your device makes, showing whether it was " +
                "allowed or blocked and by which detection layer. Useful for troubleshooting app issues " +
                "and understanding your DNS traffic patterns. Turning it off saves a small amount of storage and CPU."
            }
            message.contains("import") || message.contains("export") -> {
                "**Import/Export** lets you backup and restore your DNSAI settings (filters, DNS servers, " +
                "app bypass list, etc.) as a JSON file. Useful for transferring settings to a new device."
            }
            else -> {
                "You're on the **Settings** screen.\n\n${context.liveData}\n\n" +
                "Ask about any setting: **AI classification**, **trackers**, **block log**, or **import/export**."
            }
        }
    }

    private fun handleDashboardHelp(message: String, context: AiContext): String {
        return when {
            message.contains("threat") || message.contains("block") || message.contains("domain") -> {
                "The dashboard shows your threat statistics for today.\n\n${context.liveData}\n\n" +
                "Tap any domain to see its full history, detection source, and confidence level. " +
                "You can also set per-domain policies (allow/block) from the detail screen."
            }
            else -> {
                "**Dashboard** -- your threat intelligence overview.\n\n${context.liveData}\n\n" +
                "Ask me about any threats you see, or what the numbers mean."
            }
        }
    }

    private fun handleFiltersHelp(message: String, context: AiContext): String {
        return when {
            message.contains("state") || message.contains("deny") || message.contains("allow") || message.contains("ignore") -> {
                "Filter states control how domains in the list are handled:\n\n" +
                "- **Deny** -- Domains in this list are blocked\n" +
                "- **Allow** -- Domains in this list are always allowed (overrides other blocks)\n" +
                "- **Ignore** -- This filter is disabled and won't be loaded\n\n" +
                "You can cycle through states by tapping the state icon next to each filter."
            }
            else -> {
                "**Filters** -- manage your DNS blocklists.\n\n${context.liveData}\n\n" +
                "Filter files are URL-based blocklists (like Hagezi or OISD). " +
                "Single filters are individual domain rules you add manually.\n\n" +
                "Ask about **filter states** (Deny/Allow/Ignore) for more detail."
            }
        }
    }

    private fun handleAppsHelp(message: String, context: AiContext): String {
        return when {
            message.contains("bypass") || message.contains("exclude") || message.contains("vpn") -> {
                "Apps can be configured to either **use the VPN** (DNS filtering applies) or " +
                "**bypass the VPN** (DNS goes directly to the network, no filtering).\n\n" +
                "Bypass an app if it needs to reach domains that DNSAI blocks but you can't allowlist, " +
                "or if it has its own DNS handling that conflicts with the VPN.\n\n" +
                "The default mode controls what happens for apps you haven't explicitly configured."
            }
            else -> {
                "**Apps** -- control which apps use DNS filtering.\n\n${context.liveData}\n\n" +
                "Ask about **app bypass** to understand how to exclude specific apps from filtering."
            }
        }
    }

    private fun handleDnsHelp(message: String, context: AiContext): String {
        return when {
            message.contains("doh3") || message.contains("http/3") || message.contains("quic") || message.contains("protocol") -> {
                "**DNS over HTTP/3 (DoH3)** sends DNS queries via the QUIC protocol, providing " +
                "encryption and faster connection setup.\n\n" +
                "**Important:** Most home routers don't support DoH3. If apps can't connect after " +
                "enabling it, turn it OFF and use standard DNS instead.\n\n" +
                "Standard DNS sends queries in plaintext to your configured servers (like Cloudflare 1.1.1.1)."
            }
            message.contains("server") || message.contains("cloudflare") || message.contains("google") -> {
                "DNS servers resolve domain names to IP addresses. DNSAI intercepts these queries " +
                "to filter threats before forwarding to your chosen upstream server.\n\n" +
                "Popular options:\n" +
                "- **Cloudflare (1.1.1.1)** -- Fast, privacy-focused\n" +
                "- **Quad9 (9.9.9.9)** -- Security-focused, blocks known threats\n" +
                "- **Google (8.8.8.8)** -- Reliable, widely used"
            }
            else -> {
                "**DNS** -- configure upstream DNS servers and protocols.\n\n${context.liveData}\n\n" +
                "Ask about **DNS protocols** or specific **servers** for more detail."
            }
        }
    }

    private fun analyzeInitial(context: AiContext): String {
        val sb = StringBuilder()
        val appName = context.appName

        if (context.recentBlocks.isEmpty()) {
            sb.appendLine("I don't see any domains blocked for **$appName** recently.\n")
            sb.appendLine("This usually means one of these things:\n")

            if (context.recentAllowed.isEmpty()) {
                sb.appendLine("**DNS resolution might not be working.** I don't see any DNS traffic at all. Check these:")
                sb.appendLine("- Open the **DNS** tab and make sure **DNS over HTTP/3 is OFF** (your router may not support it)")
                sb.appendLine("- Try toggling the VPN off and on")
                sb.appendLine("- Make sure you're connected to WiFi or mobile data\n")
            } else {
                val appKeywords = extractAppKeywords(appName.lowercase())
                val matchingAllowed = context.recentAllowed.filter { domain ->
                    appKeywords.any { it.length >= 3 && domain.lowercase().contains(it) }
                }

                if (matchingAllowed.isNotEmpty()) {
                    sb.appendLine("I can see traffic from $appName (${matchingAllowed.take(3).joinToString(", ")}), and it's being **allowed** -- DNSAI isn't blocking it.\n")
                    sb.appendLine("The issue might be:")
                    sb.appendLine("- The server itself is down")
                    sb.appendLine("- DNS over HTTP/3 is enabled but your router doesn't support it (check DNS tab)")
                    sb.appendLine("- A network issue unrelated to DNSAI\n")
                    sb.appendLine("Try turning DNSAI off temporarily. If the app still doesn't work, the problem is outside DNSAI.")
                } else {
                    sb.appendLine("I see other DNS traffic flowing, but nothing matching **$appName**.")
                    sb.appendLine("- The app might not have made any requests yet")
                    sb.appendLine("- Try opening **$appName** now, wait a few seconds, then come back here and type **retry**")
                }
            }

            return sb.toString().trim()
        }

        return analyzeBlocks(context)
    }

    private fun analyzeBlocks(context: AiContext): String {
        val appLower = context.appName.lowercase()
        val appKeywords = extractAppKeywords(appLower)

        val likelyNeeded = mutableListOf<BlockedDomain>()
        val trackers = mutableListOf<BlockedDomain>()
        val apiOrCdn = mutableListOf<BlockedDomain>()
        val other = mutableListOf<BlockedDomain>()

        for (domain in context.recentBlocks) {
            val domainLower = domain.domain.lowercase()
            when {
                appKeywords.any { it.length >= 3 && domainLower.contains(it) } -> likelyNeeded.add(domain)
                isTracker(domainLower) -> trackers.add(domain)
                isApiOrCdn(domainLower) -> apiOrCdn.add(domain)
                else -> other.add(domain)
            }
        }

        val sb = StringBuilder()

        sb.appendLine("I found **${context.recentBlocks.size}** blocked domain(s) in the last few minutes.\n")

        if (likelyNeeded.isNotEmpty()) {
            sb.appendLine("These look like they belong to **${context.appName}** and are likely needed:\n")
            for (d in likelyNeeded) {
                sb.appendLine("- **${d.domain}** -- blocked ${d.count} time(s) by ${formatSource(d.source)}. This looks essential. [ALLOW:${d.domain}]")
            }
            sb.appendLine()
        }

        if (apiOrCdn.isNotEmpty()) {
            sb.appendLine("These might be needed (API/CDN endpoints):\n")
            for (d in apiOrCdn) {
                sb.appendLine("- **${d.domain}** -- blocked ${d.count}x by ${formatSource(d.source)}. Could be required. [ALLOW:${d.domain}]")
            }
            sb.appendLine()
        }

        if (trackers.isNotEmpty()) {
            sb.appendLine("These are likely trackers (probably not needed):\n")
            for (d in trackers) {
                sb.appendLine("- **${d.domain}** (${formatSource(d.source)}) -- tracking/analytics")
            }
            sb.appendLine()
        }

        if (other.isNotEmpty() && likelyNeeded.isEmpty() && apiOrCdn.isEmpty()) {
            sb.appendLine("I couldn't match these to ${context.appName}, but they were recently blocked:\n")
            for (d in other.take(5)) {
                sb.appendLine("- **${d.domain}** -- blocked ${d.count}x by ${formatSource(d.source)} [ALLOW:${d.domain}]")
            }
            sb.appendLine()
        }

        sb.appendLine("Try allowing the suggested domains, then check if **${context.appName}** works. Type **retry** to re-check, or **yes/no** to let me know.")

        return sb.toString().trim()
    }

    private fun handleFollowUp(message: String, context: AiContext): String {
        return when {
            message.contains("retry") || message.contains("check again") || message.contains("re-check") -> {
                if (context.recentBlocks.isEmpty()) {
                    "Still no new blocks detected. The issue might not be DNS-related. Try:\n" +
                    "- Check your **DNS tab** -- make sure **DNS over HTTP/3 is OFF**\n" +
                    "- Turn the VPN off, test the app, then turn it back on\n" +
                    "- If the app works without VPN, the issue is DNS resolution timing"
                } else {
                    analyzeBlocks(context)
                }
            }
            message.contains("yes") || message.contains("works") || message.contains("fixed") || message.contains("thank") -> {
                "Great, glad it's working! The domain policy has been saved -- it'll stay allowed across VPN restarts."
            }
            message.contains("no") || message.contains("still") || message.contains("not working") || message.contains("didn't") -> {
                if (context.recentBlocks.isNotEmpty()) {
                    "Let me look at additional blocked domains that might be causing the issue.\n\n" +
                    analyzeBlocks(context)
                } else {
                    "I'm not seeing new blocks. This suggests the issue isn't DNSAI blocking domains. Try:\n\n" +
                    "1. **Check DNS tab** -- Is **DNS over HTTP/3** turned OFF? Your router doesn't support it.\n" +
                    "2. **Toggle VPN** -- Stop and restart the VPN service\n" +
                    "3. **Test without VPN** -- If the app works without DNSAI, it's a DNS resolution issue\n" +
                    "4. **Check the Dashboard** -- see if the app's domains are showing up at all"
                }
            }
            message.contains("hello") || message.contains("hi") || message.contains("hey") -> {
                "Hi! I'm the DNSAI assistant. I can help with:\n" +
                "- Troubleshooting app connectivity issues\n" +
                "- Explaining what's on your current screen\n" +
                "- Understanding DNS and threat detection settings\n\n" +
                "What would you like to know?"
            }
            message.contains("help") -> {
                "Here's how I can help:\n\n" +
                "1. Tell me which **app** isn't working\n" +
                "2. I'll check what domains were recently blocked\n" +
                "3. I'll suggest which ones to **Allow** so the app works\n" +
                "4. You can tap the Allow button to fix it instantly\n\n" +
                "I also know about every screen in DNSAI -- just ask about what you see!"
            }
            message.contains("doh3") || message.contains("dns over http") || message.contains("dns setting") -> {
                "DNS over HTTP/3 (DoH3) sends DNS queries via QUIC protocol. " +
                "Most home routers only support standard DNS or DNS-over-TLS (DoT), not DoH3. " +
                "When DoH3 is enabled, DNS queries may time out and apps can't connect.\n\n" +
                "**Fix:** Go to the DNS tab and turn OFF 'DNS over HTTP/3'."
            }
            else -> {
                // Try screen-aware help if we have a context
                if (context.screenName.isNotBlank()) {
                    handleScreenHelp(message, context)
                } else if (context.recentBlocks.isNotEmpty()) {
                    "I see ${context.recentBlocks.size} recently blocked domain(s). " +
                    "Would you like me to analyze them? Type the app name that's having issues, " +
                    "or type **retry** to re-check."
                } else {
                    "I can help with app connectivity issues or explain any DNSAI feature. " +
                    "Type **help** for instructions, or just ask a question!"
                }
            }
        }
    }

    override fun isAvailable(): Boolean = true
    override fun name(): String = "Heuristic"

    private fun extractAppKeywords(appName: String): List<String> {
        val cleaned = appName
            .replace(Regex("[^a-z0-9\\s.]"), " ")
            .split(Regex("[\\s.]+"))
            .filter { it.length >= 3 }
            .filter { it !in STOP_WORDS }
        return cleaned.distinct()
    }

    private fun isTracker(domain: String): Boolean =
        TRACKER_PATTERNS.any { domain.contains(it) }

    private fun isApiOrCdn(domain: String): Boolean =
        API_CDN_PATTERNS.any { domain.startsWith(it) || domain.contains(".$it") } ||
                domain.contains("googleapis.com") ||
                domain.contains("gstatic.com") ||
                domain.contains("cloudfront.net") ||
                domain.contains("akamai")

    private fun formatSource(source: String): String = when (source) {
        "ai" -> "AI (DGA detection)"
        "blocklist" -> "your filter list"
        "tunneling" -> "tunneling detector"
        "tracker" -> "tracker detector"
        "beaconing" -> "beaconing detector"
        "user_policy" -> "your policy"
        else -> source
    }

    companion object {
        private val STOP_WORDS = setOf(
            "the", "and", "for", "app", "android", "com", "org", "net",
            "free", "pro", "lite", "plus", "new", "best", "top", "your",
            "smart", "super", "ultra", "mega", "reader", "viewer", "manager",
        )

        private val TRACKER_PATTERNS = listOf(
            "analytics", "tracker", "tracking", "telemetry", "metric",
            "doubleclick", "adsserv", "adservice", "googlesyndication",
            "facebook.com/tr", "pixel", "crashlytics", "appsflyer",
            "adjust.com", "branch.io", "amplitude", "mixpanel",
            "segment.io", "segment.com", "sentry.io",
            "firebaselogging", "app-measurement",
        )

        private val API_CDN_PATTERNS = listOf(
            "api.", "cdn.", "static.", "assets.", "media.", "images.",
            "content.", "data.", "edge.", "gateway.",
        )
    }
}
