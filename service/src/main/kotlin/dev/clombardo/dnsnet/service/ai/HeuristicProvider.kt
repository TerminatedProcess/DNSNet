package dev.clombardo.dnsnet.service.ai

/**
 * Rule-based troubleshooting provider that works without any LLM model.
 * Analyzes blocked domains and the app name to produce actionable suggestions.
 */
class HeuristicProvider : LlmProvider {

    override suspend fun chat(messages: List<ChatMessage>, context: TroubleshootContext): String {
        if (context.recentBlocks.isEmpty()) {
            return "No domains were blocked in the last few minutes. " +
                    "Try using the app first, then come back here so I can see what got blocked."
        }

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

        // Check if the last user message is a follow-up
        val lastUserMessage = messages.lastOrNull { it.role == "user" }?.content?.lowercase() ?: ""
        if (lastUserMessage.contains("no") || lastUserMessage.contains("still") ||
            lastUserMessage.contains("not working") || lastUserMessage.contains("didn't")
        ) {
            sb.appendLine("Let me suggest some additional domains to try allowing.\n")
        }

        if (likelyNeeded.isNotEmpty()) {
            sb.appendLine("These blocked domains look like they belong to **${context.appName}** and are likely needed:\n")
            for (d in likelyNeeded) {
                sb.appendLine("- **${d.domain}** was blocked ${d.count} time(s) by ${formatSource(d.source)}. This looks like an essential endpoint. [ALLOW:${d.domain}]")
            }
            sb.appendLine()
        }

        if (apiOrCdn.isNotEmpty()) {
            sb.appendLine("These might be needed (API/CDN endpoints):\n")
            for (d in apiOrCdn) {
                sb.appendLine("- **${d.domain}** (blocked ${d.count}x by ${formatSource(d.source)}). Could be required for content delivery. [ALLOW:${d.domain}]")
            }
            sb.appendLine()
        }

        if (trackers.isNotEmpty()) {
            sb.appendLine("These are likely trackers/analytics (probably not needed):\n")
            for (d in trackers) {
                sb.appendLine("- **${d.domain}** (${formatSource(d.source)}) -- tracking/analytics, unlikely to break the app")
            }
            sb.appendLine()
        }

        if (other.isNotEmpty() && likelyNeeded.isEmpty() && apiOrCdn.isEmpty()) {
            sb.appendLine("I couldn't match these domains to ${context.appName}, but they were recently blocked:\n")
            for (d in other.take(5)) {
                sb.appendLine("- **${d.domain}** (blocked ${d.count}x by ${formatSource(d.source)}) [ALLOW:${d.domain}]")
            }
            sb.appendLine()
        }

        sb.appendLine("Try allowing the suggested domains above, then check if ${context.appName} works. Did that fix it?")

        return sb.toString().trim()
    }

    override fun isAvailable(): Boolean = true

    override fun name(): String = "Heuristic"

    private fun extractAppKeywords(appName: String): List<String> {
        // Extract meaningful words from the app name
        // "Feedly - Smarter News Reader" -> ["feedly"]
        // "com.feedly.android" -> ["feedly"]
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
