package dev.clombardo.dnsnet.service.ai

/**
 * Rule-based troubleshooting provider that works without any LLM model.
 * Analyzes blocked domains, allowed domains, and conversation context
 * to produce actionable suggestions.
 */
class HeuristicProvider : LlmProvider {

    override suspend fun chat(messages: List<ChatMessage>, context: TroubleshootContext): String {
        val lastUserMessage = messages.lastOrNull { it.role == "user" }?.content?.lowercase() ?: ""
        val messageCount = messages.count { it.role == "user" }

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

    private fun analyzeInitial(context: TroubleshootContext): String {
        val sb = StringBuilder()
        val appName = context.appName

        if (context.recentBlocks.isEmpty()) {
            // No blocks found — diagnose why the app might not be working
            sb.appendLine("I don't see any domains blocked for **$appName** recently.\n")
            sb.appendLine("This usually means one of these things:\n")

            if (context.recentAllowed.isEmpty()) {
                // Nothing at all — DNS likely not working
                sb.appendLine("**DNS resolution might not be working.** I don't see any DNS traffic at all. Check these:")
                sb.appendLine("- Open the **DNS** tab and make sure **DNS over HTTP/3 is OFF** (your router may not support it)")
                sb.appendLine("- Try toggling the VPN off and on")
                sb.appendLine("- Make sure you're connected to WiFi or mobile data\n")
            } else {
                // Some domains are allowed — DNS works but the app's domains aren't being blocked
                val appKeywords = extractAppKeywords(appName.lowercase())
                val matchingAllowed = context.recentAllowed.filter { domain ->
                    appKeywords.any { it.length >= 3 && domain.lowercase().contains(it) }
                }

                if (matchingAllowed.isNotEmpty()) {
                    sb.appendLine("I can see traffic from $appName (${matchingAllowed.take(3).joinToString(", ")}), and it's being **allowed** — DNSAI isn't blocking it.\n")
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

        // We have blocked domains — analyze them
        return analyzeBlocks(context)
    }

    private fun analyzeBlocks(context: TroubleshootContext): String {
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
                sb.appendLine("- **${d.domain}** — blocked ${d.count} time(s) by ${formatSource(d.source)}. This looks essential. [ALLOW:${d.domain}]")
            }
            sb.appendLine()
        }

        if (apiOrCdn.isNotEmpty()) {
            sb.appendLine("These might be needed (API/CDN endpoints):\n")
            for (d in apiOrCdn) {
                sb.appendLine("- **${d.domain}** — blocked ${d.count}x by ${formatSource(d.source)}. Could be required. [ALLOW:${d.domain}]")
            }
            sb.appendLine()
        }

        if (trackers.isNotEmpty()) {
            sb.appendLine("These are likely trackers (probably not needed):\n")
            for (d in trackers) {
                sb.appendLine("- **${d.domain}** (${formatSource(d.source)}) — tracking/analytics")
            }
            sb.appendLine()
        }

        if (other.isNotEmpty() && likelyNeeded.isEmpty() && apiOrCdn.isEmpty()) {
            sb.appendLine("I couldn't match these to ${context.appName}, but they were recently blocked:\n")
            for (d in other.take(5)) {
                sb.appendLine("- **${d.domain}** — blocked ${d.count}x by ${formatSource(d.source)} [ALLOW:${d.domain}]")
            }
            sb.appendLine()
        }

        sb.appendLine("Try allowing the suggested domains, then check if **${context.appName}** works. Type **retry** to re-check, or **yes/no** to let me know.")

        return sb.toString().trim()
    }

    private fun handleFollowUp(message: String, context: TroubleshootContext): String {
        return when {
            message.contains("retry") || message.contains("check again") || message.contains("re-check") -> {
                if (context.recentBlocks.isEmpty()) {
                    "Still no new blocks detected. The issue might not be DNS-related. Try:\n" +
                    "- Check your **DNS tab** — make sure **DNS over HTTP/3 is OFF**\n" +
                    "- Turn the VPN off, test the app, then turn it back on\n" +
                    "- If the app works without VPN, the issue is DNS resolution timing"
                } else {
                    analyzeBlocks(context)
                }
            }
            message.contains("yes") || message.contains("works") || message.contains("fixed") || message.contains("thank") -> {
                "Great, glad it's working! The domain policy has been saved — it'll stay allowed across VPN restarts."
            }
            message.contains("no") || message.contains("still") || message.contains("not working") || message.contains("didn't") -> {
                if (context.recentBlocks.isNotEmpty()) {
                    "Let me look at additional blocked domains that might be causing the issue.\n\n" +
                    analyzeBlocks(context)
                } else {
                    "I'm not seeing new blocks. This suggests the issue isn't DNSAI blocking domains. Try:\n\n" +
                    "1. **Check DNS tab** — Is **DNS over HTTP/3** turned OFF? Your router doesn't support it.\n" +
                    "2. **Toggle VPN** — Stop and restart the VPN service\n" +
                    "3. **Test without VPN** — If the app works without DNSAI, it's a DNS resolution issue\n" +
                    "4. **Check the Dashboard** — see if the app's domains are showing up at all"
                }
            }
            message.contains("hello") || message.contains("hi") || message.contains("hey") -> {
                "Hi! I'm here to help fix app connectivity issues. What app isn't working? " +
                "Just tell me the name and I'll look at what DNSAI might be blocking."
            }
            message.contains("help") -> {
                "Here's how I can help:\n\n" +
                "1. Tell me which **app** isn't working\n" +
                "2. I'll check what domains were recently blocked\n" +
                "3. I'll suggest which ones to **Allow** so the app works\n" +
                "4. You can tap the Allow button to fix it instantly\n\n" +
                "The fix is saved permanently. You can also check the **Dashboard** to see all blocked domains."
            }
            message.contains("doh3") || message.contains("dns over http") || message.contains("dns setting") -> {
                "DNS over HTTP/3 (DoH3) sends DNS queries via QUIC protocol. " +
                "Your ASUS RT-BE58 Go router only supports DNS-over-TLS (DoT), not DoH3. " +
                "When DoH3 is enabled, DNS queries time out and apps can't connect.\n\n" +
                "**Fix:** Go to the DNS tab and turn OFF 'DNS over HTTP/3'."
            }
            else -> {
                // Generic response — try to be helpful
                if (context.recentBlocks.isNotEmpty()) {
                    "I see ${context.recentBlocks.size} recently blocked domain(s). " +
                    "Would you like me to analyze them? Type the app name that's having issues, " +
                    "or type **retry** to re-check."
                } else {
                    "I can help troubleshoot app connectivity issues. Tell me which app isn't working, " +
                    "or type **help** for instructions.\n\n" +
                    "If no app is broken but you want to check what's happening, " +
                    "visit the **Dashboard** tab for a full overview."
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
