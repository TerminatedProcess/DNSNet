package dev.clombardo.dnsnet.service.ai

import dev.clombardo.dnsnet.common.logError
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

/**
 * LLM provider that calls the Anthropic Messages API.
 */
class ClaudeProvider(
    private val apiKey: String,
    private val model: String = DEFAULT_MODEL,
) : LlmProvider {

    override suspend fun chat(messages: List<ChatMessage>, context: TroubleshootContext): String =
        withContext(Dispatchers.IO) {
            try {
                val systemPrompt = buildSystemPrompt(context)
                val apiMessages = buildApiMessages(messages)

                val requestBody = JSONObject().apply {
                    put("model", model)
                    put("max_tokens", 1024)
                    put("system", systemPrompt)
                    put("messages", apiMessages)
                }

                val url = URL(API_URL)
                val conn = url.openConnection() as HttpURLConnection
                conn.apply {
                    requestMethod = "POST"
                    setRequestProperty("Content-Type", "application/json")
                    setRequestProperty("x-api-key", apiKey)
                    setRequestProperty("anthropic-version", "2023-06-01")
                    doOutput = true
                    connectTimeout = 30_000
                    readTimeout = 60_000
                }

                conn.outputStream.use { os ->
                    os.write(requestBody.toString().toByteArray(Charsets.UTF_8))
                }

                if (conn.responseCode != 200) {
                    val errorBody = conn.errorStream?.bufferedReader()?.readText() ?: "Unknown error"
                    return@withContext "API error (${conn.responseCode}): $errorBody"
                }

                val responseText = BufferedReader(InputStreamReader(conn.inputStream)).use {
                    it.readText()
                }

                val responseJson = JSONObject(responseText)
                val content = responseJson.getJSONArray("content")
                if (content.length() > 0) {
                    content.getJSONObject(0).getString("text")
                } else {
                    "No response from Claude."
                }
            } catch (e: Exception) {
                logError("ClaudeProvider error", e)
                "Failed to reach Claude API: ${e.message}"
            }
        }

    override fun isAvailable(): Boolean = apiKey.isNotBlank()

    override fun name(): String = "Claude"

    private fun buildSystemPrompt(context: TroubleshootContext): String {
        val blockedList = context.recentBlocks.joinToString("\n") { d ->
            "- ${d.domain} (source: ${d.source}, blocked ${d.count}x, confidence: ${(d.confidence * 100).toInt()}%)"
        }
        val allowedList = if (context.recentAllowed.isNotEmpty()) {
            context.recentAllowed.joinToString("\n") { "- $it" }
        } else {
            "(none)"
        }

        return """
You are a DNS firewall troubleshooting assistant for the DNSAI app.
The user's app "${context.appName}" isn't working properly.

Here are domains that were recently blocked:
$blockedList

Here are domains that were recently allowed:
$allowedList

Analyze which blocked domains the app likely needs to function.
For each domain you think should be allowed, include [ALLOW:domain.com] in your response.
Explain your reasoning briefly. Ask if the fix worked after suggesting changes.
        """.trimIndent()
    }

    private fun buildApiMessages(messages: List<ChatMessage>): JSONArray {
        val arr = JSONArray()
        for (msg in messages) {
            arr.put(JSONObject().apply {
                put("role", if (msg.role == "assistant") "assistant" else "user")
                put("content", msg.content)
            })
        }
        return arr
    }

    companion object {
        private const val API_URL = "https://api.anthropic.com/v1/messages"
        private const val DEFAULT_MODEL = "claude-sonnet-4-6"
    }
}
