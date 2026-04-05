/* Copyright (C) 2025 Charles Lombardo <clombardo169@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package dev.clombardo.dnsnet.blocklogger

import android.content.Context
import dev.clombardo.dnsnet.common.FileHelper
import dev.clombardo.dnsnet.common.logError
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.encodeToStream

@Serializable
data class BlockLogger(val connections: MutableMap<String, LoggedConnection> = HashMap()) {
    @Transient
    private var onConnection: ((name: String, connection: LoggedConnection) -> Unit)? = null

    @Transient
    var threatLog: ThreatLog? = null

    fun setOnConnectionListener(listener: ((name: String, connection: LoggedConnection) -> Unit)?) {
        onConnection = listener
    }

    fun newConnection(name: String, allowed: Boolean) {
        newConnectionWithAi(name, allowed, "none", 0f)
    }

    fun newConnectionWithAi(name: String, allowed: Boolean, blockSource: String, aiConfidence: Float) {
        val connection = connections[name]
        val now = System.currentTimeMillis()
        if (connection != null) {
            if (connection.allowed != allowed) {
                connections.remove(name)
                connections[name] = LoggedConnection(allowed, 1, now, blockSource, aiConfidence)
            } else {
                connection.attempt(now)
                connection.blockSource = blockSource
                connection.aiConfidence = aiConfidence
            }
        } else {
            connections[name] = LoggedConnection(allowed, 1, now, blockSource, aiConfidence)
        }
        onConnection?.invoke(name, connections[name]!!)

        // Record to persistent threat log
        val action = if (allowed) "allowed" else "blocked"
        threatLog?.record(name, blockSource, action, aiConfidence)
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun save(context: Context, name: String = DEFAULT_LOG_FILENAME) {
        try {
            val outputStream = FileHelper.openWrite(context, name)
            json.encodeToStream(this, outputStream)
        } catch (e: Exception) {
            logError("Failed to write connection history", e)
        }
    }

    fun clear(context: Context) {
        connections.clear()
        context.getFileStreamPath(DEFAULT_LOG_FILENAME).delete()
    }

    companion object {
        private const val DEFAULT_LOG_FILENAME = "connections.json"

        private val json by lazy {
            Json {
                ignoreUnknownKeys = true
            }
        }

        @OptIn(ExperimentalSerializationApi::class)
        internal fun load(context: Context, name: String = DEFAULT_LOG_FILENAME): BlockLogger {
            val inputStream =
                FileHelper.openRead(context, name) ?: return BlockLogger()
            return try {
                json.decodeFromStream<BlockLogger>(inputStream)
            } catch (e: Exception) {
                logError("Failed to load connection history", e)
                BlockLogger()
            }
        }
    }
}

@Serializable
data class LoggedConnection(
    val allowed: Boolean = true,
    var attempts: Long = 0,
    var lastAttemptTime: Long = 0,
    var blockSource: String = "none",
    var aiConfidence: Float = 0f,
) {
    fun attempt(now: Long) {
        attempts++
        lastAttemptTime = now
    }
}
