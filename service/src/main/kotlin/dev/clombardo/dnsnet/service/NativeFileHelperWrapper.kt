/* Copyright (C) 2025 Charles Lombardo <clombardo169@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package dev.clombardo.dnsnet.service

import android.content.Context
import android.os.ParcelFileDescriptor
import dev.clombardo.dnsnet.blocklogger.ThreatLog
import dev.clombardo.dnsnet.common.FileHelper
import uniffi.net_bindings.FileHelperBinding
import java.io.File

class NativeFileHelperWrapper(private val context: Context) : FileHelperBinding {
    override fun getFd(path: String): Int? = FileHelper.getDetachedFd(context, path)

    override fun getDnsCacheFileFd(): Int? =
        FileHelper.getDetachedFd(
            context = context,
            path = File(context.externalCacheDir, "dnscache.blob").absolutePath,
            mode = ParcelFileDescriptor.MODE_READ_WRITE
        )

    override fun getAiModelData(): ByteArray? =
        try {
            context.assets.open("dga_classifier.bin").use { it.readBytes() }
        } catch (e: Exception) {
            null
        }

    override fun getAllowedDomains(): List<String>? =
        ThreatLog.getInstance(context).getAllowedDomains().ifEmpty { null }

    override fun getBlockedDomains(): List<String>? =
        ThreatLog.getInstance(context).getBlockedDomains().ifEmpty { null }
}
