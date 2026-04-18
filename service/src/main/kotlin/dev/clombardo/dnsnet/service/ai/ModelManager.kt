package dev.clombardo.dnsnet.service.ai

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import dev.clombardo.dnsnet.common.logDebug
import dev.clombardo.dnsnet.common.logError
import dev.clombardo.dnsnet.common.logInfo
import dev.clombardo.dnsnet.settings.ConfigurationManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ModelManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val configuration: ConfigurationManager,
) {
    companion object {
        private const val MODEL_DIR = "models"
        private const val MODEL_FILENAME = "gemma-4-e4b-q4_k_m.gguf"
        private const val MODEL_URL =
            "https://huggingface.co/unsloth/gemma-4-E4B-it-GGUF/resolve/main/gemma-4-E4B-it-Q4_K_M.gguf"
        private const val MODEL_SIZE_BYTES = 2_500_000_000L
        private const val BUFFER_SIZE = 8192
    }

    sealed class DownloadState {
        data object NotStarted : DownloadState()
        data class Downloading(val progress: Float) : DownloadState()
        data class Ready(val path: String) : DownloadState()
        data class Error(val message: String) : DownloadState()
    }

    private val _state = MutableStateFlow<DownloadState>(DownloadState.NotStarted)
    val state: StateFlow<DownloadState> = _state.asStateFlow()

    init {
        val path = modelPath()
        if (path != null && File(path).exists()) {
            _state.value = DownloadState.Ready(path)
            logDebug("AI model already downloaded at $path")
        }
    }

    fun isModelReady(): Boolean = _state.value is DownloadState.Ready

    fun modelPath(): String? {
        val dir = context.getExternalFilesDir(MODEL_DIR) ?: return null
        val file = File(dir, MODEL_FILENAME)
        return if (file.exists()) file.absolutePath else null
    }

    fun getModelSizeDescription(): String = "~2.5 GB"

    suspend fun startDownload() = withContext(Dispatchers.IO) {
        if (_state.value is DownloadState.Downloading) return@withContext

        val dir = context.getExternalFilesDir(MODEL_DIR)
        if (dir == null) {
            _state.value = DownloadState.Error("Cannot access external storage")
            return@withContext
        }
        dir.mkdirs()

        val targetFile = File(dir, MODEL_FILENAME)
        val tempFile = File(dir, "$MODEL_FILENAME.part")

        try {
            _state.value = DownloadState.Downloading(0f)

            val existingBytes = if (tempFile.exists()) tempFile.length() else 0L

            val url = URL(MODEL_URL)
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 30_000
            conn.readTimeout = 60_000

            if (existingBytes > 0) {
                conn.setRequestProperty("Range", "bytes=$existingBytes-")
                logInfo("Resuming download from byte $existingBytes")
            }

            conn.connect()

            val responseCode = conn.responseCode
            val isResume = responseCode == HttpURLConnection.HTTP_PARTIAL
            val totalBytes = if (isResume) {
                existingBytes + conn.contentLengthLong
            } else {
                conn.contentLengthLong.let { if (it > 0) it else MODEL_SIZE_BYTES }
            }

            if (responseCode != HttpURLConnection.HTTP_OK &&
                responseCode != HttpURLConnection.HTTP_PARTIAL
            ) {
                _state.value = DownloadState.Error("HTTP error: $responseCode")
                conn.disconnect()
                return@withContext
            }

            val outputStream = if (isResume) {
                tempFile.outputStream().apply {
                    channel.position(existingBytes)
                }
            } else {
                tempFile.outputStream()
            }

            conn.inputStream.use { input ->
                outputStream.use { output ->
                    val buffer = ByteArray(BUFFER_SIZE)
                    var bytesDownloaded = if (isResume) existingBytes else 0L
                    var bytesRead: Int

                    while (input.read(buffer).also { bytesRead = it } != -1) {
                        output.write(buffer, 0, bytesRead)
                        bytesDownloaded += bytesRead
                        val progress = (bytesDownloaded.toFloat() / totalBytes).coerceIn(0f, 1f)
                        _state.value = DownloadState.Downloading(progress)
                    }
                }
            }

            conn.disconnect()

            // Rename temp to final
            if (tempFile.renameTo(targetFile)) {
                val path = targetFile.absolutePath
                configuration.edit {
                    modelDownloadStatus = "ready"
                    modelFilePath = path
                }
                _state.value = DownloadState.Ready(path)
                logInfo("AI model downloaded successfully to $path")
            } else {
                _state.value = DownloadState.Error("Failed to finalize download")
            }
        } catch (e: Exception) {
            logError("Model download failed", e)
            _state.value = DownloadState.Error(e.message ?: "Download failed")
        }
    }

    fun deleteModel() {
        val dir = context.getExternalFilesDir(MODEL_DIR)
        if (dir != null) {
            File(dir, MODEL_FILENAME).delete()
            File(dir, "$MODEL_FILENAME.part").delete()
        }
        configuration.edit {
            modelDownloadStatus = "none"
            modelFilePath = ""
        }
        _state.value = DownloadState.NotStarted
        logInfo("AI model deleted")
    }
}
