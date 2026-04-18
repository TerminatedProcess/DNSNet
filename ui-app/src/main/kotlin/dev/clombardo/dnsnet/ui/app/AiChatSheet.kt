package dev.clombardo.dnsnet.ui.app

import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Download
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SheetState
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.clombardo.dnsnet.service.ai.ChatMessage
import dev.clombardo.dnsnet.service.ai.ModelManager
import dev.clombardo.dnsnet.ui.app.viewmodel.AiChatViewModel

// ── Message parsing ──

internal sealed class MessagePart {
    data class TextBlock(val text: String) : MessagePart()
    data class AllowAction(val domain: String) : MessagePart()
}

private val ALLOW_PATTERN = Regex("""\[ALLOW:([^\]]+)]""")

internal fun parseAssistantMessage(content: String): List<MessagePart> {
    val parts = mutableListOf<MessagePart>()
    var lastIndex = 0

    for (match in ALLOW_PATTERN.findAll(content)) {
        val before = content.substring(lastIndex, match.range.first)
        if (before.isNotEmpty()) {
            parts.add(MessagePart.TextBlock(before))
        }
        parts.add(MessagePart.AllowAction(match.groupValues[1]))
        lastIndex = match.range.last + 1
    }

    val remaining = content.substring(lastIndex)
    if (remaining.isNotEmpty()) {
        parts.add(MessagePart.TextBlock(remaining))
    }

    return parts
}

// ── Chat bubble ──

@Composable
internal fun ChatBubble(
    message: ChatMessage,
    allowedDomains: Set<String>,
    onAllowDomain: (String) -> Unit,
) {
    val isUser = message.role == "user"

    Box(
        modifier = Modifier.fillMaxWidth(),
        contentAlignment = if (isUser) Alignment.CenterEnd else Alignment.CenterStart,
    ) {
        Card(
            modifier = Modifier.widthIn(max = 320.dp),
            colors = CardDefaults.cardColors(
                containerColor = if (isUser) {
                    MaterialTheme.colorScheme.primaryContainer
                } else {
                    MaterialTheme.colorScheme.surfaceVariant
                }
            )
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                if (isUser) {
                    Text(
                        message.content,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        fontSize = 14.sp,
                    )
                } else {
                    val parts = parseAssistantMessage(message.content)
                    for (part in parts) {
                        when (part) {
                            is MessagePart.TextBlock -> {
                                if (part.text.isNotBlank()) {
                                    Text(
                                        part.text.trim(),
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        fontSize = 14.sp,
                                    )
                                }
                            }
                            is MessagePart.AllowAction -> {
                                val isAlreadyAllowed = allowedDomains.contains(part.domain)
                                Spacer(Modifier.height(4.dp))
                                Button(
                                    onClick = { onAllowDomain(part.domain) },
                                    enabled = !isAlreadyAllowed,
                                    colors = if (isAlreadyAllowed) {
                                        ButtonDefaults.buttonColors(
                                            disabledContainerColor = Color(0xFF2E7D32).copy(alpha = 0.3f),
                                            disabledContentColor = Color(0xFF2E7D32),
                                        )
                                    } else {
                                        ButtonDefaults.buttonColors(
                                            containerColor = Color(0xFF2E7D32),
                                            contentColor = Color.White,
                                        )
                                    },
                                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                                ) {
                                    if (isAlreadyAllowed) {
                                        Icon(
                                            Icons.Filled.CheckCircle,
                                            contentDescription = null,
                                            modifier = Modifier.size(16.dp),
                                        )
                                        Spacer(Modifier.width(4.dp))
                                        Text(
                                            stringResource(R.string.troubleshoot_domain_allowed, part.domain),
                                            fontSize = 12.sp,
                                            fontFamily = FontFamily.Monospace,
                                        )
                                    } else {
                                        Text(
                                            stringResource(R.string.troubleshoot_allow_domain, part.domain),
                                            fontSize = 12.sp,
                                            fontFamily = FontFamily.Monospace,
                                        )
                                    }
                                }
                                Spacer(Modifier.height(4.dp))
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Chat input bar ──

@Composable
internal fun ChatInputBar(
    onSend: (String) -> Unit,
    enabled: Boolean,
) {
    var text by rememberSaveable { mutableStateOf("") }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        OutlinedTextField(
            modifier = Modifier.weight(1f),
            value = text,
            onValueChange = { text = it },
            singleLine = true,
            enabled = enabled,
            placeholder = { Text(stringResource(R.string.ai_chat_placeholder)) },
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
            keyboardActions = KeyboardActions(onSend = {
                if (text.isNotBlank()) {
                    onSend(text.trim())
                    text = ""
                }
            }),
        )
        Spacer(Modifier.width(8.dp))
        IconButton(
            onClick = {
                if (text.isNotBlank()) {
                    onSend(text.trim())
                    text = ""
                }
            },
            enabled = enabled && text.isNotBlank(),
        ) {
            Icon(
                Icons.AutoMirrored.Filled.Send,
                contentDescription = stringResource(R.string.ai_send),
            )
        }
    }
}

// ── Model download card ──

@Composable
private fun ModelDownloadCard(
    downloadState: ModelManager.DownloadState,
    onDownload: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer,
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            when (downloadState) {
                is ModelManager.DownloadState.NotStarted -> {
                    Text(
                        stringResource(R.string.ai_model_not_downloaded),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.ai_model_description),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.7f),
                    )
                    Spacer(Modifier.height(12.dp))
                    Button(onClick = onDownload) {
                        Icon(
                            Icons.Default.Download,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.ai_download_model))
                    }
                }
                is ModelManager.DownloadState.Downloading -> {
                    Text(
                        stringResource(R.string.ai_downloading_model),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                    )
                    Spacer(Modifier.height(8.dp))
                    LinearProgressIndicator(
                        progress = { downloadState.progress },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "${(downloadState.progress * 100).toInt()}%",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.7f),
                    )
                }
                is ModelManager.DownloadState.Ready -> {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                stringResource(R.string.ai_model_ready),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF2E7D32),
                            )
                            Spacer(Modifier.height(2.dp))
                            Text(
                                "${ModelManager.MODEL_DISPLAY_NAME} (Q4_K_M)",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.7f),
                            )
                            Text(
                                "Model located at ${(downloadState as ModelManager.DownloadState.Ready).path}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.5f),
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                        OutlinedButton(
                            onClick = { onDelete(); onDownload() },
                            modifier = Modifier.padding(start = 8.dp),
                        ) {
                            Icon(
                                Icons.Default.Download,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(Modifier.width(4.dp))
                            Text("Re-download", style = MaterialTheme.typography.bodySmall)
                        }
                        IconButton(onClick = onDelete) {
                            Icon(
                                Icons.Default.DeleteOutline,
                                contentDescription = stringResource(R.string.ai_delete_model),
                                tint = MaterialTheme.colorScheme.error,
                            )
                        }
                    }
                }
                is ModelManager.DownloadState.Error -> {
                    Text(
                        stringResource(R.string.ai_model_error),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.error,
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        downloadState.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.7f),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(onClick = onDownload) {
                        Text(stringResource(R.string.ai_retry_download))
                    }
                }
            }
        }
    }
}

// ── Bottom sheet ──

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AiChatSheet(
    vm: AiChatViewModel,
    onDismiss: () -> Unit,
    onReloadVpn: () -> Unit,
) {
    val messages by vm.messages.collectAsState()
    val isLoading by vm.isLoading.collectAsState()
    val allowedDomains by vm.allowedDomains.collectAsState()
    val modelState by vm.modelState.collectAsState()

    val sheetState: SheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val screenHeight = LocalConfiguration.current.screenHeightDp.dp

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        dragHandle = null,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(max = screenHeight * 0.8f)
                .imePadding(),
        ) {
            // Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        stringResource(R.string.ai_assistant),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                    )
                }
                IconButton(onClick = onDismiss) {
                    Icon(
                        Icons.Default.Close,
                        contentDescription = stringResource(R.string.close),
                    )
                }
            }

            // Model download/status card
            ModelDownloadCard(
                downloadState = modelState,
                onDownload = { vm.startModelDownload() },
                onDelete = { vm.deleteModel() },
            )

            // Message list
            val listState = rememberLazyListState()

            LaunchedEffect(messages.size) {
                if (messages.isNotEmpty()) {
                    listState.animateScrollToItem(messages.size - 1)
                }
            }

            LazyColumn(
                modifier = Modifier.weight(1f),
                state = listState,
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(messages.size) { index ->
                    val message = messages[index]
                    ChatBubble(
                        message = message,
                        allowedDomains = allowedDomains,
                        onAllowDomain = { domain ->
                            vm.allowDomain(domain)
                            onReloadVpn()
                        },
                    )
                }

                if (isLoading) {
                    item {
                        Row(
                            modifier = Modifier.padding(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(
                                stringResource(R.string.ai_thinking),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }

            // Input bar
            ChatInputBar(
                onSend = { text -> vm.sendMessage(text) },
                enabled = !isLoading,
            )
        }
    }
}
