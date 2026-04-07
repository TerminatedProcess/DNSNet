package dev.clombardo.dnsnet.ui.app

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.clombardo.dnsnet.blocklogger.DomainDetail
import dev.clombardo.dnsnet.blocklogger.DomainPolicy
import dev.clombardo.dnsnet.blocklogger.HourlyCount
import dev.clombardo.dnsnet.ui.app.viewmodel.ThreatDetailViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreatDetailScreen(
    vm: ThreatDetailViewModel,
    onNavigateUp: () -> Unit,
    onReloadVpn: () -> Unit,
) {
    val detail by vm.detail.collectAsState()
    val hourlyActivity by vm.hourlyActivity.collectAsState()
    val policy by vm.policy.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        vm.domain,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 14.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onNavigateUp) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = PaddingValues(vertical = 12.dp),
        ) {
            // Detection info card
            item {
                detail?.let { d ->
                    DetectionInfoCard(d)
                }
            }

            // Stats
            item {
                detail?.let { d ->
                    StatsCard(d)
                }
            }

            // Activity chart
            if (hourlyActivity.isNotEmpty()) {
                item {
                    Text(
                        "Activity — Last 24 Hours",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                    )
                }
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant
                        )
                    ) {
                        val textMeasurer = rememberTextMeasurer()
                        val barColor = MaterialTheme.colorScheme.primary
                        val labelColor = MaterialTheme.colorScheme.onSurfaceVariant
                        ActivityChart(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(140.dp)
                                .padding(16.dp),
                            data = hourlyActivity,
                            barColor = barColor,
                            labelColor = labelColor,
                            textMeasurer = textMeasurer,
                        )
                    }
                }
            }

            // Policy selector
            item {
                Text(
                    "Domain Policy",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "Override how DNSAI handles this domain. Changes take effect immediately.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            item {
                PolicySelector(
                    currentPolicy = policy,
                    onPolicyChange = { newPolicy ->
                        vm.setPolicy(newPolicy)
                        onReloadVpn()
                    },
                )
            }

            item { Spacer(Modifier.height(24.dp)) }
        }
    }
}

@Composable
private fun DetectionInfoCard(detail: DomainDetail) {
    val sourceLabel = when (detail.primarySource) {
        "ai" -> "AI DGA Classifier"
        "blocklist" -> "Static Blocklist"
        "tunneling" -> "DNS Tunneling Detector"
        "tracker" -> "Known Tracker"
        "beaconing" -> "Beaconing Detector"
        "user_policy" -> "User Policy"
        else -> detail.primarySource.replaceFirstChar { it.uppercase() }
    }
    val sourceColor = when (detail.primarySource) {
        "ai" -> Color(0xFF4A148C)
        "blocklist" -> Color(0xFFB71C1C)
        "tunneling" -> Color(0xFF1B5E20)
        "tracker" -> Color(0xFFE65100)
        "beaconing" -> Color(0xFF0D47A1)
        "user_policy" -> Color(0xFF37474F)
        else -> Color(0xFF616161)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = sourceColor)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
        ) {
            Text(
                sourceLabel,
                color = Color.White,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                detail.domain,
                color = Color.White.copy(alpha = 0.9f),
                fontSize = 13.sp,
                fontFamily = FontFamily.Monospace,
            )
            if (detail.maxConfidence > 0f) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "AI Confidence: ${(detail.maxConfidence * 100).toInt()}%",
                    color = Color.White.copy(alpha = 0.8f),
                    fontSize = 13.sp,
                )
            }
        }
    }
}

@Composable
private fun StatsCard(detail: DomainDetail) {
    val dateFormat = SimpleDateFormat("MMM d, yyyy HH:mm", Locale.getDefault())

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Statistics", fontWeight = FontWeight.Bold, fontSize = 16.sp)

            StatRow("Total hits", detail.totalHits.toString())
            StatRow("Blocked", detail.blockedCount.toString())
            StatRow("Allowed", detail.allowedCount.toString())
            StatRow("First seen", dateFormat.format(Date(detail.firstSeen)))
            StatRow("Last seen", dateFormat.format(Date(detail.lastSeen)))
        }
    }
}

@Composable
private fun StatRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            label,
            fontSize = 13.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            fontSize = 13.sp,
            fontWeight = FontWeight.Medium,
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PolicySelector(
    currentPolicy: DomainPolicy,
    onPolicyChange: (DomainPolicy) -> Unit,
) {
    val options = DomainPolicy.entries

    SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
        options.forEachIndexed { index, policy ->
            SegmentedButton(
                shape = SegmentedButtonDefaults.itemShape(index = index, count = options.size),
                onClick = { onPolicyChange(policy) },
                selected = policy == currentPolicy,
                colors = when (policy) {
                    DomainPolicy.ALLOW -> SegmentedButtonDefaults.colors(
                        activeContainerColor = Color(0xFF2E7D32),
                        activeContentColor = Color.White,
                    )
                    DomainPolicy.AUTO -> SegmentedButtonDefaults.colors()
                    DomainPolicy.BLOCK -> SegmentedButtonDefaults.colors(
                        activeContainerColor = Color(0xFFB71C1C),
                        activeContentColor = Color.White,
                    )
                },
            ) {
                Text(
                    when (policy) {
                        DomainPolicy.ALLOW -> "Allow"
                        DomainPolicy.AUTO -> "Auto"
                        DomainPolicy.BLOCK -> "Block"
                    },
                    fontWeight = FontWeight.Bold,
                )
            }
        }
    }
}

@Composable
private fun ActivityChart(
    modifier: Modifier,
    data: List<HourlyCount>,
    barColor: Color,
    labelColor: Color,
    textMeasurer: androidx.compose.ui.text.TextMeasurer,
) {
    Canvas(modifier = modifier) {
        if (data.isEmpty()) return@Canvas

        val maxCount = data.maxOf { it.count }.coerceAtLeast(1)
        val slotWidth = (size.width / data.size.coerceAtLeast(1)).coerceAtMost(60.dp.toPx())
        val barWidth = slotWidth * 0.7f
        val chartHeight = size.height - 36.dp.toPx()
        val topPadding = 16.dp.toPx()
        val fmt = SimpleDateFormat("HH:mm", Locale.getDefault())

        data.forEachIndexed { index, hourly ->
            val barHeight = (hourly.count.toFloat() / maxCount) * (chartHeight - topPadding)
            val x = index * slotWidth + (slotWidth - barWidth) / 2

            drawRect(
                color = barColor,
                topLeft = Offset(x, chartHeight - barHeight),
                size = Size(barWidth, barHeight),
            )

            val countText = textMeasurer.measure(
                hourly.count.toString(),
                style = TextStyle(fontSize = 10.sp, color = labelColor, fontWeight = FontWeight.Bold)
            )
            drawText(
                countText,
                topLeft = Offset(
                    x + barWidth / 2 - countText.size.width / 2,
                    chartHeight - barHeight - countText.size.height - 2.dp.toPx()
                )
            )

            if (data.size <= 12 || index % 3 == 0) {
                val label = fmt.format(Date(hourly.hourTimestamp))
                val textResult = textMeasurer.measure(
                    label, style = TextStyle(fontSize = 9.sp, color = labelColor)
                )
                drawText(
                    textResult,
                    topLeft = Offset(
                        x + barWidth / 2 - textResult.size.width / 2,
                        chartHeight + 4.dp.toPx()
                    )
                )
            }
        }
    }
}
