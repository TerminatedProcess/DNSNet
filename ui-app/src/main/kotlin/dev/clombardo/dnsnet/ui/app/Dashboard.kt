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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.TextMeasurer
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.clombardo.dnsnet.blocklogger.HourlyCount
import dev.clombardo.dnsnet.blocklogger.ThreatSummary
import dev.clombardo.dnsnet.blocklogger.TopDomain
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun DashboardScreen(
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(),
    listState: LazyListState = rememberLazyListState(),
    summary: ThreatSummary,
    hourlyBlocks: List<HourlyCount>,
    topDomains: List<TopDomain>,
    onClear: () -> Unit = {},
) {
    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(contentPadding)
            .padding(horizontal = 12.dp),
        state = listState,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // Summary cards
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "Today",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 8.dp)
                )
                androidx.compose.material3.IconButton(onClick = onClear) {
                    Icon(
                        Icons.Default.DeleteSweep,
                        contentDescription = "Clear logs",
                        tint = MaterialTheme.colorScheme.outline,
                    )
                }
            }
        }

        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                SummaryCard(
                    modifier = Modifier.weight(1f),
                    label = "Blocked",
                    value = summary.totalBlocked.toString(),
                    icon = Icons.Default.Block,
                    color = Color(0xFFB71C1C),
                )
                SummaryCard(
                    modifier = Modifier.weight(1f),
                    label = "AI Blocks",
                    value = summary.aiBlocks.toString(),
                    icon = Icons.Default.Psychology,
                    color = Color(0xFF4A148C),
                )
            }
        }

        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                SummaryCard(
                    modifier = Modifier.weight(1f),
                    label = "Trackers",
                    value = summary.trackerFlags.toString(),
                    icon = Icons.Default.Visibility,
                    color = Color(0xFFE65100),
                )
                SummaryCard(
                    modifier = Modifier.weight(1f),
                    label = "Tunneling",
                    value = summary.tunnelingBlocks.toString(),
                    icon = Icons.Default.Security,
                    color = Color(0xFF1B5E20),
                )
            }
        }

        // Timeline chart
        if (hourlyBlocks.isNotEmpty()) {
            item {
                Text(
                    "Blocks — Last 24 Hours",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 8.dp)
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
                    BlocksChart(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(180.dp)
                            .padding(16.dp),
                        data = hourlyBlocks,
                        barColor = barColor,
                        labelColor = labelColor,
                        textMeasurer = textMeasurer,
                    )
                }
            }
        }

        // Top threats
        if (topDomains.isNotEmpty()) {
            item {
                Text(
                    "Top Threats",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }

            items(topDomains) { td ->
                TopDomainCard(td)
            }
        }

        item { Spacer(Modifier.height(24.dp)) }
    }
}

@Composable
private fun SummaryCard(
    modifier: Modifier = Modifier,
    label: String,
    value: String,
    icon: ImageVector,
    color: Color,
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = color)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = Color.White.copy(alpha = 0.8f),
                    modifier = Modifier.size(20.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    label,
                    color = Color.White.copy(alpha = 0.8f),
                    fontSize = 13.sp,
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(
                value,
                color = Color.White,
                fontSize = 32.sp,
                fontWeight = FontWeight.Bold,
            )
        }
    }
}

@Composable
private fun BlocksChart(
    modifier: Modifier,
    data: List<HourlyCount>,
    barColor: Color,
    labelColor: Color,
    textMeasurer: TextMeasurer,
) {
    Canvas(modifier = modifier) {
        if (data.isEmpty()) return@Canvas

        val maxCount = data.maxOf { it.count }.coerceAtLeast(1)
        // Cap bar width so single data points don't fill the whole chart
        val slotWidth = (size.width / data.size.coerceAtLeast(1)).coerceAtMost(60.dp.toPx())
        val barWidth = slotWidth * 0.7f
        val chartHeight = size.height - 36.dp.toPx() // room for labels below + count above
        val topPadding = 16.dp.toPx() // room for count labels above bars
        val fmt = SimpleDateFormat("HH:mm", Locale.getDefault())

        data.forEachIndexed { index, hourly ->
            val barHeight = (hourly.count.toFloat() / maxCount) * (chartHeight - topPadding)
            val x = index * slotWidth + (slotWidth - barWidth) / 2

            // Bar
            drawRect(
                color = barColor,
                topLeft = Offset(x, chartHeight - barHeight),
                size = Size(barWidth, barHeight),
            )

            // Count label above bar
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

            // Hour label below bar
            if (data.size <= 12 || index % 3 == 0) {
                val label = fmt.format(Date(hourly.hourTimestamp))
                val textResult = textMeasurer.measure(
                    label,
                    style = TextStyle(fontSize = 9.sp, color = labelColor)
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

@Composable
private fun TopDomainCard(td: TopDomain) {
    val sourceLabel = when (td.source) {
        "ai" -> "AI DGA"
        "blocklist" -> "Blocklist"
        "tunneling" -> "Tunneling"
        "tracker" -> "Tracker"
        "beaconing" -> "Beaconing"
        else -> td.source
    }

    val sourceColor = when (td.source) {
        "ai" -> Color(0xFF4A148C)
        "blocklist" -> Color(0xFFB71C1C)
        "tunneling" -> Color(0xFF1B5E20)
        "tracker" -> Color(0xFFE65100)
        "beaconing" -> Color(0xFF0D47A1)
        else -> MaterialTheme.colorScheme.onSurface
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    td.domain,
                    fontWeight = FontWeight.Medium,
                    fontSize = 13.sp,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        sourceLabel,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = sourceColor,
                    )
                    if (td.maxConfidence > 0f) {
                        Text(
                            " (${(td.maxConfidence * 100).toInt()}%)",
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.outline,
                        )
                    }
                    Text(
                        " — ${td.action}",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.outline,
                    )
                }
            }
            Text(
                td.count.toString(),
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold,
                color = sourceColor,
            )
        }
    }
}
