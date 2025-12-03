package com.infosec.trafficsniffer.ui

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.infosec.trafficsniffer.service.PacketCaptureService
import com.infosec.trafficsniffer.ui.theme.TrafficSnifferTheme
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : ComponentActivity() {
    
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVPNService()
        }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        setContent {
            TrafficSnifferTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainScreen(
                        onStartCapture = { requestVPNPermission() },
                        onStopCapture = { stopVPNService() }
                    )
                }
            }
        }
    }
    
    private fun requestVPNPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVPNService()
        }
    }
    
    private fun startVPNService() {
        val serviceIntent = Intent(this, PacketCaptureService::class.java)
        startService(serviceIntent)
    }
    
    private fun stopVPNService() {
        val serviceIntent = Intent(this, PacketCaptureService::class.java)
        stopService(serviceIntent)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    onStartCapture: () -> Unit,
    onStopCapture: () -> Unit,
    viewModel: TrafficViewModel = viewModel()
) {
    var selectedTab by remember { mutableStateOf(0) }
    val isCapturing by viewModel.isCapturing.collectAsState()
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Traffic Sniffer") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // Control Panel
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp)
                ) {
                    Text(
                        text = if (isCapturing) "Capturing Traffic..." else "Ready to Capture",
                        style = MaterialTheme.typography.titleMedium,
                        color = if (isCapturing) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
                    )
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    Button(
                        onClick = {
                            if (isCapturing) {
                                onStopCapture()
                                viewModel.stopCapture()
                            } else {
                                onStartCapture()
                                viewModel.startCapture()
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (isCapturing) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                        )
                    ) {
                        Text(if (isCapturing) "Stop Capture" else "Start Capture")
                    }
                }
            }
            
            // Tabs
            TabRow(
                selectedTabIndex = selectedTab,
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            ) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = { Text("All Packets") }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = { Text("Vulnerabilities") }
                )
                Tab(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    text = { Text("Statistics") }
                )
            }
            
            // Content based on selected tab
            when (selectedTab) {
                0 -> PacketListView(viewModel)
                1 -> VulnerabilityListView(viewModel)
                2 -> StatisticsView(viewModel)
            }
        }
    }
}

@Composable
fun PacketListView(viewModel: TrafficViewModel) {
    val packets by viewModel.packets.collectAsState()
    
    if (packets.isEmpty()) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = androidx.compose.ui.Alignment.Center
        ) {
            Text(
                text = "No packets captured yet",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    } else {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(packets) { packet ->
                PacketCard(
                    protocol = packet.protocol,
                    source = "${packet.sourceIP}:${packet.sourcePort}",
                    destination = "${packet.destIP}:${packet.destPort}",
                    isEncrypted = packet.isEncrypted,
                    timestamp = packet.timestamp,
                    vulnerabilityCount = packet.vulnerabilityCount
                )
            }
        }
    }
}

@Composable
fun PacketCard(
    protocol: String,
    source: String,
    destination: String,
    isEncrypted: Boolean,
    timestamp: Long,
    vulnerabilityCount: Int
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when {
                vulnerabilityCount > 0 -> Color(0xFFFFEBEE)
                !isEncrypted -> Color(0xFFFFF3E0)
                else -> MaterialTheme.colorScheme.surfaceVariant
            }
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = protocol,
                        style = MaterialTheme.typography.labelLarge,
                        color = if (isEncrypted) Color(0xFF4CAF50) else Color(0xFFFF5722)
                    )
                    if (vulnerabilityCount > 0) {
                        Surface(
                            color = Color(0xFFD32F2F),
                            shape = MaterialTheme.shapes.small
                        ) {
                            Text(
                                text = "$vulnerabilityCount",
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelSmall,
                                color = Color.White
                            )
                        }
                    }
                }
                Text(
                    text = formatTimestamp(timestamp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "$source → $destination",
                style = MaterialTheme.typography.bodyMedium
            )
            if (!isEncrypted) {
                Text(
                    text = "⚠️ UNENCRYPTED",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(0xFFFF5722)
                )
            }
        }
    }
}

@Composable
fun VulnerabilityListView(viewModel: TrafficViewModel) {
    val vulnerablePackets by viewModel.vulnerablePackets.collectAsState()
    
    if (vulnerablePackets.isEmpty()) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = androidx.compose.ui.Alignment.Center
        ) {
            Column(horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally) {
                Text(
                    text = "✅",
                    style = MaterialTheme.typography.displayMedium
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "No vulnerabilities detected",
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    } else {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(vulnerablePackets) { packet ->
                VulnerabilityCard(
                    protocol = packet.protocol,
                    source = "${packet.sourceIP}:${packet.sourcePort}",
                    destination = "${packet.destIP}:${packet.destPort}",
                    vulnerabilityCount = packet.vulnerabilityCount,
                    timestamp = packet.timestamp
                )
            }
        }
    }
}

@Composable
fun VulnerabilityCard(
    protocol: String,
    source: String,
    destination: String,
    vulnerabilityCount: Int,
    timestamp: Long
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFFFFEBEE)
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "⚠️",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        text = "$vulnerabilityCount Vulnerabilit${if (vulnerabilityCount > 1) "ies" else "y"}",
                        style = MaterialTheme.typography.titleSmall,
                        color = Color(0xFFD32F2F)
                    )
                }
                Text(
                    text = formatTimestamp(timestamp),
                    style = MaterialTheme.typography.bodySmall
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = protocol,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary
            )
            Text(
                text = "$source → $destination",
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
fun StatisticsView(viewModel: TrafficViewModel) {
    val stats by viewModel.statistics.collectAsState()
    
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            StatCard(
                label = "Total Packets Captured",
                value = stats.totalPackets.toString(),
                icon = "📦"
            )
        }
        item {
            StatCard(
                label = "Unencrypted Packets",
                value = stats.unencryptedPackets.toString(),
                isWarning = stats.unencryptedPackets > 0,
                icon = "🔓"
            )
        }
        item {
            StatCard(
                label = "Vulnerabilities Found",
                value = stats.vulnerabilities.toString(),
                isWarning = stats.vulnerabilities > 0,
                icon = "⚠️"
            )
        }
        item {
            StatCard(
                label = "HTTP Requests",
                value = stats.httpRequests.toString(),
                icon = "🌐"
            )
        }
        item {
            StatCard(
                label = "HTTPS Requests",
                value = stats.httpsRequests.toString(),
                icon = "🔒"
            )
        }
        item {
            StatCard(
                label = "Encryption Rate",
                value = "${stats.encryptionRate}%",
                isWarning = stats.encryptionRate < 80,
                icon = "🛡️"
            )
        }
    }
}

@Composable
fun StatCard(label: String, value: String, isWarning: Boolean = false, icon: String = "") {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (isWarning) Color(0xFFFFEBEE) else MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = label,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = value,
                    style = MaterialTheme.typography.headlineMedium,
                    color = if (isWarning) Color(0xFFD32F2F) else MaterialTheme.colorScheme.onSurface
                )
            }
            if (icon.isNotEmpty()) {
                Text(
                    text = icon,
                    style = MaterialTheme.typography.displaySmall
                )
            }
        }
    }
}

fun formatTimestamp(timestamp: Long): String {
    val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    return sdf.format(Date(timestamp))
}