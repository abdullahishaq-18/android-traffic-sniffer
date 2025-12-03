package com.infosec.trafficsniffer.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.infosec.trafficsniffer.data.PacketDatabase
import com.infosec.trafficsniffer.data.PacketEntity
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class TrafficStatistics(
    val totalPackets: Int = 0,
    val unencryptedPackets: Int = 0,
    val vulnerabilities: Int = 0,
    val httpRequests: Int = 0,
    val httpsRequests: Int = 0,
    val encryptionRate: Int = 0
)

class TrafficViewModel(application: Application) : AndroidViewModel(application) {
    
    private val database = PacketDatabase.getInstance(application)
    private val packetDao = database.packetDao()
    
    private val _isCapturing = MutableStateFlow(false)
    val isCapturing: StateFlow<Boolean> = _isCapturing.asStateFlow()
    
    private val _packets = MutableStateFlow<List<PacketEntity>>(emptyList())
    val packets: StateFlow<List<PacketEntity>> = _packets.asStateFlow()
    
    private val _vulnerablePackets = MutableStateFlow<List<PacketEntity>>(emptyList())
    val vulnerablePackets: StateFlow<List<PacketEntity>> = _vulnerablePackets.asStateFlow()
    
    private val _statistics = MutableStateFlow(TrafficStatistics())
    val statistics: StateFlow<TrafficStatistics> = _statistics.asStateFlow()
    
    init {
        startDataRefresh()
    }
    
    fun startCapture() {
        _isCapturing.value = true
    }
    
    fun stopCapture() {
        _isCapturing.value = false
    }
    
    private fun startDataRefresh() {
        viewModelScope.launch {
            while (true) {
                if (_isCapturing.value) {
                    refreshData()
                }
                delay(1000) // Refresh every second
            }
        }
    }
    
    private suspend fun refreshData() {
        try {
            // Get recent packets
            _packets.value = packetDao.getRecentPackets(100)
            
            // Get vulnerable packets
            _vulnerablePackets.value = packetDao.getVulnerablePackets()
            
            // Calculate statistics
            val totalPackets = packetDao.getTotalPacketCount()
            val unencryptedCount = packetDao.getUnencryptedCount()
            val vulnerableCount = packetDao.getVulnerableCount()
            
            val allPackets = _packets.value
            val httpCount = allPackets.count { it.protocol == "HTTP" }
            val httpsCount = allPackets.count { it.protocol == "HTTPS" }
            
            val encryptionRate = if (totalPackets > 0) {
                ((totalPackets - unencryptedCount) * 100 / totalPackets)
            } else {
                100
            }
            
            _statistics.value = TrafficStatistics(
                totalPackets = totalPackets,
                unencryptedPackets = unencryptedCount,
                vulnerabilities = vulnerableCount,
                httpRequests = httpCount,
                httpsRequests = httpsCount,
                encryptionRate = encryptionRate
            )
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
    
    fun clearData() {
        viewModelScope.launch {
            val cutoffTime = System.currentTimeMillis() - (24 * 60 * 60 * 1000) // 24 hours ago
            packetDao.deleteOldPackets(cutoffTime)
            refreshData()
        }
    }
}