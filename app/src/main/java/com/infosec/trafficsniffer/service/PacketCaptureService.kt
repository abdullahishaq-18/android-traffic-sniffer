package com.infosec.trafficsniffer.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.infosec.trafficsniffer.data.PacketDatabase
import com.infosec.trafficsniffer.data.PacketEntity
import com.infosec.trafficsniffer.parser.PacketProcessor
import com.infosec.trafficsniffer.security.SecurityAnalyzer
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

class PacketCaptureService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val packetProcessor = PacketProcessor()
    
    companion object {
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val MTU = 1500
        private const val NOTIFICATION_CHANNEL_ID = "traffic_sniffer_channel"
        private const val NOTIFICATION_ID = 1
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification())
        setupVPN()
        startPacketCapture()
        return START_STICKY
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "Traffic Capture Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Captures and analyzes network traffic"
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("Traffic Sniffer Active")
            .setContentText("Capturing network traffic...")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
    
    private fun setupVPN() {
        vpnInterface = Builder()
            .setSession("TrafficSniffer")
            .addAddress(VPN_ADDRESS, 32)
            .addRoute(VPN_ROUTE, 0)
            .setMtu(MTU)
            .setBlocking(false)
            .establish()
    }
    
    private fun startPacketCapture() {
        serviceScope.launch {
            val inputStream = FileInputStream(vpnInterface?.fileDescriptor)
            val outputStream = FileOutputStream(vpnInterface?.fileDescriptor)
            val buffer = ByteBuffer.allocate(MTU)
            
            while (isActive) {
                try {
                    val length = inputStream.channel.read(buffer)
                    if (length > 0) {
                        buffer.flip()
                        val packet = ByteArray(length)
                        buffer.get(packet)
                        
                        // Process packet asynchronously
                        launch {
                            processPacket(packet)
                        }
                        
                        // Forward packet to destination
                        buffer.clear()
                        buffer.put(packet)
                        buffer.flip()
                        outputStream.channel.write(buffer)
                        buffer.clear()
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
        }
    }
    
    private suspend fun processPacket(packet: ByteArray) {
        val parsedPacket = packetProcessor.parse(packet)
        parsedPacket?.let {
            // Analyze for vulnerabilities
            val vulnerabilities = SecurityAnalyzer.analyze(it)
            
            // Convert to database entity
            val packetEntity = PacketEntity(
                timestamp = it.timestamp,
                protocol = it.protocol.name,
                sourceIP = it.sourceIP,
                destIP = it.destIP,
                sourcePort = it.sourcePort,
                destPort = it.destPort,
                payload = it.payload,
                isEncrypted = it.isEncrypted,
                vulnerabilityCount = vulnerabilities.size
            )
            
            // Store in database
            PacketDatabase.getInstance(this).packetDao().insert(packetEntity)
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
        vpnInterface?.close()
    }
}