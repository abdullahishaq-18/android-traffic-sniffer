package com.infosec.trafficsniffer.parser

import java.nio.ByteBuffer

data class ParsedPacket(
    val timestamp: Long,
    val protocol: Protocol,
    val sourceIP: String,
    val destIP: String,
    val sourcePort: Int,
    val destPort: Int,
    val payload: ByteArray,
    val isEncrypted: Boolean
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        
        other as ParsedPacket
        
        if (timestamp != other.timestamp) return false
        if (protocol != other.protocol) return false
        if (sourceIP != other.sourceIP) return false
        if (destIP != other.destIP) return false
        if (sourcePort != other.sourcePort) return false
        if (destPort != other.destPort) return false
        if (!payload.contentEquals(other.payload)) return false
        if (isEncrypted != other.isEncrypted) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = timestamp.hashCode()
        result = 31 * result + protocol.hashCode()
        result = 31 * result + sourceIP.hashCode()
        result = 31 * result + destIP.hashCode()
        result = 31 * result + sourcePort
        result = 31 * result + destPort
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + isEncrypted.hashCode()
        return result
    }
}

enum class Protocol {
    TCP, UDP, HTTP, HTTPS, DNS, UNKNOWN
}

class PacketProcessor {
    
    fun parse(packet: ByteArray): ParsedPacket? {
        return try {
            val buffer = ByteBuffer.wrap(packet)
            val ipHeader = parseIPHeader(buffer)
            
            when (ipHeader.protocol) {
                6 -> parseTCPPacket(buffer, ipHeader) // TCP
                17 -> parseUDPPacket(buffer, ipHeader) // UDP
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }
    
    private fun parseIPHeader(buffer: ByteBuffer): IPHeader {
        val versionAndIHL = buffer.get().toInt() and 0xFF
        val version = versionAndIHL shr 4
        val ihl = (versionAndIHL and 0x0F) * 4
        
        buffer.position(buffer.position() + 8) // Skip to protocol
        val protocol = buffer.get().toInt() and 0xFF
        
        buffer.position(buffer.position() + 2) // Skip checksum
        
        val sourceIP = readIPAddress(buffer)
        val destIP = readIPAddress(buffer)
        
        return IPHeader(version, ihl, protocol, sourceIP, destIP)
    }
    
    private fun parseTCPPacket(buffer: ByteBuffer, ipHeader: IPHeader): ParsedPacket {
        buffer.position(ipHeader.headerLength)
        
        val sourcePort = buffer.short.toInt() and 0xFFFF
        val destPort = buffer.short.toInt() and 0xFFFF
        
        buffer.position(buffer.position() + 8) // Skip sequence and ack numbers
        
        val dataOffset = ((buffer.get().toInt() and 0xFF) shr 4) * 4
        buffer.position(ipHeader.headerLength + dataOffset)
        
        val payload = ByteArray(buffer.remaining())
        buffer.get(payload)
        
        val protocol = detectProtocol(payload, destPort)
        val isEncrypted = protocol == Protocol.HTTPS || isSSLTLS(payload)
        
        return ParsedPacket(
            timestamp = System.currentTimeMillis(),
            protocol = protocol,
            sourceIP = ipHeader.sourceIP,
            destIP = ipHeader.destIP,
            sourcePort = sourcePort,
            destPort = destPort,
            payload = payload,
            isEncrypted = isEncrypted
        )
    }
    
    private fun parseUDPPacket(buffer: ByteBuffer, ipHeader: IPHeader): ParsedPacket {
        buffer.position(ipHeader.headerLength)
        
        val sourcePort = buffer.short.toInt() and 0xFFFF
        val destPort = buffer.short.toInt() and 0xFFFF
        
        buffer.position(buffer.position() + 4) // Skip length and checksum
        
        val payload = ByteArray(buffer.remaining())
        buffer.get(payload)
        
        return ParsedPacket(
            timestamp = System.currentTimeMillis(),
            protocol = if (destPort == 53) Protocol.DNS else Protocol.UDP,
            sourceIP = ipHeader.sourceIP,
            destIP = ipHeader.destIP,
            sourcePort = sourcePort,
            destPort = destPort,
            payload = payload,
            isEncrypted = false
        )
    }
    
    private fun detectProtocol(payload: ByteArray, port: Int): Protocol {
        return when {
            port == 443 -> Protocol.HTTPS
            port == 80 || isHTTPRequest(payload) -> Protocol.HTTP
            else -> Protocol.TCP
        }
    }
    
    private fun isHTTPRequest(payload: ByteArray): Boolean {
        if (payload.size < 4) return false
        val httpMethods = listOf("GET ", "POST", "PUT ", "DELE", "HEAD", "PATC")
        val payloadString = String(payload.take(4).toByteArray(), Charsets.UTF_8)
        return httpMethods.any { payloadString.startsWith(it) }
    }
    
    private fun isSSLTLS(payload: ByteArray): Boolean {
        if (payload.size < 3) return false
        val contentType = payload[0].toInt() and 0xFF
        val version = (payload[1].toInt() and 0xFF shl 8) or (payload[2].toInt() and 0xFF)
        
        // SSL/TLS content types: 20-23
        // TLS versions: 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2, 1.3)
        return contentType in 20..23 && version in 0x0301..0x0304
    }
    
    private fun readIPAddress(buffer: ByteBuffer): String {
        return "${buffer.get().toInt() and 0xFF}.${buffer.get().toInt() and 0xFF}." +
               "${buffer.get().toInt() and 0xFF}.${buffer.get().toInt() and 0xFF}"
    }
    
    data class IPHeader(
        val version: Int,
        val headerLength: Int,
        val protocol: Int,
        val sourceIP: String,
        val destIP: String
    )
}