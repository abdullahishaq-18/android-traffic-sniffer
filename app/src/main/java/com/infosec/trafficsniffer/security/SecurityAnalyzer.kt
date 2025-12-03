package com.infosec.trafficsniffer.security

import com.infosec.trafficsniffer.parser.ParsedPacket
import com.infosec.trafficsniffer.parser.Protocol

data class SecurityVulnerability(
    val type: VulnerabilityType,
    val severity: Severity,
    val description: String,
    val evidence: String,
    val recommendation: String
)

enum class VulnerabilityType {
    UNENCRYPTED_CREDENTIALS,
    PLAINTEXT_API_KEY,
    SENSITIVE_DATA_EXPOSURE,
    WEAK_ENCRYPTION,
    MISSING_CERTIFICATE_VALIDATION,
    INSECURE_HTTP
}

enum class Severity {
    CRITICAL, HIGH, MEDIUM, LOW
}

object SecurityAnalyzer {
    
    private val credentialPatterns = listOf(
        Regex("password[\"'\\s:=]+([^\"'\\s&]+)", RegexOption.IGNORE_CASE),
        Regex("passwd[\"'\\s:=]+([^\"'\\s&]+)", RegexOption.IGNORE_CASE),
        Regex("pwd[\"'\\s:=]+([^\"'\\s&]+)", RegexOption.IGNORE_CASE),
        Regex("username[\"'\\s:=]+([^\"'\\s&]+)", RegexOption.IGNORE_CASE),
        Regex("email[\"'\\s:=]+([^@\\s]+@[^\\s\"'&]+)", RegexOption.IGNORE_CASE)
    )
    
    private val apiKeyPatterns = listOf(
        Regex("api[_-]?key[\"'\\s:=]+([a-zA-Z0-9_-]{20,})", RegexOption.IGNORE_CASE),
        Regex("apikey[\"'\\s:=]+([a-zA-Z0-9_-]{20,})", RegexOption.IGNORE_CASE),
        Regex("access[_-]?token[\"'\\s:=]+([a-zA-Z0-9_-]{20,})", RegexOption.IGNORE_CASE),
        Regex("bearer\\s+([a-zA-Z0-9_-]{20,})", RegexOption.IGNORE_CASE),
        Regex("authorization[\"'\\s:]+([a-zA-Z0-9+/=]{20,})", RegexOption.IGNORE_CASE)
    )
    
    private val sensitiveDataPatterns = listOf(
        Regex("\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"), // Credit card
        Regex("\\b\\d{3}-\\d{2}-\\d{4}\\b"), // SSN
        Regex("\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b", RegexOption.IGNORE_CASE)
    )
    
    suspend fun analyze(packet: ParsedPacket): List<SecurityVulnerability> {
        val vulnerabilities = mutableListOf<SecurityVulnerability>()
        
        // Check for unencrypted HTTP traffic
        if (packet.protocol == Protocol.HTTP) {
            vulnerabilities.add(
                SecurityVulnerability(
                    type = VulnerabilityType.INSECURE_HTTP,
                    severity = Severity.HIGH,
                    description = "Unencrypted HTTP traffic detected",
                    evidence = "${packet.sourceIP}:${packet.sourcePort} → ${packet.destIP}:${packet.destPort}",
                    recommendation = "Use HTTPS with proper certificate validation"
                )
            )
            
            val payloadString = String(packet.payload, Charsets.UTF_8)
            
            // Check for credentials in plaintext
            credentialPatterns.forEach { pattern ->
                pattern.findAll(payloadString).forEach { match ->
                    vulnerabilities.add(
                        SecurityVulnerability(
                            type = VulnerabilityType.UNENCRYPTED_CREDENTIALS,
                            severity = Severity.CRITICAL,
                            description = "Credentials transmitted in plaintext",
                            evidence = match.value.take(50) + "...",
                            recommendation = "Always use HTTPS for authentication endpoints"
                        )
                    )
                }
            }
            
            // Check for API keys
            apiKeyPatterns.forEach { pattern ->
                pattern.findAll(payloadString).forEach { match ->
                    vulnerabilities.add(
                        SecurityVulnerability(
                            type = VulnerabilityType.PLAINTEXT_API_KEY,
                            severity = Severity.CRITICAL,
                            description = "API key exposed in plaintext HTTP request",
                            evidence = "Key: ${match.groupValues[1].take(20)}...",
                            recommendation = "Use HTTPS and consider OAuth 2.0 or API Gateway"
                        )
                    )
                }
            }
            
            // Check for sensitive data
            sensitiveDataPatterns.forEach { pattern ->
                if (pattern.containsMatchIn(payloadString)) {
                    vulnerabilities.add(
                        SecurityVulnerability(
                            type = VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                            severity = Severity.HIGH,
                            description = "Sensitive data transmitted without encryption",
                            evidence = "Pattern matched in payload",
                            recommendation = "Encrypt all sensitive data and use HTTPS"
                        )
                    )
                }
            }
        }
        
        return vulnerabilities
    }
}