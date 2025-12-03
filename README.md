# Android Traffic Sniffer - Information Security Project

[![Android](https://img.shields.io/badge/Platform-Android-green.svg)](https://www.android.com/)
[![Kotlin](https://img.shields.io/badge/Language-Kotlin-blue.svg)](https://kotlinlang.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A comprehensive Android application that captures and analyzes network traffic to demonstrate insecure API vulnerabilities and showcase information security expertise.

## 🎯 Project Overview

This project demonstrates advanced information security concepts by:

- **Intercepting network traffic** without requiring root access using Android's VpnService API
- **Analyzing HTTP/HTTPS protocols** to identify unencrypted data transmission
- **Detecting insecure API patterns** including plaintext credentials, API keys, and sensitive data
- **Providing real-time security insights** with detailed packet analysis
- **Showcasing mitigation strategies** for common mobile security vulnerabilities

## 🔒 Key Security Concepts Demonstrated

- Man-in-the-Middle (MITM) attack simulation
- SSL/TLS verification bypass detection
- Unencrypted data transmission identification
- API security vulnerability assessment
- Network protocol analysis and packet inspection
- Mobile application security testing methodologies

## 🏛️ Architecture

### System Architecture

The application consists of three primary layers:

1. **Capture Layer** - VPN-based packet interception using Android VpnService
2. **Analysis Layer** - Protocol parsing and security vulnerability detection
3. **Presentation Layer** - Real-time traffic visualization with Jetpack Compose

### Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Kotlin |
| Minimum SDK | Android 7.0 (API 24) |
| Target SDK | Android 14 (API 34) |
| Architecture | MVVM + Clean Architecture |
| Concurrency | Kotlin Coroutines |
| UI Framework | Jetpack Compose + Material Design 3 |
| Database | Room Database |
| Packet Parsing | Custom IP/TCP/UDP/HTTP Parser |

## 🐛 Vulnerability Detection Capabilities

### 1. Plaintext Credential Detection
- Username/password in POST data
- Email addresses in authentication requests
- Session tokens in query parameters

### 2. API Key Exposure
- API keys in HTTP headers
- Bearer tokens in Authorization headers
- Access tokens in request bodies

### 3. Sensitive Data Leakage
- Credit card numbers (PAN)
- Social Security Numbers
- Personal Identifiable Information (PII)

### 4. Protocol Security Analysis
- HTTP vs HTTPS usage patterns
- SSL/TLS version detection
- Certificate validation bypass indicators

## 🚀 Getting Started

### Prerequisites

- Android Studio Hedgehog (2023.1.1) or later
- JDK 17 or later
- Android SDK with API 24-34
- Gradle 8.2+

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/abdullahishaq-18/android-traffic-sniffer.git
   cd android-traffic-sniffer
   ```

2. **Open in Android Studio**
   - Open Android Studio
   - Select "Open an Existing Project"
   - Navigate to the cloned directory
   - Wait for Gradle sync to complete

3. **Build the project**
   ```bash
   ./gradlew build
   ```

4. **Run on device/emulator**
   - Connect an Android device with USB debugging enabled, or start an emulator
   - Click "Run" in Android Studio or use:
   ```bash
   ./gradlew installDebug
   ```

## 📱 Usage

### Starting Packet Capture

1. Launch the Traffic Sniffer app
2. Grant VPN permission when prompted
3. Click "Start Capture" button
4. The app will begin intercepting all network traffic from your device

### Viewing Results

**All Packets Tab**
- View all captured network packets in real-time
- Color-coded indicators for encrypted/unencrypted traffic
- Timestamp, protocol, source, and destination information

**Vulnerabilities Tab**
- Lists only packets with detected security vulnerabilities
- Shows vulnerability count and severity
- Provides detailed evidence and recommendations

**Statistics Tab**
- Total packets captured
- Unencrypted packet count
- Vulnerability statistics
- HTTP vs HTTPS breakdown
- Encryption rate percentage

## 🧪 Testing with Vulnerable App

To demonstrate the sniffer's capabilities, you can create a simple vulnerable test app:

```kotlin
// Example: Insecure HTTP login
val url = "http://api.example.com/login"
val formBody = FormBody.Builder()
    .add("username", "testuser")
    .add("password", "password123")
    .build()

val request = Request.Builder()
    .url(url)
    .post(formBody)
    .build()
```

The sniffer will detect:
- ⚠️ Unencrypted HTTP traffic
- ⚠️ Plaintext credentials (username and password)
- ⚠️ CRITICAL severity vulnerability

## 🛡️ Security Implications

### Educational Purpose Statement

This application is designed **exclusively** for:

- Educational demonstrations of network security concepts
- Security research and vulnerability assessment
- Testing applications you own or have permission to test
- Information security training and awareness

### ⚠️ Legal and Ethical Guidelines

**WARNING:** Unauthorized interception of network traffic may be illegal in your jurisdiction.

This tool should **ONLY** be used:

1. On devices you own
2. On networks you control or have explicit permission to monitor
3. For educational and research purposes
4. In controlled testing environments

### Responsible Disclosure

When vulnerabilities are discovered:

1. Document findings thoroughly
2. Report to application developers privately
3. Allow reasonable time for patches
4. Follow coordinated disclosure principles

## 📚 Project Structure

```
android-traffic-sniffer/
├── app/
│   ├── src/
│   │   ├── main/
│   │   │   ├── java/com/infosec/trafficsniffer/
│   │   │   │   ├── service/
│   │   │   │   │   └── PacketCaptureService.kt    # VPN service implementation
│   │   │   │   ├── parser/
│   │   │   │   │   └── PacketProcessor.kt         # Protocol parser
│   │   │   │   ├── security/
│   │   │   │   │   └── SecurityAnalyzer.kt        # Vulnerability detection
│   │   │   │   ├── data/
│   │   │   │   │   └── PacketDatabase.kt          # Room database
│   │   │   │   └── ui/
│   │   │   │       ├── MainActivity.kt            # Main UI
│   │   │   │       ├── TrafficViewModel.kt        # ViewModel
│   │   │   │       └── theme/                     # Compose theming
│   │   │   └── AndroidManifest.xml
│   └── build.gradle.kts
├── build.gradle.kts
├── settings.gradle.kts
└── README.md
```

## 🧩 Advanced Features

### Implemented
- ✅ Non-root VPN-based packet capture
- ✅ Real-time protocol analysis (TCP/UDP/HTTP/HTTPS/DNS)
- ✅ Automated vulnerability detection with pattern matching
- ✅ Material Design 3 UI with dark mode support
- ✅ Room database for packet storage
- ✅ Coroutine-based asynchronous processing
- ✅ Statistics and analytics dashboard

### Potential Extensions
- 🚧 PCAP export for Wireshark analysis
- 🚧 Machine learning-based anomaly detection
- 🚧 Certificate pinning bypass detection
- 🚧 GraphQL/REST API endpoint analysis
- 🚧 Network topology visualization
- 🚧 Multi-device traffic correlation

## 📝 Documentation

For detailed technical documentation, see:

- [Architecture Guide](docs/ARCHITECTURE.md) (Coming soon)
- [API Reference](docs/API.md) (Coming soon)
- [Security Analysis](docs/SECURITY.md) (Coming soon)

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🚀 Author

**Abdullah Ishaq**
- GitHub: [@abdullahishaq-18](https://github.com/abdullahishaq-18)

## 🙏 Acknowledgments

- Android VpnService API documentation
- OWASP Mobile Security Project
- RFC 791 (Internet Protocol) and RFC 793 (TCP)
- OWASP API Security Top 10

## 📊 Project Statistics

- **Lines of Code:** ~2,000+
- **Components:** 5 core modules
- **Vulnerability Patterns:** 15+ detection patterns
- **Supported Protocols:** TCP, UDP, HTTP, HTTPS, DNS

---

**⚠️ Disclaimer:** This tool is for educational and authorized security testing only. Unauthorized use may violate laws. Use responsibly and ethically.