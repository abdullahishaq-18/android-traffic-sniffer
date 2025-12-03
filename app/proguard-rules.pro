# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.

# Keep Room database entities
-keep class com.infosec.trafficsniffer.data.** { *; }

# Keep Kotlin Coroutines
-keepclassmembernames class kotlinx.** {
    volatile <fields>;
}

# Keep security analyzer patterns
-keep class com.infosec.trafficsniffer.security.** { *; }