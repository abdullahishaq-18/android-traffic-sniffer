package com.infosec.trafficsniffer.data

import android.content.Context
import androidx.room.*

@Entity(tableName = "packets")
data class PacketEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val timestamp: Long,
    val protocol: String,
    val sourceIP: String,
    val destIP: String,
    val sourcePort: Int,
    val destPort: Int,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val payload: ByteArray,
    val isEncrypted: Boolean,
    val vulnerabilityCount: Int,
    val appName: String? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        
        other as PacketEntity
        
        if (id != other.id) return false
        if (timestamp != other.timestamp) return false
        if (protocol != other.protocol) return false
        if (sourceIP != other.sourceIP) return false
        if (destIP != other.destIP) return false
        if (sourcePort != other.sourcePort) return false
        if (destPort != other.destPort) return false
        if (!payload.contentEquals(other.payload)) return false
        if (isEncrypted != other.isEncrypted) return false
        if (vulnerabilityCount != other.vulnerabilityCount) return false
        if (appName != other.appName) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + protocol.hashCode()
        result = 31 * result + sourceIP.hashCode()
        result = 31 * result + destIP.hashCode()
        result = 31 * result + sourcePort
        result = 31 * result + destPort
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + isEncrypted.hashCode()
        result = 31 * result + vulnerabilityCount
        result = 31 * result + (appName?.hashCode() ?: 0)
        return result
    }
}

@Dao
interface PacketDao {
    @Insert
    suspend fun insert(packet: PacketEntity)
    
    @Query("SELECT * FROM packets ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getRecentPackets(limit: Int = 100): List<PacketEntity>
    
    @Query("SELECT * FROM packets WHERE isEncrypted = 0 ORDER BY timestamp DESC")
    suspend fun getUnencryptedPackets(): List<PacketEntity>
    
    @Query("SELECT * FROM packets WHERE vulnerabilityCount > 0 ORDER BY timestamp DESC")
    suspend fun getVulnerablePackets(): List<PacketEntity>
    
    @Query("DELETE FROM packets WHERE timestamp < :cutoffTime")
    suspend fun deleteOldPackets(cutoffTime: Long)
    
    @Query("SELECT COUNT(*) FROM packets")
    suspend fun getTotalPacketCount(): Int
    
    @Query("SELECT COUNT(*) FROM packets WHERE isEncrypted = 0")
    suspend fun getUnencryptedCount(): Int
    
    @Query("SELECT COUNT(*) FROM packets WHERE vulnerabilityCount > 0")
    suspend fun getVulnerableCount(): Int
}

@Database(entities = [PacketEntity::class], version = 1, exportSchema = false)
abstract class PacketDatabase : RoomDatabase() {
    abstract fun packetDao(): PacketDao
    
    companion object {
        @Volatile
        private var INSTANCE: PacketDatabase? = null
        
        fun getInstance(context: Context): PacketDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    PacketDatabase::class.java,
                    "packet_database"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}