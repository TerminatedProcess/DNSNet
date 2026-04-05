package dev.clombardo.dnsnet.blocklogger

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * Persistent threat event log backed by SQLite.
 * Records every DNS decision with source, action, and confidence
 * for dashboard statistics and historical analysis.
 */
class ThreatLog private constructor(context: Context) :
    SQLiteOpenHelper(context, DB_NAME, null, DB_VERSION) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE $TABLE (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                domain TEXT NOT NULL,
                source TEXT NOT NULL,
                action TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0.0
            )
        """)
        db.execSQL("CREATE INDEX idx_timestamp ON $TABLE(timestamp)")
        db.execSQL("CREATE INDEX idx_source ON $TABLE(source)")
        db.execSQL("CREATE INDEX idx_action ON $TABLE(action)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS $TABLE")
        onCreate(db)
    }

    /** Record a threat event. Called from BlockLogger on every DNS decision. */
    fun record(domain: String, source: String, action: String, confidence: Float) {
        val values = ContentValues().apply {
            put("timestamp", System.currentTimeMillis())
            put("domain", domain)
            put("source", source)
            put("action", action)
            put("confidence", confidence)
        }
        writableDatabase.insert(TABLE, null, values)
    }

    /** Summary counts for today. */
    fun todaySummary(): ThreatSummary {
        val startOfDay = startOfToday()
        val db = readableDatabase

        fun countWhere(where: String): Int {
            db.rawQuery(
                "SELECT COUNT(*) FROM $TABLE WHERE timestamp >= ? AND $where",
                arrayOf(startOfDay.toString())
            ).use { c ->
                return if (c.moveToFirst()) c.getInt(0) else 0
            }
        }

        return ThreatSummary(
            totalBlocked = countWhere("action = 'blocked'"),
            aiBlocks = countWhere("action = 'blocked' AND source = 'ai'"),
            tunnelingBlocks = countWhere("action = 'blocked' AND source = 'tunneling'"),
            trackerFlags = countWhere("source = 'tracker'"),
            beaconingFlags = countWhere("source = 'beaconing'"),
            totalAllowed = countWhere("action = 'allowed'"),
            blocklistBlocks = countWhere("action = 'blocked' AND source = 'blocklist'"),
        )
    }

    /** Hourly block counts for the last 24 hours. Returns list of (hour, count). */
    fun hourlyBlocks24h(): List<HourlyCount> {
        val since = System.currentTimeMillis() - 24 * 60 * 60 * 1000L
        val db = readableDatabase
        val result = mutableListOf<HourlyCount>()

        db.rawQuery("""
            SELECT (timestamp / 3600000) * 3600000 AS hour_bucket, COUNT(*) AS cnt
            FROM $TABLE
            WHERE timestamp >= ? AND action = 'blocked'
            GROUP BY hour_bucket
            ORDER BY hour_bucket ASC
        """, arrayOf(since.toString())).use { c ->
            while (c.moveToNext()) {
                result.add(HourlyCount(c.getLong(0), c.getInt(1)))
            }
        }
        return result
    }

    /** Top N most-seen domains with their source and total count. */
    fun topDomains(limit: Int = 10): List<TopDomain> {
        val db = readableDatabase
        val result = mutableListOf<TopDomain>()

        db.rawQuery("""
            SELECT domain, source, action, COUNT(*) AS cnt, MAX(confidence) AS max_conf
            FROM $TABLE
            WHERE action = 'blocked' OR source IN ('tracker', 'beaconing')
            GROUP BY domain
            ORDER BY cnt DESC
            LIMIT ?
        """, arrayOf(limit.toString())).use { c ->
            while (c.moveToNext()) {
                result.add(
                    TopDomain(
                        domain = c.getString(0),
                        source = c.getString(1),
                        action = c.getString(2),
                        count = c.getInt(3),
                        maxConfidence = c.getFloat(4),
                    )
                )
            }
        }
        return result
    }

    /** Purge events older than the given number of days. */
    fun purgeOlderThan(days: Int = 30) {
        val cutoff = System.currentTimeMillis() - days * 24L * 60 * 60 * 1000
        writableDatabase.delete(TABLE, "timestamp < ?", arrayOf(cutoff.toString()))
    }

    /** Clear all events. */
    fun clearAll() {
        writableDatabase.delete(TABLE, null, null)
    }

    private fun startOfToday(): Long {
        val cal = java.util.Calendar.getInstance()
        cal.set(java.util.Calendar.HOUR_OF_DAY, 0)
        cal.set(java.util.Calendar.MINUTE, 0)
        cal.set(java.util.Calendar.SECOND, 0)
        cal.set(java.util.Calendar.MILLISECOND, 0)
        return cal.timeInMillis
    }

    companion object {
        private const val DB_NAME = "threat_log.db"
        private const val DB_VERSION = 1
        private const val TABLE = "events"

        @Volatile
        private var INSTANCE: ThreatLog? = null

        fun getInstance(context: Context): ThreatLog {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: ThreatLog(context.applicationContext).also { INSTANCE = it }
            }
        }
    }
}

data class ThreatSummary(
    val totalBlocked: Int = 0,
    val aiBlocks: Int = 0,
    val tunnelingBlocks: Int = 0,
    val trackerFlags: Int = 0,
    val beaconingFlags: Int = 0,
    val totalAllowed: Int = 0,
    val blocklistBlocks: Int = 0,
)

data class HourlyCount(
    val hourTimestamp: Long,
    val count: Int,
)

data class TopDomain(
    val domain: String,
    val source: String,
    val action: String,
    val count: Int,
    val maxConfidence: Float,
)
