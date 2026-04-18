package dev.clombardo.dnsnet.blocklogger

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * Persistent threat event log backed by SQLite.
 * Records every DNS decision with source, action, and confidence
 * for dashboard statistics and historical analysis.
 * Also stores per-domain user policy overrides (allow/auto/block).
 */
class ThreatLog private constructor(context: Context) :
    SQLiteOpenHelper(context, DB_NAME, null, DB_VERSION) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE $TABLE_EVENTS (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                domain TEXT NOT NULL,
                source TEXT NOT NULL,
                action TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0.0
            )
        """)
        db.execSQL("CREATE INDEX idx_timestamp ON $TABLE_EVENTS(timestamp)")
        db.execSQL("CREATE INDEX idx_source ON $TABLE_EVENTS(source)")
        db.execSQL("CREATE INDEX idx_action ON $TABLE_EVENTS(action)")
        db.execSQL("CREATE INDEX idx_domain ON $TABLE_EVENTS(domain)")

        db.execSQL("""
            CREATE TABLE $TABLE_POLICIES (
                domain TEXT PRIMARY KEY,
                policy TEXT NOT NULL DEFAULT 'auto',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
        """)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) {
            // v1 → v2: add domain_policies table and domain index on events
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS $TABLE_POLICIES (
                    domain TEXT PRIMARY KEY,
                    policy TEXT NOT NULL DEFAULT 'auto',
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """)
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_domain ON $TABLE_EVENTS(domain)")
        }
    }

    // ── Event Recording ──

    fun record(domain: String, source: String, action: String, confidence: Float) {
        val values = ContentValues().apply {
            put("timestamp", System.currentTimeMillis())
            put("domain", domain)
            put("source", source)
            put("action", action)
            put("confidence", confidence)
        }
        writableDatabase.insert(TABLE_EVENTS, null, values)
    }

    // ── Dashboard Summary Queries ──

    fun todaySummary(): ThreatSummary {
        val startOfDay = startOfToday()
        val db = readableDatabase

        fun countWhere(where: String): Int {
            db.rawQuery(
                "SELECT COUNT(*) FROM $TABLE_EVENTS WHERE timestamp >= ? AND $where",
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

    fun hourlyBlocks24h(): List<HourlyCount> {
        val since = System.currentTimeMillis() - 24 * 60 * 60 * 1000L
        val db = readableDatabase
        val result = mutableListOf<HourlyCount>()

        db.rawQuery("""
            SELECT (timestamp / 3600000) * 3600000 AS hour_bucket, COUNT(*) AS cnt
            FROM $TABLE_EVENTS
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

    fun topDomains(limit: Int = 10): List<TopDomain> {
        val db = readableDatabase
        val result = mutableListOf<TopDomain>()

        db.rawQuery("""
            SELECT domain, source, action, COUNT(*) AS cnt, MAX(confidence) AS max_conf
            FROM $TABLE_EVENTS
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

    // ── Troubleshoot Queries ──

    /**
     * Returns domains blocked within the last [minutes] minutes,
     * grouped by domain, sorted by hit count descending.
     */
    fun recentBlocks(minutes: Int = 5): List<RecentBlock> {
        val since = System.currentTimeMillis() - minutes * 60 * 1000L
        val db = readableDatabase
        val result = mutableListOf<RecentBlock>()

        db.rawQuery("""
            SELECT domain, source, COUNT(*) AS cnt, MAX(confidence) AS max_conf
            FROM $TABLE_EVENTS
            WHERE action = 'blocked' AND timestamp >= ?
            GROUP BY domain
            ORDER BY cnt DESC
        """, arrayOf(since.toString())).use { c ->
            while (c.moveToNext()) {
                result.add(
                    RecentBlock(
                        domain = c.getString(0),
                        source = c.getString(1),
                        count = c.getInt(2),
                        maxConfidence = c.getFloat(3),
                    )
                )
            }
        }
        return result
    }

    /**
     * Returns domains allowed within the last [minutes] minutes (distinct).
     */
    fun recentAllowed(minutes: Int = 5): List<String> {
        val since = System.currentTimeMillis() - minutes * 60 * 1000L
        val db = readableDatabase
        val result = mutableListOf<String>()

        db.rawQuery("""
            SELECT DISTINCT domain
            FROM $TABLE_EVENTS
            WHERE action = 'allowed' AND timestamp >= ?
            ORDER BY domain ASC
        """, arrayOf(since.toString())).use { c ->
            while (c.moveToNext()) {
                result.add(c.getString(0))
            }
        }
        return result
    }

    // ── Domain Detail Queries ──

    fun domainDetail(domain: String): DomainDetail? {
        val db = readableDatabase
        db.rawQuery("""
            SELECT
                COUNT(*) AS total_hits,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen,
                SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked_count,
                SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END) AS allowed_count,
                MAX(confidence) AS max_confidence
            FROM $TABLE_EVENTS
            WHERE domain = ?
        """, arrayOf(domain)).use { c ->
            if (!c.moveToFirst() || c.getInt(0) == 0) return null
            val totalHits = c.getInt(0)
            val firstSeen = c.getLong(1)
            val lastSeen = c.getLong(2)
            val blockedCount = c.getInt(3)
            val allowedCount = c.getInt(4)
            val maxConfidence = c.getFloat(5)

            // Get the most common source for this domain
            var primarySource = "none"
            db.rawQuery("""
                SELECT source, COUNT(*) AS cnt
                FROM $TABLE_EVENTS
                WHERE domain = ?
                GROUP BY source
                ORDER BY cnt DESC
                LIMIT 1
            """, arrayOf(domain)).use { sc ->
                if (sc.moveToFirst()) primarySource = sc.getString(0)
            }

            return DomainDetail(
                domain = domain,
                totalHits = totalHits,
                firstSeen = firstSeen,
                lastSeen = lastSeen,
                primarySource = primarySource,
                maxConfidence = maxConfidence,
                blockedCount = blockedCount,
                allowedCount = allowedCount,
            )
        }
    }

    fun domainHourlyActivity(domain: String, hours: Int = 24): List<HourlyCount> {
        val since = System.currentTimeMillis() - hours * 60 * 60 * 1000L
        val db = readableDatabase
        val result = mutableListOf<HourlyCount>()

        db.rawQuery("""
            SELECT (timestamp / 3600000) * 3600000 AS hour_bucket, COUNT(*) AS cnt
            FROM $TABLE_EVENTS
            WHERE domain = ? AND timestamp >= ?
            GROUP BY hour_bucket
            ORDER BY hour_bucket ASC
        """, arrayOf(domain, since.toString())).use { c ->
            while (c.moveToNext()) {
                result.add(HourlyCount(c.getLong(0), c.getInt(1)))
            }
        }
        return result
    }

    // ── Domain Policy Management ──

    fun setPolicy(domain: String, policy: DomainPolicy) {
        val now = System.currentTimeMillis()
        val values = ContentValues().apply {
            put("domain", domain)
            put("policy", policy.value)
            put("created_at", now)
            put("updated_at", now)
        }
        writableDatabase.insertWithOnConflict(
            TABLE_POLICIES, null, values, SQLiteDatabase.CONFLICT_REPLACE
        )
    }

    fun getPolicy(domain: String): DomainPolicy {
        readableDatabase.rawQuery(
            "SELECT policy FROM $TABLE_POLICIES WHERE domain = ?",
            arrayOf(domain)
        ).use { c ->
            if (c.moveToFirst()) {
                return DomainPolicy.fromValue(c.getString(0))
            }
        }
        return DomainPolicy.AUTO
    }

    fun getAllowedDomains(): List<String> {
        val result = mutableListOf<String>()
        readableDatabase.rawQuery(
            "SELECT domain FROM $TABLE_POLICIES WHERE policy = 'allow'", null
        ).use { c ->
            while (c.moveToNext()) result.add(c.getString(0))
        }
        return result
    }

    fun getBlockedDomains(): List<String> {
        val result = mutableListOf<String>()
        readableDatabase.rawQuery(
            "SELECT domain FROM $TABLE_POLICIES WHERE policy = 'block'", null
        ).use { c ->
            while (c.moveToNext()) result.add(c.getString(0))
        }
        return result
    }

    // ── Maintenance ──

    fun purgeOlderThan(days: Int = 30) {
        val cutoff = System.currentTimeMillis() - days * 24L * 60 * 60 * 1000
        writableDatabase.delete(TABLE_EVENTS, "timestamp < ?", arrayOf(cutoff.toString()))
    }

    fun clearAll() {
        writableDatabase.delete(TABLE_EVENTS, null, null)
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
        private const val DB_VERSION = 2
        private const val TABLE_EVENTS = "events"
        private const val TABLE_POLICIES = "domain_policies"

        @Volatile
        private var INSTANCE: ThreatLog? = null

        fun getInstance(context: Context): ThreatLog {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: ThreatLog(context.applicationContext).also { INSTANCE = it }
            }
        }
    }
}

enum class DomainPolicy(val value: String) {
    ALLOW("allow"),
    AUTO("auto"),
    BLOCK("block");

    companion object {
        fun fromValue(value: String): DomainPolicy =
            entries.firstOrNull { it.value == value } ?: AUTO
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

data class RecentBlock(
    val domain: String,
    val source: String,
    val count: Int,
    val maxConfidence: Float,
)

data class DomainDetail(
    val domain: String,
    val totalHits: Int,
    val firstSeen: Long,
    val lastSeen: Long,
    val primarySource: String,
    val maxConfidence: Float,
    val blockedCount: Int,
    val allowedCount: Int,
)
