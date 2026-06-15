"""Database connection and operations for Nexo Sentinel."""

import sqlite3
import json
import aiosqlite
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import hashlib
from loguru import logger


class Database:
    """Async SQLite database handler with WAL mode for concurrent access."""

    def __init__(self, db_path: str = "nexo_sentinel.db"):
        """Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._conn = None

    async def initialize(self):
        """Initialize database schema and enable WAL mode."""
        # Create database file if it doesn't exist
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Read and execute schema
        schema_path = Path(__file__).parent / "schema.sql"
        with open(schema_path, "r") as f:
            schema = f.read()
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(schema)
            await db.commit()
        
        logger.info(f"Database initialized at {self.db_path}")

    @asynccontextmanager
    async def get_connection(self):
        """Get async database connection."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            yield db

    async def execute(self, query: str, params: tuple = ()):
        """Execute a query and return cursor."""
        async with self.get_connection() as db:
            cursor = await db.execute(query, params)
            await db.commit()
            return cursor

    async def fetch_one(self, query: str, params: tuple = ()) -> Optional[Dict]:
        """Fetch a single row."""
        async with self.get_connection() as db:
            cursor = await db.execute(query, params)
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None

    async def fetch_all(self, query: str, params: tuple = ()) -> List[Dict]:
        """Fetch all rows."""
        async with self.get_connection() as db:
            cursor = await db.execute(query, params)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    # ============== Article Operations ==============

    async def add_article(
        self,
        title: str,
        url: str,
        content: str,
        source_feed_id: int,
        published_date: Optional[datetime] = None,
    ) -> str:
        """Add new article and generate UID."""
        # Generate UID: NEXO-YYYY-NNNNN
        now = datetime.now()
        year = now.year
        
        # Get count of articles this year
        last_article = await self.fetch_one(
            "SELECT MAX(id) as max_id FROM articles WHERE strftime('%Y', created_at) = ?",
            (str(year),)
        )
        
        count = (last_article["max_id"] or 0) + 1 if last_article else 1
        uid = f"NEXO-{year}-{count:05d}"
        
        await self.execute(
            """INSERT INTO articles (uid, title, url, content, source_feed_id, published_date)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (uid, title, url, content, source_feed_id, published_date)
        )
        
        return uid

    async def get_article(self, article_id: int) -> Optional[Dict]:
        """Get article by ID."""
        return await self.fetch_one("SELECT * FROM articles WHERE id = ?", (article_id,))

    async def get_article_by_uid(self, uid: str) -> Optional[Dict]:
        """Get article by UID."""
        return await self.fetch_one("SELECT * FROM articles WHERE uid = ?", (uid,))

    async def get_articles_by_status(self, status: str, limit: int = 100) -> List[Dict]:
        """Get articles by status."""
        return await self.fetch_all(
            "SELECT * FROM articles WHERE status = ? ORDER BY fetched_date DESC LIMIT ?",
            (status, limit)
        )

    async def update_article_status(self, article_id: int, status: str):
        """Update article processing status."""
        await self.execute(
            "UPDATE articles SET status = ? WHERE id = ?",
            (status, article_id)
        )

    async def update_article_summary(self, article_id: int, summary: str):
        """Update article summary."""
        await self.execute(
            "UPDATE articles SET summary = ? WHERE id = ?",
            (summary, article_id)
        )

    async def update_article_threat_info(
        self,
        article_id: int,
        threat_category: str,
        severity: str,
        ttps_json: str,
        threat_actors_json: str,
    ):
        """Update the threat intelligence columns for an article.
        
        Args:
            article_id: Article primary key
            threat_category: One of Malware, Phishing, Vulnerability, Ransomware, APT, Data Breach, Info
            severity: One of Critical, High, Medium, Low, Info
            ttps_json: JSON array string of MITRE ATT&CK IDs
            threat_actors_json: JSON array string of actor names
        """
        await self.execute(
            """UPDATE articles
               SET threat_category = ?, severity = ?, ttps = ?, threat_actors = ?
               WHERE id = ?""",
            (threat_category, severity, ttps_json, threat_actors_json, article_id)
        )

    async def get_articles_by_severity(self, severity: str, limit: int = 50) -> List[Dict]:
        """Get articles filtered by severity level.
        
        Args:
            severity: One of Critical, High, Medium, Low, Info
            limit: Max results to return
        """
        return await self.fetch_all(
            "SELECT * FROM articles WHERE severity = ? ORDER BY fetched_date DESC LIMIT ?",
            (severity, limit)
        )

    async def get_articles_by_category(self, category: str, limit: int = 50) -> List[Dict]:
        """Get articles filtered by threat category.
        
        Args:
            category: One of Malware, Phishing, Vulnerability, Ransomware, APT, Data Breach, Info
            limit: Max results to return
        """
        return await self.fetch_all(
            "SELECT * FROM articles WHERE threat_category = ? ORDER BY fetched_date DESC LIMIT ?",
            (category, limit)
        )

    async def get_latest_articles(self, limit: int = 10) -> List[Dict]:
        """Get latest articles."""
        return await self.fetch_all(
            """SELECT * FROM articles 
               WHERE status = 'complete' 
               ORDER BY fetched_date DESC 
               LIMIT ?""",
            (limit,)
        )

    # ============== IOC Operations ==============

    async def add_ioc(
        self,
        article_id: int,
        ioc_type: str,
        ioc_value: str,
        source: str = "main_content",
        original_value: Optional[str] = None,
    ) -> Optional[int]:
        """Add IOC with deduplication via hash."""
        ioc_hash = hashlib.sha256(ioc_value.lower().encode()).hexdigest()
        
        try:
            await self.execute(
                """INSERT INTO iocs (article_id, ioc_type, ioc_value, ioc_value_hash, original_value, source)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (article_id, ioc_type, ioc_value, ioc_hash, original_value, source)
            )
            
            # Update article IOC count
            count = await self.fetch_one(
                "SELECT COUNT(*) as cnt FROM iocs WHERE article_id = ?",
                (article_id,)
            )
            await self.execute(
                "UPDATE articles SET ioc_count = ? WHERE id = ?",
                (count["cnt"], article_id)
            )
            
            # Get the inserted ID
            result = await self.fetch_one(
                "SELECT id FROM iocs WHERE article_id = ? AND ioc_value_hash = ? ORDER BY id DESC LIMIT 1",
                (article_id, ioc_hash)
            )
            return result["id"] if result else None
        except sqlite3.IntegrityError:
            # IOC already exists for this article
            return None

    async def get_article_iocs(self, article_id: int) -> List[Dict]:
        """Get all IOCs for an article."""
        return await self.fetch_all(
            "SELECT * FROM iocs WHERE article_id = ? ORDER BY ioc_type",
            (article_id,)
        )

    async def get_iocs_by_type(self, ioc_type: str) -> List[Dict]:
        """Get all IOCs of a specific type."""
        return await self.fetch_all(
            "SELECT * FROM iocs WHERE ioc_type = ? ORDER BY created_at DESC",
            (ioc_type,)
        )

    async def get_all_iocs(self) -> List[Dict]:
        """Get all IOCs with article info."""
        return await self.fetch_all(
            """SELECT i.*, a.uid, a.title, a.url, a.published_date, f.name as feed_name
               FROM iocs i
               JOIN articles a ON i.article_id = a.id
               JOIN feed_sources f ON a.source_feed_id = f.id
               ORDER BY i.created_at DESC"""
        )

    # ============== User IOC Downloads (CSV Export Tracking) ==============

    async def mark_iocs_as_downloaded(self, telegram_user_id: int, ioc_ids: List[int], download_type: str = "all_iocs"):
        """Mark IOCs as downloaded by user to prevent duplicates in future exports."""
        for ioc_id in ioc_ids:
            try:
                await self.execute(
                    """INSERT INTO user_ioc_downloads (telegram_user_id, ioc_id, download_type)
                       VALUES (?, ?, ?)""",
                    (telegram_user_id, ioc_id, download_type)
                )
            except sqlite3.IntegrityError:
                # Already marked as downloaded
                pass

    async def get_undownloaded_iocs(self, telegram_user_id: int) -> List[Dict]:
        """Get all IOCs not yet downloaded by user."""
        return await self.fetch_all(
            """SELECT i.*, a.uid, a.title, a.url, a.published_date, f.name as feed_name
               FROM iocs i
               JOIN articles a ON i.article_id = a.id
               JOIN feed_sources f ON a.source_feed_id = f.id
               WHERE i.id NOT IN (
                   SELECT ioc_id FROM user_ioc_downloads WHERE telegram_user_id = ?
               )
               ORDER BY i.created_at DESC""",
            (telegram_user_id,)
        )

    async def get_new_iocs_since_last_download(self, telegram_user_id: int) -> List[Dict]:
        """Get IOCs added since user's last download."""
        last_download = await self.fetch_one(
            "SELECT MAX(downloaded_at) as last_time FROM user_ioc_downloads WHERE telegram_user_id = ?",
            (telegram_user_id,)
        )
        
        last_time = last_download["last_time"] if last_download and last_download["last_time"] else "1970-01-01"
        
        return await self.fetch_all(
            """SELECT i.*, a.uid, a.title, a.url, a.published_date, f.name as feed_name
               FROM iocs i
               JOIN articles a ON i.article_id = a.id
               JOIN feed_sources f ON a.source_feed_id = f.id
               WHERE i.created_at > ? AND i.id NOT IN (
                   SELECT ioc_id FROM user_ioc_downloads WHERE telegram_user_id = ?
               )
               ORDER BY i.created_at DESC""",
            (last_time, telegram_user_id)
        )

    async def get_article_iocs_undownloaded(self, article_id: int, telegram_user_id: int) -> List[Dict]:
        """Get IOCs for specific article not yet downloaded by user."""
        return await self.fetch_all(
            """SELECT i.*, a.uid, a.title, a.url, a.published_date, f.name as feed_name
               FROM iocs i
               JOIN articles a ON i.article_id = a.id
               JOIN feed_sources f ON a.source_feed_id = f.id
               WHERE a.id = ? AND i.id NOT IN (
                   SELECT ioc_id FROM user_ioc_downloads WHERE telegram_user_id = ?
               )
               ORDER BY i.ioc_type""",
            (article_id, telegram_user_id)
        )

    # ============== Feed Operations ==============

    async def add_feed_source(self, name: str, url: str, category: str = "") -> int:
        """Add RSS feed source."""
        await self.execute(
            "INSERT INTO feed_sources (name, url, category) VALUES (?, ?, ?)",
            (name, url, category)
        )
        
        result = await self.fetch_one(
            "SELECT id FROM feed_sources WHERE name = ?",
            (name,)
        )
        return result["id"] if result else 0

    async def get_feed_sources(self, enabled_only: bool = True) -> List[Dict]:
        """Get all feed sources."""
        if enabled_only:
            return await self.fetch_all("SELECT * FROM feed_sources WHERE enabled = 1")
        return await self.fetch_all("SELECT * FROM feed_sources")

    async def update_feed_last_fetched(self, feed_id: int):
        """Update last fetch timestamp for feed."""
        await self.execute(
            "UPDATE feed_sources SET last_fetched = CURRENT_TIMESTAMP WHERE id = ?",
            (feed_id,)
        )

    # ============== Telegram User Operations ==============

    async def add_telegram_user(self, telegram_id: int, telegram_name: str = "", is_admin: bool = False) -> int:
        """Add or get Telegram user. Sets admin flag if specified."""
        existing = await self.fetch_one(
            "SELECT id, is_admin FROM telegram_users WHERE telegram_id = ?",
            (telegram_id,)
        )
        
        if existing:
            # Update name and activity
            await self.execute(
                "UPDATE telegram_users SET telegram_name = ?, last_activity = CURRENT_TIMESTAMP WHERE telegram_id = ?",
                (telegram_name, telegram_id)
            )
            # Promote to admin if requested and not already
            if is_admin and not existing["is_admin"]:
                await self.execute(
                    "UPDATE telegram_users SET is_admin = 1 WHERE telegram_id = ?",
                    (telegram_id,)
                )
            return existing["id"]
        
        await self.execute(
            "INSERT INTO telegram_users (telegram_id, telegram_name, is_admin, notifications_enabled) VALUES (?, ?, ?, 1)",
            (telegram_id, telegram_name, 1 if is_admin else 0)
        )
        
        result = await self.fetch_one(
            "SELECT id FROM telegram_users WHERE telegram_id = ?",
            (telegram_id,)
        )
        return result["id"] if result else 0

    async def get_all_subscribers(self) -> List[Dict]:
        """Get all users with notifications enabled."""
        return await self.fetch_all(
            "SELECT telegram_id, telegram_name, is_admin FROM telegram_users WHERE notifications_enabled = 1"
        )

    async def is_admin(self, telegram_id: int) -> bool:
        """Check if user is admin."""
        result = await self.fetch_one(
            "SELECT is_admin FROM telegram_users WHERE telegram_id = ?",
            (telegram_id,)
        )
        return bool(result and result["is_admin"])

    async def set_notifications(self, telegram_id: int, enabled: bool):
        """Enable/disable notifications for a user."""
        await self.execute(
            "UPDATE telegram_users SET notifications_enabled = ? WHERE telegram_id = ?",
            (1 if enabled else 0, telegram_id)
        )

    async def get_subscriber_count(self) -> int:
        """Get total subscriber count."""
        result = await self.fetch_one(
            "SELECT COUNT(*) as count FROM telegram_users WHERE notifications_enabled = 1"
        )
        return result["count"] if result else 0

    async def update_user_activity(self, telegram_id: int):
        """Update user's last activity timestamp."""
        await self.execute(
            "UPDATE telegram_users SET last_activity = CURRENT_TIMESTAMP WHERE telegram_id = ?",
            (telegram_id,)
        )

    # ============== Statistics ==============

    async def get_statistics(self) -> Dict[str, Any]:
        """Get system statistics including threat intelligence breakdowns."""
        total_articles = await self.fetch_one(
            "SELECT COUNT(*) as count FROM articles"
        )
        
        total_iocs = await self.fetch_one(
            "SELECT COUNT(*) as count FROM iocs"
        )
        
        ioc_by_type = await self.fetch_all(
            "SELECT ioc_type, COUNT(*) as count FROM iocs GROUP BY ioc_type"
        )
        
        articles_by_status = await self.fetch_all(
            "SELECT status, COUNT(*) as count FROM articles GROUP BY status"
        )
        
        articles_by_severity = await self.fetch_all(
            "SELECT severity, COUNT(*) as count FROM articles GROUP BY severity"
        )
        
        articles_by_category = await self.fetch_all(
            "SELECT threat_category, COUNT(*) as count FROM articles GROUP BY threat_category"
        )
        
        # Get distinct threat actors with counts
        # threat_actors column stores JSON arrays, so we extract individual actors
        threat_actors_raw = await self.fetch_all(
            """SELECT threat_actors FROM articles
               WHERE threat_actors IS NOT NULL AND threat_actors != '[]'"""
        )
        
        # Parse JSON arrays and count occurrences
        actor_counts: Dict[str, int] = {}
        for row in threat_actors_raw:
            try:
                actors = json.loads(row["threat_actors"])
                for actor in actors:
                    actor = actor.strip()
                    if actor:
                        actor_counts[actor] = actor_counts.get(actor, 0) + 1
            except (json.JSONDecodeError, TypeError):
                pass
        
        return {
            "total_articles": total_articles["count"],
            "total_iocs": total_iocs["count"],
            "iocs_by_type": {row["ioc_type"]: row["count"] for row in ioc_by_type},
            "articles_by_status": {row["status"]: row["count"] for row in articles_by_status},
            "articles_by_severity": {row["severity"]: row["count"] for row in articles_by_severity},
            "articles_by_category": {row["threat_category"]: row["count"] for row in articles_by_category},
            "threat_actors": actor_counts,
        }

    async def search_articles(self, query: str, limit: int = 20) -> List[Dict]:
        """Full-text search in articles."""
        search_query = f"%{query}%"
        return await self.fetch_all(
            """SELECT * FROM articles 
               WHERE title LIKE ? OR content LIKE ? OR summary LIKE ?
               ORDER BY fetched_date DESC
               LIMIT ?""",
            (search_query, search_query, search_query, limit)
        )
