"""Database sync utilities for Next.js dashboard."""

import json
import sqlite3
from pathlib import Path
from datetime import datetime
from loguru import logger
from nexo_backend.db import Database


class DatabaseSync:
    """Sync SQLite database to JSON for Next.js dashboard."""

    def __init__(self, db: Database, output_dir: str = "public/data"):
        """Initialize sync utility.
        
        Args:
            db: Database instance
            output_dir: Output directory for JSON files
        """
        self.db = db
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def sync_all(self) -> bool:
        """Sync all data to JSON files.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            await self.sync_articles()
            await self.sync_iocs()
            await self.sync_statistics()
            await self.sync_metadata()
            
            logger.info("Database sync complete")
            return True
        except Exception as e:
            logger.error(f"Error syncing database: {str(e)}")
            return False

    async def sync_articles(self):
        """Sync articles to JSON."""
        articles = await self.db.get_latest_articles(limit=1000)
        
        articles_list = []
        for a in articles:
            # Parse JSON fields safely
            ttps = []
            threat_actors = []
            try:
                ttps_raw = a.get("ttps", "[]")
                ttps = json.loads(ttps_raw) if ttps_raw else []
            except (json.JSONDecodeError, TypeError):
                pass
            try:
                actors_raw = a.get("threat_actors", "[]")
                threat_actors = json.loads(actors_raw) if actors_raw else []
            except (json.JSONDecodeError, TypeError):
                pass

            articles_list.append({
                "id": a["id"],
                "uid": a["uid"],
                "title": a["title"],
                "url": a["url"],
                "summary": a.get("summary", ""),
                "ioc_count": a.get("ioc_count", 0),
                "status": a["status"],
                "threat_category": a.get("threat_category", "Info"),
                "severity": a.get("severity", "Info"),
                "ttps": ttps,
                "threat_actors": threat_actors,
                "published_date": str(a.get("published_date", "")),
                "fetched_date": str(a.get("fetched_date", "")),
                "feed_source": await self._get_feed_name(a["source_feed_id"]),
            })
        
        output_file = self.output_dir / "articles.json"
        with open(output_file, "w") as f:
            json.dump(articles_list, f, indent=2)
        
        logger.debug(f"Synced {len(articles_list)} articles to {output_file}")

    async def sync_iocs(self):
        """Sync IOCs to JSON."""
        iocs = await self.db.get_all_iocs()
        
        # Group by type
        iocs_by_type = {}
        for ioc in iocs:
            ioc_type = ioc["ioc_type"]
            if ioc_type not in iocs_by_type:
                iocs_by_type[ioc_type] = []
            
            iocs_by_type[ioc_type].append({
                "id": ioc["id"],
                "value": ioc["ioc_value"],
                "article_uid": ioc["uid"],
                "article_title": ioc["title"],
                "article_url": ioc["url"],
                "source": ioc.get("source", "main_content"),
                "created_at": str(ioc.get("created_at", "")),
            })
        
        output_file = self.output_dir / "iocs.json"
        with open(output_file, "w") as f:
            json.dump(iocs_by_type, f, indent=2)
        
        total_iocs = sum(len(v) for v in iocs_by_type.values())
        logger.debug(f"Synced {total_iocs} IOCs to {output_file}")

    async def sync_statistics(self):
        """Sync statistics to JSON."""
        stats = await self.db.get_statistics()
        
        stats_data = {
            "total_articles": stats["total_articles"],
            "total_iocs": stats["total_iocs"],
            "iocs_by_type": stats["iocs_by_type"],
            "articles_by_status": stats["articles_by_status"],
            "articles_by_severity": stats.get("articles_by_severity", {}),
            "articles_by_category": stats.get("articles_by_category", {}),
            "threat_actors": stats.get("threat_actors", []),
            "last_updated": datetime.now().isoformat(),
        }
        
        output_file = self.output_dir / "statistics.json"
        with open(output_file, "w") as f:
            json.dump(stats_data, f, indent=2)
        
        logger.debug(f"Synced statistics to {output_file}")

    async def sync_metadata(self):
        """Sync metadata to JSON."""
        feeds = await self.db.get_feed_sources()
        
        metadata = {
            "feeds": [
                {
                    "id": f["id"],
                    "name": f["name"],
                    "url": f["url"],
                    "category": f.get("category", ""),
                    "enabled": f["enabled"],
                    "last_fetched": str(f.get("last_fetched", "")),
                }
                for f in feeds
            ],
            "sync_timestamp": datetime.now().isoformat(),
            "db_path": self.db.db_path,
        }
        
        output_file = self.output_dir / "metadata.json"
        with open(output_file, "w") as f:
            json.dump(metadata, f, indent=2)
        
        logger.debug(f"Synced metadata to {output_file}")

    async def _get_feed_name(self, feed_id: int) -> str:
        """Get feed name by ID."""
        feed = await self.db.fetch_one(
            "SELECT name FROM feed_sources WHERE id = ?",
            (feed_id,)
        )
        return feed["name"] if feed else "Unknown"
