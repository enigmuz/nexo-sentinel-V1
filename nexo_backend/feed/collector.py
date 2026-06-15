"""RSS feed collector for Nexo Sentinel."""

import feedparser
import aiohttp
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
from loguru import logger
from nexo_backend.config import get_settings
from nexo_backend.db import Database


class FeedCollector:
    """Async RSS feed collector."""

    def __init__(self, db: Database):
        """Initialize feed collector.
        
        Args:
            db: Database instance
        """
        self.db = db
        self.settings = get_settings()

    async def initialize_feed_sources(self):
        """Initialize default RSS feed sources."""
        from nexo_backend.config import FEED_SOURCES
        
        existing = await self.db.get_feed_sources(enabled_only=False)
        existing_names = {feed["name"] for feed in existing}
        
        for source in FEED_SOURCES:
            if source["name"] not in existing_names:
                await self.db.add_feed_source(
                    name=source["name"],
                    url=source["url"],
                    category=source["category"]
                )
                logger.info(f"Added feed source: {source['name']}")

    async def collect_feeds(self) -> Dict[str, int]:
        """Collect articles from all enabled feeds.
        
        Returns:
            Dictionary with feed names and article count
        """
        feeds = await self.db.get_feed_sources(enabled_only=True)
        results = {}
        
        for feed in feeds:
            try:
                count = await self._fetch_feed(feed)
                results[feed["name"]] = count
                logger.info(f"Fetched {count} articles from {feed['name']}")
                
                # Update last fetched timestamp
                await self.db.update_feed_last_fetched(feed["id"])
            except Exception as e:
                logger.error(f"Error fetching feed {feed['name']}: {str(e)}")
                results[feed["name"]] = 0
        
        return results

    async def _fetch_feed(self, feed: Dict) -> int:
        """Fetch single feed and add new articles.
        
        Args:
            feed: Feed configuration dict
            
        Returns:
            Number of new articles added
        """
        import asyncio
        try:
            # Use feedparser directly — it handles RSS User-Agent properly
            # Run in executor to keep async compatibility
            loop = asyncio.get_event_loop()
            parsed = await loop.run_in_executor(
                None,
                lambda: feedparser.parse(
                    feed["url"],
                    agent="NexoSentinel/2.0 (+https://github.com/nexo-sentinel; RSS Feed Reader)"
                )
            )
        except Exception as e:
            logger.error(f"Error downloading feed {feed['name']}: {str(e)}")
            return 0
        
        if parsed.bozo:
            logger.warning(f"Feed {feed['name']} has parsing issues: {parsed.bozo_exception}")
        
        added = 0
        skipped_old = 0
        for entry in parsed.entries:
            try:
                # Skip if article already exists (deduplication by URL)
                url = entry.get("link", "")
                if not url:
                    continue
                
                existing = await self.db.fetch_one(
                    "SELECT id FROM articles WHERE url = ?",
                    (url,)
                )
                
                if existing:
                    continue
                
                # Extract article data
                title = entry.get("title", "Unknown")
                content = entry.get("summary", "") or entry.get("content", "")
                published_date = self._parse_date(entry)
                
                # Skip articles older than 48 hours
                if published_date:
                    cutoff = datetime.now(timezone.utc) - timedelta(hours=48)
                    pub_utc = published_date
                    if pub_utc.tzinfo is None:
                        pub_utc = pub_utc.replace(tzinfo=timezone.utc)
                    if pub_utc < cutoff:
                        skipped_old += 1
                        continue
                
                # Add article to database
                uid = await self.db.add_article(
                    title=title,
                    url=url,
                    content=content,
                    source_feed_id=feed["id"],
                    published_date=published_date
                )
                
                logger.debug(f"Added article: {uid} - {title}")
                added += 1
            except Exception as e:
                logger.error(f"Error processing feed entry: {str(e)}")
                continue
        
        if skipped_old > 0:
            logger.info(f"Skipped {skipped_old} old articles (>48h) from {feed['name']}")
        
        return added

    @staticmethod
    def _parse_date(entry) -> Optional[datetime]:
        """Parse date from feed entry using feedparser's parsed date."""
        # feedparser provides published_parsed or updated_parsed as time.struct_time
        import time
        import calendar
        
        for field in ('published_parsed', 'updated_parsed'):
            parsed_time = entry.get(field)
            if parsed_time:
                try:
                    # Convert struct_time to UTC datetime
                    timestamp = calendar.timegm(parsed_time)
                    return datetime.fromtimestamp(timestamp, tz=timezone.utc)
                except Exception:
                    continue
        
        # Fallback: try the raw string
        date_str = entry.get('published') or entry.get('updated')
        if date_str and isinstance(date_str, str):
            try:
                from email.utils import parsedate_to_datetime
                return parsedate_to_datetime(date_str)
            except Exception:
                pass
        
        return None
