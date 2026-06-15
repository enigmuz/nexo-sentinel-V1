"""Hybrid CTI pipeline scheduler.

v4 — Uses iocextract for local IOC extraction + DeepSeek API for classification.
iocextract handles IOCs locally (free, fast, accurate).
DeepSeek only classifies + summarizes (saves 70% API tokens).
"""

import asyncio
import json
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from datetime import datetime
from urllib.parse import urlparse
from loguru import logger
from nexo_backend.config import get_settings
from nexo_backend.db import Database
from nexo_backend.feed import FeedCollector
from nexo_backend.parser import ArticleParser
from nexo_backend.parser.ioc_extractor import extract_iocs_from_text
from nexo_backend.ioc import IOCExtractor
from nexo_backend.ai import Summarizer
from nexo_backend.telegram import TelegramBot
from nexo_backend.sync import DatabaseSync


class Pipeline:
    """Hybrid CTI pipeline: Fetch → Download → IOCs (local) → Classify (DeepSeek) → Notify."""

    def __init__(
        self,
        db: Database,
        feed_collector: FeedCollector,
        parser: ArticleParser,
        ioc_extractor: IOCExtractor,
        summarizer: Summarizer,
        telegram_bot: TelegramBot,
    ):
        self.db = db
        self.feed_collector = feed_collector
        self.parser = parser
        self.ioc_extractor = ioc_extractor
        self.summarizer = summarizer
        self.telegram_bot = telegram_bot
        self.settings = get_settings()

    async def collect_feeds(self) -> dict:
        """Collect articles from all RSS feeds."""
        logger.info("=== Feed collection started ===")
        try:
            results = await self.feed_collector.collect_feeds()
            total = sum(results.values())
            logger.info(f"Feed collection complete: {total} new articles from {len(results)} feeds")
            return results
        except Exception as e:
            logger.error(f"Error collecting feeds: {str(e)}")
            return {}

    async def process_pending_articles(self):
        """Process pending articles — 20 per batch (DeepSeek is fast)."""
        logger.info("Starting article processing pipeline...")
        articles = await self.db.get_articles_by_status("pending", limit=20)

        if not articles:
            logger.info("No pending articles to process")
            return

        logger.info(f"Processing {len(articles)} pending articles...")

        for article in articles:
            try:
                await self.process_article(article)
            except Exception as e:
                logger.error(f"Error processing article {article.get('uid', '?')}: {str(e)}")
                continue

    async def process_article(self, article: dict):
        """Process a single article through the DeepSeek pipeline.

        Flow:
        1. Download full article content from URL
        2. Run regex IOC extraction on full text
        3. Send to DeepSeek API for classification + analysis
        4. Merge IOCs (regex + DeepSeek)
        5. If NOT security → ignore silently
        6. If security → store + notify Telegram
        """
        article_id = article["id"]
        uid = article["uid"]
        article_url = article.get("url", "")
        logger.info(f"Processing {uid}: {article.get('title', '')[:60]}")

        # ═══════════════════════════════════════════════════════════
        # Step 1: Download full article content
        # ═══════════════════════════════════════════════════════════
        full_text = ""
        try:
            content_text, links, full_text = await self.parser.parse_article(article_id)
            await self.db.update_article_status(article_id, "parsed")
        except Exception as e:
            logger.error(f"Error downloading {uid}: {str(e)}")
            await self.db.update_article_status(article_id, "parsed")
            content_text = article.get("content", "")
            full_text = content_text

        # Re-fetch article to get updated content
        article = await self.db.get_article(article_id)
        if not article:
            return
        article_content = article.get("content", "")

        # Use full text for IOC extraction (before any truncation)
        ioc_source_text = full_text if full_text else article_content

        # ═══════════════════════════════════════════════════════════
        # Step 2: Extract IOCs LOCALLY with iocextract (free, fast)
        # ═══════════════════════════════════════════════════════════
        iocs_data = extract_iocs_from_text(ioc_source_text, article_url)
        total_iocs = sum(len(v) for v in iocs_data.values())
        logger.info(f"Local IOC extraction for {uid}: {total_iocs} IOCs found")

        # ═══════════════════════════════════════════════════════════
        # Step 3: Send to DeepSeek API for classification + summary ONLY
        #         (DeepSeek does NOT extract IOCs — saves 70% tokens)
        # ═══════════════════════════════════════════════════════════
        deepseek_result = None
        if self.settings.deepseek_enabled and article_content:
            try:
                deepseek_result = await self.summarizer.analyze_article(article_id)
                if deepseek_result:
                    is_cti = deepseek_result.get("is_security_related", False)
                    cat = deepseek_result.get("threat_category", "?")
                    sev = deepseek_result.get("severity", "?")
                    logger.info(
                        f"DeepSeek classified {uid}: security={is_cti}, "
                        f"category={cat}, severity={sev}"
                    )
            except Exception as e:
                logger.warning(f"DeepSeek analysis failed for {uid}: {str(e)}")

        # No result? Defer to next cycle
        if not deepseek_result:
            logger.info(f"DeepSeek unavailable, deferring {uid} for next cycle")
            return

        # ═══════════════════════════════════════════════════════════
        # Step 4: Extract classification results from DeepSeek
        # ═══════════════════════════════════════════════════════════
        is_security_related = deepseek_result.get("is_security_related", False)
        summary = deepseek_result.get("summary", "")
        threat_category = deepseek_result.get("threat_category", "Non-Related")
        severity = deepseek_result.get("severity", "Info")
        ttps = deepseek_result.get("ttps", [])
        threat_actors = deepseek_result.get("threat_actors", [])

        # ═══════════════════════════════════════════════════════════
        # Step 5: NOT security → ignore silently
        # Double-check: if category is Non-Related or severity is Info,
        # treat as not security even if DeepSeek said is_security_related=true
        # ═══════════════════════════════════════════════════════════
        if not is_security_related or threat_category == "Non-Related" or severity == "Info":
            await self.db.update_article_status(article_id, "ignored")
            if summary:
                await self.db.update_article_summary(article_id, summary)
            try:
                await self.db.update_article_threat_info(
                    article_id=article_id,
                    threat_category=threat_category,
                    severity="Info",
                    ttps_json="[]",
                    threat_actors_json="[]",
                )
            except Exception:
                pass
            logger.info(f"✗ Ignored {uid}: {article.get('title', '')[:60]}")
            return

        # ═══════════════════════════════════════════════════════════
        # Step 6: IS security → store IOCs + details
        # ═══════════════════════════════════════════════════════════
        ioc_type_map = {
            "ipv4": "IPv4", "ipv6": "IPv6", "domains": "Domain",
            "urls": "URL", "md5": "MD5", "sha1": "SHA1",
            "sha256": "SHA256", "emails": "Email", "cves": "CVE"
        }

        stored_iocs = 0
        for ioc_key, db_type in ioc_type_map.items():
            values = iocs_data.get(ioc_key, [])
            for ioc_value in values:
                if ioc_value and isinstance(ioc_value, str):
                    ioc_id = await self.db.add_ioc(
                        article_id=article_id,
                        ioc_type=db_type,
                        ioc_value=ioc_value.strip(),
                        source="iocextract"
                    )
                    if ioc_id:
                        stored_iocs += 1

        # Update article in DB
        await self.db.update_article_status(article_id, "ioc_extracted")

        if summary:
            await self.db.update_article_summary(article_id, summary)

        try:
            await self.db.update_article_threat_info(
                article_id=article_id,
                threat_category=threat_category,
                severity=severity,
                ttps_json=json.dumps(ttps) if isinstance(ttps, list) else ttps,
                threat_actors_json=json.dumps(threat_actors) if isinstance(threat_actors, list) else threat_actors,
            )
        except Exception as e:
            logger.warning(f"Could not update threat info for {uid}: {str(e)}")

        await self.db.update_article_status(article_id, "complete")

        # ═══════════════════════════════════════════════════════════
        # Step 7: Send Telegram notification
        # ═══════════════════════════════════════════════════════════
        try:
            notification_data = {
                "uid": uid,
                "title": article.get("title", "Unknown"),
                "url": article_url,
                "summary": summary,
                "threat_category": threat_category,
                "severity": severity,
                "iocs": iocs_data,
                "ttps": ttps,
                "threat_actors": threat_actors,
            }
            await self.telegram_bot.send_article_notification(notification_data)
            logger.info(
                f"✓ CTI Alert sent: {uid} | {threat_category} | "
                f"{severity} | {total_iocs} IOCs"
            )
        except Exception as e:
            logger.error(f"Error sending notification for {uid}: {str(e)}")

        logger.info(f"✓ Completed {uid}")


class Scheduler:
    """APScheduler wrapper for pipeline orchestration."""

    def __init__(self, pipeline: Pipeline, db_sync: DatabaseSync = None):
        self.pipeline = pipeline
        self.db_sync = db_sync
        self.settings = get_settings()
        from datetime import timezone as _tz
        self.scheduler = AsyncIOScheduler(timezone=_tz.utc)

    def setup_jobs(self):
        """Register scheduled jobs."""
        # Feed collection — every N minutes
        self.scheduler.add_job(
            self._fetch_feeds,
            "interval",
            minutes=self.settings.feed_fetch_interval,
            id="fetch_feeds",
            name="Fetch RSS feeds"
        )

        # Article processing — every 2 minutes (DeepSeek is fast!)
        self.scheduler.add_job(
            self._process_articles,
            "interval",
            minutes=2,
            id="process_articles",
            name="Process pending articles"
        )

        # Data sync — every 10 minutes
        if self.db_sync:
            self.scheduler.add_job(
                self._sync_data,
                "interval",
                minutes=10,
                id="sync_data",
                name="Sync data to dashboard"
            )

        logger.info(
            f"Scheduled jobs: Feed fetch every {self.settings.feed_fetch_interval} min, "
            f"Article processing every 2 min, Data sync every 10 min"
        )

    async def _fetch_feeds(self):
        """Fetch feeds job."""
        try:
            await self.pipeline.collect_feeds()
        except Exception as e:
            logger.error(f"Error in feed collection job: {str(e)}")

    async def _process_articles(self):
        """Process articles job."""
        try:
            await self.pipeline.process_pending_articles()
        except Exception as e:
            logger.error(f"Error in article processing job: {str(e)}")

    async def _sync_data(self):
        """Sync database to JSON files for dashboard."""
        logger.info("=== Data sync job started ===")
        try:
            success = await self.db_sync.sync_all()
            if success:
                logger.info("Data sync complete")
            else:
                logger.warning("Data sync completed with errors")
        except Exception as e:
            logger.error(f"Error in data sync job: {str(e)}")

    async def start(self):
        """Start scheduler."""
        self.setup_jobs()
        self.scheduler.start()
        logger.info("Scheduler started")

    async def shutdown(self):
        """Shutdown scheduler."""
        self.scheduler.shutdown()
        logger.info("Scheduler stopped")
