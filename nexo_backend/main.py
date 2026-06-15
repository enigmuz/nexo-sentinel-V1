"""Nexo Sentinel CTI System v2 — Main entry point.

Runs the complete system:
- RSS feed collector
- Article parser + DeepSeek AI analysis
- IOC extractor (AI-powered with regex fallback)
- Telegram bot
- REST API server (for dashboard)
- Data sync to JSON files
"""

import asyncio
import sys
import signal
import threading
from pathlib import Path
from loguru import logger

from nexo_backend.logger import logger as setup_logger
from nexo_backend.config import get_settings
from nexo_backend.db import Database
from nexo_backend.feed import FeedCollector
from nexo_backend.parser import ArticleParser
from nexo_backend.ioc import IOCExtractor
from nexo_backend.ai import Summarizer
from nexo_backend.telegram import TelegramBot
from nexo_backend.scheduler import Pipeline, Scheduler
from nexo_backend.sync import DatabaseSync


class NexoSentinel:
    """Main application class — runs the entire CTI system."""

    def __init__(self):
        """Initialize all components."""
        self.settings = get_settings()
        self.db = Database(self.settings.database_path)
        self.telegram_bot = TelegramBot(self.db)
        self.feed_collector = FeedCollector(self.db)
        self.parser = ArticleParser(self.db)
        self.ioc_extractor = IOCExtractor(self.db)
        self.summarizer = Summarizer(self.db)
        self.db_sync = DatabaseSync(self.db, "public/data")
        self.pipeline = None
        self.scheduler = None
        self.running = False

    async def initialize(self):
        """Initialize all components and verify connections."""
        logger.info("=" * 60)
        logger.info("NEXO SENTINEL CTI SYSTEM v2")
        logger.info("DeepSeek AI-Powered Pipeline")
        logger.info("=" * 60)

        # Initialize database
        logger.info("Initializing database...")
        await self.db.initialize()
        logger.info("[OK] Database initialized")

        # Initialize feed sources (auto-populate from config if empty)
        await self.feed_collector.initialize_feed_sources()
        feeds = await self.db.get_feed_sources()
        logger.info(f"[OK] {len(feeds)} feed sources configured")

        # Initialize Telegram bot
        logger.info("Initializing Telegram bot...")
        try:
            await self.telegram_bot.initialize()
            logger.info("[OK] Telegram bot initialized")
        except Exception as e:
            logger.error(f"[WARN] Telegram bot init error: {str(e)}")

        # Check DeepSeek API connectivity
        if self.settings.deepseek_enabled:
            logger.info("Checking DeepSeek API connectivity...")
            is_healthy = await self.summarizer.check_health()
            if is_healthy:
                logger.info("[OK] DeepSeek API ready")
            else:
                logger.warning(
                    "[WARN] DeepSeek API not reachable "
                    "- will use regex fallback for IOC extraction"
                )
        else:
            logger.info("[INFO] DeepSeek AI not configured (no API key), using regex extraction")

        # Build pipeline
        try:
            self.pipeline = Pipeline(
                self.db,
                self.feed_collector,
                self.parser,
                self.ioc_extractor,
                self.summarizer,
                self.telegram_bot,
            )
            self.scheduler = Scheduler(self.pipeline, self.db_sync)
            logger.info("[OK] Pipeline and scheduler configured")
        except Exception as e:
            logger.error(f"Failed to create pipeline: {str(e)}")
            raise

        logger.info("=" * 60)
        logger.info("INITIALIZATION COMPLETE")
        logger.info("=" * 60)

    async def run(self):
        """Run the system."""
        self.running = True

        try:
            await self.initialize()

            # Send startup message via Telegram
            await self.telegram_bot.send_message_to_admin(
                "🟢 <b>Nexo Sentinel v2 started</b>\n\n"
                "🤖 DeepSeek AI: " + ("Enabled" if self.settings.deepseek_enabled else "Disabled") + "\n"
                "📡 Feeds: Monitoring\n"
                "📊 Dashboard API: http://0.0.0.0:" + str(self.settings.api_server_port) + "\n\n"
                "Send /help for commands.",
                parse_mode="HTML"
            )

            # Start Telegram bot polling
            bot_task = asyncio.create_task(self.telegram_bot.start_polling())

            # Start scheduler
            scheduler_task = asyncio.create_task(self.scheduler.start())

            # Start API server in a separate thread
            api_thread = threading.Thread(target=self._start_api_server, daemon=True)
            api_thread.start()
            logger.info(f"[OK] API server started on {self.settings.api_server_host}:{self.settings.api_server_port}")

            logger.info("All services started. Entering main loop...")

            # Trigger immediate feed fetch
            logger.info("Triggering initial feed fetch...")
            asyncio.create_task(self._initial_fetch())

            # Keep running
            while self.running:
                await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Fatal error: {str(e)}")
            await self.shutdown()
            sys.exit(1)

    async def _initial_fetch(self):
        """Run initial feed fetch and article processing on startup."""
        try:
            await asyncio.sleep(5)  # Let services initialize

            logger.info("=== Initial feed fetch started ===")
            results = await self.feed_collector.collect_feeds()
            total = sum(results.values())
            logger.info(f"Initial fetch complete: {total} articles from {len(results)} feeds")

            if total > 0:
                await asyncio.sleep(2)
                await self.pipeline.process_pending_articles()

                # Sync data to dashboard
                await self.db_sync.sync_all()
                logger.info("Initial data sync complete")
        except Exception as e:
            logger.error(f"Error in initial fetch: {str(e)}")

    def _start_api_server(self):
        """Start the Flask API server in a separate thread."""
        try:
            from nexo_backend.api_server import create_app
            app = create_app(self.db)
            app.run(
                host=self.settings.api_server_host,
                port=self.settings.api_server_port,
                debug=False,
                use_reloader=False,
            )
        except ImportError:
            logger.warning("Flask not installed — API server disabled. Install with: pip install flask flask-cors")
        except Exception as e:
            logger.error(f"API server error: {str(e)}")

    async def shutdown(self):
        """Graceful shutdown."""
        logger.info("\n" + "=" * 60)
        logger.info("SHUTTING DOWN NEXO SENTINEL")
        logger.info("=" * 60)

        self.running = False

        try:
            logger.info("Stopping Telegram bot...")
            await self.telegram_bot.stop()

            logger.info("Shutting down scheduler...")
            await self.scheduler.shutdown()

            await self.telegram_bot.send_message_to_admin(
                "🔴 Nexo Sentinel shutdown complete.",
                parse_mode="HTML"
            )
        except Exception as e:
            logger.error(f"Error during shutdown: {str(e)}")

        logger.info("Shutdown complete")


def main():
    """Entry point."""
    app = NexoSentinel()

    # Handle graceful shutdown
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(app.run())
    except KeyboardInterrupt:
        logger.info("\nReceived keyboard interrupt")
        loop.run_until_complete(app.shutdown())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
