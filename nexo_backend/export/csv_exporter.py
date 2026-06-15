"""CSV export functionality with user-based deduplication."""

import csv
import io
from typing import List, Dict, Tuple
from datetime import datetime
from loguru import logger
from nexo_backend.db import Database


class CSVExporter:
    """Generate CSV exports of IOCs with user tracking to prevent duplicates."""

    def __init__(self, db: Database):
        """Initialize CSV exporter.
        
        Args:
            db: Database instance
        """
        self.db = db

    async def export_all_iocs(self, telegram_user_id: int) -> Tuple[bytes, str]:
        """Export all IOCs not previously downloaded by user.
        
        Args:
            telegram_user_id: Telegram user ID for download tracking
            
        Returns:
            Tuple of (CSV bytes, filename)
        """
        iocs = await self.db.get_undownloaded_iocs(telegram_user_id)
        
        if not iocs:
            logger.info(f"No new IOCs for user {telegram_user_id}")
            return b"", "empty.csv"
        
        # Extract IOC IDs and mark as downloaded
        ioc_ids = [ioc["id"] for ioc in iocs]
        await self.db.mark_iocs_as_downloaded(
            telegram_user_id,
            ioc_ids,
            download_type="all_iocs"
        )
        
        # Generate CSV
        csv_bytes = self._generate_csv(iocs)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nexo_all_iocs_{timestamp}.csv"
        
        logger.info(f"Exported {len(iocs)} IOCs to {filename} for user {telegram_user_id}")
        
        return csv_bytes, filename

    async def export_new_iocs(self, telegram_user_id: int) -> Tuple[bytes, str]:
        """Export only IOCs added since user's last download.
        
        Args:
            telegram_user_id: Telegram user ID for download tracking
            
        Returns:
            Tuple of (CSV bytes, filename)
        """
        iocs = await self.db.get_new_iocs_since_last_download(telegram_user_id)
        
        if not iocs:
            logger.info(f"No new IOCs since last download for user {telegram_user_id}")
            return b"", "empty.csv"
        
        # Extract IOC IDs and mark as downloaded
        ioc_ids = [ioc["id"] for ioc in iocs]
        await self.db.mark_iocs_as_downloaded(
            telegram_user_id,
            ioc_ids,
            download_type="new_iocs"
        )
        
        # Generate CSV
        csv_bytes = self._generate_csv(iocs)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nexo_new_iocs_{timestamp}.csv"
        
        logger.info(f"Exported {len(iocs)} new IOCs to {filename} for user {telegram_user_id}")
        
        return csv_bytes, filename

    async def export_article_iocs(
        self,
        article_id: int,
        telegram_user_id: int
    ) -> Tuple[bytes, str]:
        """Export IOCs for specific article not previously downloaded by user.
        
        Args:
            article_id: Article ID
            telegram_user_id: Telegram user ID for download tracking
            
        Returns:
            Tuple of (CSV bytes, filename)
        """
        iocs = await self.db.get_article_iocs_undownloaded(article_id, telegram_user_id)
        
        if not iocs:
            logger.info(f"No new IOCs for article {article_id} and user {telegram_user_id}")
            return b"", "empty.csv"
        
        # Extract IOC IDs and mark as downloaded
        ioc_ids = [ioc["id"] for ioc in iocs]
        await self.db.mark_iocs_as_downloaded(
            telegram_user_id,
            ioc_ids,
            download_type="article_iocs"
        )
        
        # Generate CSV
        csv_bytes = self._generate_csv(iocs)
        
        article = await self.db.get_article(article_id)
        article_uid = article["uid"] if article else "unknown"
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nexo_iocs_{article_uid}_{timestamp}.csv"
        
        logger.info(f"Exported {len(iocs)} IOCs for article {article_uid} to {filename}")
        
        return csv_bytes, filename

    @staticmethod
    def _generate_csv(iocs: List[Dict]) -> bytes:
        """Generate CSV content from IOC data.
        
        Args:
            iocs: List of IOC dictionaries
            
        Returns:
            CSV as bytes
        """
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "IOC_Type",
                "IOC_Value",
                "Article_ID",
                "Article_Name",
                "Article_URL",
                "Article_Date",
                "Source_Feed",
                "Extracted_From"
            ]
        )
        
        writer.writeheader()
        
        for ioc in iocs:
            writer.writerow({
                "IOC_Type": ioc.get("ioc_type", ""),
                "IOC_Value": ioc.get("ioc_value", ""),
                "Article_ID": ioc.get("uid", ""),
                "Article_Name": ioc.get("title", ""),
                "Article_URL": ioc.get("url", ""),
                "Article_Date": ioc.get("published_date", ""),
                "Source_Feed": ioc.get("feed_name", ""),
                "Extracted_From": ioc.get("source", "main_content")
            })
        
        return output.getvalue().encode("utf-8")

    @staticmethod
    def _format_csv_message(filename: str, ioc_count: int) -> str:
        """Format message for Telegram about CSV export.
        
        Args:
            filename: CSV filename
            ioc_count: Number of IOCs in export
            
        Returns:
            Message string
        """
        return f"📥 **IOC Export Complete**\n\nFile: `{filename}`\nIOCs: {ioc_count}\n\nColumns: IOC_Type, IOC_Value, Article_ID, Article_Name, Article_URL, Article_Date, Source_Feed"
