"""Article text extraction — downloads full content from URL."""

import re
import asyncio
from typing import List, Tuple, Optional, Dict
from loguru import logger
from nexo_backend.config import get_settings
from nexo_backend.db import Database


class ArticleParser:
    """Download and extract full article text from URLs."""

    def __init__(self, db: Database):
        self.db = db
        self.settings = get_settings()

    async def parse_article(self, article_id: int) -> Tuple[str, List[str]]:
        """Download full article content from URL and extract text.
        
        Args:
            article_id: Article ID in database
            
        Returns:
            Tuple of (extracted_text, list_of_links)
        """
        article = await self.db.get_article(article_id)
        if not article:
            raise ValueError(f"Article {article_id} not found")

        url = article.get("url", "")
        rss_snippet = article.get("content", "")
        title = article.get("title", "")

        # --- Step 1: Download full article from URL ---
        full_text = None
        if url:
            full_text = await self._fetch_full_article(url)

        # --- Step 2: Use full text, or fall back to RSS snippet ---
        if full_text and len(full_text) > len(rss_snippet):
            extracted_text = full_text
            logger.info(
                f"Downloaded full article {article['uid']}: "
                f"{len(extracted_text)} chars from URL"
            )
        else:
            extracted_text = rss_snippet
            logger.warning(
                f"Using RSS snippet for {article['uid']}: "
                f"{len(extracted_text)} chars (download failed or empty)"
            )

        # --- Step 3: Keep full text for IOC extraction ---
        full_text_for_iocs = extracted_text  # Before any truncation

        # --- Step 4: Store full content (DeepSeek API handles large text) ---
        # NOTE: Old Hermes 3B truncated to 4000 chars. DeepSeek can handle full articles.

        # --- Step 5: Update DB with FULL content ---
        await self.db.execute(
            "UPDATE articles SET content = ?, parsed_date = CURRENT_TIMESTAMP WHERE id = ?",
            (extracted_text, article_id)
        )

        # Extract links from content
        links = self._extract_links(extracted_text)

        logger.info(
            f"Parsed article {article['uid']}: "
            f"{len(extracted_text)} chars, {len(links)} links"
            f" (full: {len(full_text_for_iocs)} chars)"
        )

        return extracted_text, links, full_text_for_iocs

    async def _fetch_full_article(self, url: str) -> Optional[str]:
        """Download and extract full article text using trafilatura.
        
        Args:
            url: Article URL
            
        Returns:
            Extracted text or None
        """
        try:
            from trafilatura import fetch_url, extract

            loop = asyncio.get_event_loop()

            # Download HTML (with timeout via trafilatura)
            downloaded = await loop.run_in_executor(
                None,
                lambda: fetch_url(url)
            )

            if not downloaded:
                logger.debug(f"Could not download: {url}")
                return None

            # Extract main text content
            text = await loop.run_in_executor(
                None,
                lambda: extract(
                    downloaded,
                    include_comments=False,
                    include_tables=True,
                    output_format="txt",
                    favor_precision=True,
                )
            )

            return text if text and len(text) > 50 else None

        except Exception as e:
            logger.warning(f"Error fetching article {url}: {str(e)}")
            return None

    @staticmethod
    def _extract_links(text: str) -> List[str]:
        """Extract URLs from text content."""
        url_pattern = r'https?://[^\s<>"\')]+' 
        links = re.findall(url_pattern, text)
        return list(set(links))[:20]  # Dedupe, max 20
