"""Configuration for Nexo Sentinel CTI System."""

import os
from typing import List, Optional
from functools import lru_cache
from dotenv import load_dotenv

# Load .env file
load_dotenv()


class FeedConfig:
    """Default RSS feed sources — curated CTI & security feeds."""
    
    SOURCES = [
        # ── Government & National CERTs ──
        {
            "name": "CISA Alerts",
            "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
            "category": "Government"
        },
        {
            "name": "US-CERT Current Activity",
            "url": "https://www.us-cert.gov/ncas/current-activity.xml",
            "category": "Government"
        },

        # ── Security News ──
        {
            "name": "The Hacker News",
            "url": "https://feeds.feedburner.com/TheHackersNews",
            "category": "News"
        },
        {
            "name": "BleepingComputer",
            "url": "https://www.bleepingcomputer.com/feed/",
            "category": "News"
        },
        {
            "name": "Dark Reading",
            "url": "https://www.darkreading.com/rss_simple.asp",
            "category": "News"
        },
        {
            "name": "SecurityWeek",
            "url": "https://www.securityweek.com/feed",
            "category": "News"
        },
        {
            "name": "Krebs on Security",
            "url": "https://krebsonsecurity.com/feed/",
            "category": "News"
        },
        {
            "name": "The Record",
            "url": "https://therecord.media/feed",
            "category": "News"
        },

        # ── Vendor Threat Research ──
        {
            "name": "Microsoft Security Blog",
            "url": "https://www.microsoft.com/en-us/security/blog/feed/",
            "category": "Research"
        },
        {
            "name": "Mandiant Blog",
            "url": "https://www.mandiant.com/resources/blog/rss.xml",
            "category": "Research"
        },
        {
            "name": "SentinelOne Labs",
            "url": "https://www.sentinelone.com/labs/feed/",
            "category": "Research"
        },
        {
            "name": "Palo Alto Unit 42",
            "url": "https://unit42.paloaltonetworks.com/feed/",
            "category": "Research"
        },
        {
            "name": "CrowdStrike Blog",
            "url": "https://www.crowdstrike.com/blog/feed/",
            "category": "Research"
        },
        {
            "name": "Recorded Future",
            "url": "https://www.recordedfuture.com/feed",
            "category": "Research"
        },
        {
            "name": "Securelist (Kaspersky)",
            "url": "https://securelist.com/feed/",
            "category": "Research"
        },
        {
            "name": "ESET WeLiveSecurity",
            "url": "https://www.welivesecurity.com/feed/",
            "category": "Research"
        },
        {
            "name": "Fortinet Threat Research",
            "url": "https://feeds.fortinet.com/fortinet/blog/threat-research",
            "category": "Research"
        },
        {
            "name": "Check Point Research",
            "url": "https://research.checkpoint.com/feed/",
            "category": "Research"
        },
        {
            "name": "Wordfence Blog",
            "url": "https://www.wordfence.com/blog/feed/",
            "category": "Research"
        },
        {
            "name": "Huntress Blog",
            "url": "https://www.huntress.com/blog/rss.xml",
            "category": "Research"
        },

        # ── Exploit & Vulnerability ──
        {
            "name": "Exploit-DB",
            "url": "https://www.exploit-db.com/rss.xml",
            "category": "Exploit"
        },

        # ── Malware & DFIR ──
        {
            "name": "The DFIR Report",
            "url": "https://thedfirreport.com/feed/",
            "category": "DFIR"
        },
        {
            "name": "Any.Run Blog",
            "url": "https://any.run/cybersecurity-blog/feed/",
            "category": "Malware"
        },

        # ── General (Hermes will filter) ──
        {
            "name": "Hacker News",
            "url": "https://news.ycombinator.com/rss",
            "category": "General"
        },
    ]


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)

def _env_int(key: str, default: int = 0) -> int:
    return int(os.environ.get(key, str(default)))

def _env_bool(key: str, default: bool = False) -> bool:
    return os.environ.get(key, str(default)).lower() in ("true", "1", "yes")


class Settings:
    """Application settings from environment variables."""
    
    def __init__(self):
        # Core settings
        self.app_name = "Nexo Sentinel CTI"
        self.debug = _env_bool("DEBUG", False)
        self.database_path = _env("DATABASE_PATH", "nexo_sentinel.db")
        
        # Telegram settings
        self.telegram_token = _env("TELEGRAM_TOKEN")
        self.telegram_user_id = _env_int("TELEGRAM_USER_ID", 0)
        
        # Processing settings
        self.enable_ioc_enrichment = _env_bool("ENABLE_IOC_ENRICHMENT", False)
        self.enable_summarization = _env_bool("ENABLE_SUMMARIZATION", True)
        self.max_crawl_depth = _env_int("MAX_CRAWL_DEPTH", 2)
        self.max_enrichment_per_article = _env_int("MAX_ENRICHMENT_PER_ARTICLE", 10)
        
        # API keys (optional)
        self.virustotal_api_key = _env("VIRUSTOTAL_API_KEY") or None
        self.abuseipdb_api_key = _env("ABUSEIPDB_API_KEY") or None
        
        # Budget settings
        self.virustotal_daily_limit = _env_int("VIRUSTOTAL_DAILY_LIMIT", 400)
        self.abuseipdb_daily_limit = _env_int("ABUSEIPDB_DAILY_LIMIT", 800)
        
        # Timeouts (seconds)
        self.article_download_timeout = _env_int("ARTICLE_DOWNLOAD_TIMEOUT", 30)
        self.link_crawl_timeout = _env_int("LINK_CRAWL_TIMEOUT", 20)
        self.llm_inference_timeout = _env_int("LLM_INFERENCE_TIMEOUT", 120)
        
        # Ollama settings
        self.ollama_base_url = _env("OLLAMA_BASE_URL", "http://localhost:11434")
        self.ollama_model = _env("OLLAMA_MODEL", "hermes3:3b")
        
        # AI mode toggle
        self.hermes_enabled = _env_bool("HERMES_ENABLED", True)
        
        # DeepSeek settings
        self.deepseek_enabled = _env_bool("DEEPSEEK_ENABLED", True)
        self.deepseek_api_key = _env("DEEPSEEK_API_KEY", "")
        self.deepseek_model = _env("DEEPSEEK_MODEL", "deepseek-chat")
        self.deepseek_api_url = _env("DEEPSEEK_API_URL", "https://api.deepseek.com/chat/completions")
        
        # Scheduler settings
        self.feed_fetch_interval = _env_int("FEED_FETCH_INTERVAL", 30)
        
        # API server settings
        self.api_server_host = _env("API_SERVER_HOST", "0.0.0.0")
        self.api_server_port = _env_int("API_SERVER_PORT", 5000)


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Export FeedConfig for easy access
FEED_SOURCES = FeedConfig.SOURCES
