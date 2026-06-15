-- Nexo Sentinel CTI System Database Schema

-- Feed sources configuration
CREATE TABLE IF NOT EXISTS feed_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    category TEXT,
    enabled INTEGER DEFAULT 1,
    last_fetched TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Articles extracted from feeds
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT NOT NULL UNIQUE,  -- NEXO-YYYY-NNNNN format
    title TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    content TEXT,
    summary TEXT,
    source_feed_id INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',  -- pending, parsed, ioc_extracted, enriched, complete
    published_date TIMESTAMP,
    fetched_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    parsed_date TIMESTAMP,
    ioc_count INTEGER DEFAULT 0,
    threat_category TEXT DEFAULT 'Info',  -- Malware, Phishing, Vulnerability, Ransomware, APT, Data Breach, Info
    severity TEXT DEFAULT 'Info',  -- Critical, High, Medium, Low, Info
    ttps TEXT DEFAULT '[]',  -- JSON array of MITRE ATT&CK IDs
    threat_actors TEXT DEFAULT '[]',  -- JSON array of actor names
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_feed_id) REFERENCES feed_sources(id)
);

-- IOCs (Indicators of Compromise)
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL,  -- IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, Email, CVE
    ioc_value TEXT NOT NULL,
    ioc_value_hash TEXT NOT NULL,  -- SHA256 hash for deduplication
    original_value TEXT,  -- Original defanged value
    source TEXT,  -- 'main_content', 'linked_page_1', etc.
    confidence INTEGER DEFAULT 100,  -- 0-100
    is_malicious INTEGER DEFAULT 0,  -- From enrichment
    last_enriched TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(article_id, ioc_value_hash),
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE
);

-- IOC enrichment results
CREATE TABLE IF NOT EXISTS ioc_enrichment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id INTEGER NOT NULL,
    source TEXT NOT NULL,  -- 'virustotal', 'abuseipdb', etc.
    verdict TEXT,  -- 'malicious', 'suspicious', 'clean', 'unknown'
    detection_count INTEGER,
    vendor_count INTEGER,
    raw_result TEXT,  -- JSON
    enriched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
);

-- Global IOC cache for cross-article deduplication
CREATE TABLE IF NOT EXISTS ioc_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_value_hash TEXT NOT NULL UNIQUE,
    ioc_type TEXT NOT NULL,
    article_count INTEGER DEFAULT 1,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_known_malicious INTEGER DEFAULT 0
);

-- Enrichment budget tracking
CREATE TABLE IF NOT EXISTS enrichment_budget (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date DATE NOT NULL UNIQUE,
    virustotal_used INTEGER DEFAULT 0,
    virustotal_limit INTEGER DEFAULT 400,
    abuseipdb_used INTEGER DEFAULT 0,
    abuseipdb_limit INTEGER DEFAULT 800,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Linked pages crawled from articles
CREATE TABLE IF NOT EXISTS linked_pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    depth INTEGER,
    content TEXT,
    extracted_iocs INTEGER DEFAULT 0,
    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE
);

-- Processing log for audit trail
CREATE TABLE IF NOT EXISTS processing_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER,
    operation TEXT NOT NULL,  -- 'fetch', 'parse', 'extract_iocs', 'enrich', 'summarize'
    status TEXT NOT NULL,  -- 'success', 'failure'
    error_message TEXT,
    duration_ms INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE
);

-- Telegram users and their preferences
CREATE TABLE IF NOT EXISTS telegram_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id INTEGER NOT NULL UNIQUE,
    telegram_name TEXT,
    is_admin INTEGER DEFAULT 0,
    notifications_enabled INTEGER DEFAULT 1,
    last_activity TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Track which IOCs each user has downloaded (for CSV export deduplication)
CREATE TABLE IF NOT EXISTS user_ioc_downloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_user_id INTEGER NOT NULL,
    ioc_id INTEGER NOT NULL,
    download_type TEXT,  -- 'all_iocs', 'new_iocs', 'article_iocs'
    downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(telegram_user_id, ioc_id),
    FOREIGN KEY (telegram_user_id) REFERENCES telegram_users(telegram_id),
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_articles_status ON articles(status);
CREATE INDEX IF NOT EXISTS idx_articles_fetched_date ON articles(fetched_date);
CREATE INDEX IF NOT EXISTS idx_articles_severity ON articles(severity);
CREATE INDEX IF NOT EXISTS idx_articles_threat_category ON articles(threat_category);
CREATE INDEX IF NOT EXISTS idx_iocs_article_id ON iocs(article_id);
CREATE INDEX IF NOT EXISTS idx_iocs_ioc_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_enrichment_ioc_id ON ioc_enrichment(ioc_id);
CREATE INDEX IF NOT EXISTS idx_linked_pages_article_id ON linked_pages(article_id);
CREATE INDEX IF NOT EXISTS idx_processing_log_article_id ON processing_log(article_id);
CREATE INDEX IF NOT EXISTS idx_user_ioc_downloads_user ON user_ioc_downloads(telegram_user_id);

-- Enable WAL mode for concurrent access
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -64000;
