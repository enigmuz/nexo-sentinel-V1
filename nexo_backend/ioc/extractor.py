"""IOC (Indicator of Compromise) extraction from article text.

Phase 2 rewrite: adds a comprehensive infrastructure whitelist and
source-aware filtering via ``extract_with_source_filter()`` so that the
article's own domain, the RSS feed domain, and common benign infrastructure
are never reported as IOCs.

The original ``extract_iocs()`` entry-point is kept for backward
compatibility and simply delegates to ``extract_with_source_filter()``
with empty URL parameters.
"""

import re
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse
from loguru import logger
from nexo_backend.db import Database


class IOCExtractor:
    """Extract Indicators of Compromise from text with smart filtering."""

    # ------------------------------------------------------------------
    # Regex patterns for each IOC type
    # ------------------------------------------------------------------
    PATTERNS = {
        "IPv4": (
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
        "IPv6": r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}",
        "Domain": (
            r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
            r"+[a-zA-Z]{2,}"
        ),
        "MD5": r"\b[a-fA-F0-9]{32}\b",
        "SHA1": r"\b[a-fA-F0-9]{40}\b",
        "SHA256": r"\b[a-fA-F0-9]{64}\b",
        "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "CVE": r"CVE-\d{4}-\d{4,}",
        "URL": (
            r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}"
            r"\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)"
        ),
    }

    # ------------------------------------------------------------------
    # Defang restoration patterns
    # ------------------------------------------------------------------
    DEFANG_PATTERNS = {
        "IPv4": [
            (
                r"(\d{1,3})\[\.?\](\d{1,3})\[\.?\](\d{1,3})\[\.?\](\d{1,3})",
                r"\1.\2.\3.\4",
            ),
            (
                r"(\d{1,3})\(dot\)(\d{1,3})\(dot\)(\d{1,3})\(dot\)(\d{1,3})",
                r"\1.\2.\3.\4",
            ),
            (
                r"(\d{1,3})x(\d{1,3})x(\d{1,3})x(\d{1,3})",
                r"\1.\2.\3.\4",
            ),
        ],
        "Domain": [
            (r"([\w-]+)\[\.\]([\w.-]+)", r"\1.\2"),
            (r"([\w-]+)\(dot\)([\w.-]+)", r"\1.\2"),
            (r"([\w-]+)hxxp(s)?://([\w.-]+)", r"\1http\2://\3"),
        ],
        "URL": [
            (r"hxxp(s)?://", r"http\1://"),
            (r"([\w-]+)\[\.\]([\w.-]+)", r"\1.\2"),
        ],
    }

    # ------------------------------------------------------------------
    # Basic false-positive whitelist (per-type)
    # ------------------------------------------------------------------
    WHITELIST = {
        "IPv4": ["127.0.0.1", "0.0.0.0", "255.255.255.255"],
        "Domain": ["localhost", "example.com", "test.com", "example.org"],
        "Email": ["test@example.com", "admin@example.com"],
    }

    # ------------------------------------------------------------------
    # Large infrastructure whitelist — domains that are NEVER real IOCs
    # ------------------------------------------------------------------
    INFRASTRUCTURE_WHITELIST: Set[str] = {
        # Social media
        "twitter.com", "x.com", "facebook.com", "linkedin.com", "reddit.com",
        "youtube.com", "instagram.com", "tiktok.com", "mastodon.social",
        # Tech platforms
        "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
        # Cloud providers
        "google.com", "googleapis.com", "gstatic.com",
        "microsoft.com", "azure.com", "windows.net", "live.com",
        "outlook.com",
        "amazon.com", "amazonaws.com", "aws.amazon.com",
        "cloudflare.com", "cloudfront.net",
        # Security vendors & feeds (sources, not IOCs)
        "talosintelligence.com", "thehackernews.com",
        "bleepingcomputer.com", "krebsonsecurity.com", "threatpost.com",
        "darkreading.com", "securityweek.com",
        "cisa.gov", "us-cert.cisa.gov", "nist.gov",
        "virustotal.com", "abuseipdb.com", "shodan.io",
        "mitre.org", "attack.mitre.org", "cve.mitre.org",
        # News & content
        "news.ycombinator.com", "ycombinator.com", "techcrunch.com",
        "arstechnica.com", "wired.com", "bbc.com", "reuters.com",
        "wikipedia.org", "medium.com", "substack.com",
        # CDNs and common infra
        "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
        "fonts.googleapis.com", "fonts.gstatic.com",
        "gravatar.com", "wp.com", "wordpress.com",
        # Other common
        "t.co", "bit.ly", "youtu.be", "archive.org",
        "pastebin.com", "gist.github.com",
    }

    # ------------------------------------------------------------------
    # Constructor
    # ------------------------------------------------------------------

    def __init__(self, db: Database):
        """Initialize IOC extractor.

        Args:
            db: Database instance for persisting extracted IOCs.
        """
        self.db = db

    # ------------------------------------------------------------------
    # Public API — source-aware extraction (Phase 2)
    # ------------------------------------------------------------------

    async def extract_with_source_filter(
        self,
        article_id: int,
        text: str,
        article_url: str = "",
        feed_url: str = "",
        source: str = "main_content",
    ) -> Dict[str, List[str]]:
        """Extract IOCs from *text*, filtering out infrastructure noise.

        This method:
        1. Runs the standard regex-based extraction + defang + validation
           pipeline for every IOC type.
        2. Builds a **combined whitelist** from:
           - The static ``INFRASTRUCTURE_WHITELIST``
           - The article's own domain (parsed from *article_url*)
           - The RSS feed's domain (parsed from *feed_url*)
        3. Removes any Domain or URL IOC whose domain matches (or is a
           subdomain of) an entry in the combined whitelist.
        4. Persists surviving IOCs in the database.

        Args:
            article_id:  Primary-key ID of the article being processed.
            text:        Body text to scan for IOCs.
            article_url: Full URL of the article (used for filtering).
            feed_url:    Full URL of the RSS feed (used for filtering).
            source:      Label for the content origin (``main_content``,
                         ``linked_page_1``, etc.).

        Returns:
            ``{ioc_type: [values…]}`` dict of extracted & filtered IOCs.
        """
        # Build the combined whitelist for this invocation
        dynamic_whitelist = set(self.INFRASTRUCTURE_WHITELIST)

        for url in (article_url, feed_url):
            domain = self._extract_domain(url)
            if domain:
                dynamic_whitelist.add(domain)

        extracted: Dict[str, List[str]] = {}

        for ioc_type, pattern in self.PATTERNS.items():
            try:
                matches = self._extract_type(text, ioc_type, pattern)

                # Apply infrastructure whitelist to domain-bearing types
                if ioc_type in ("Domain", "URL"):
                    matches = self._filter_whitelisted(
                        matches, ioc_type, dynamic_whitelist
                    )

                # Persist to database
                added_count = 0
                for ioc_value in matches:
                    ioc_id = await self.db.add_ioc(
                        article_id=article_id,
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        source=source,
                    )
                    if ioc_id:
                        added_count += 1

                if added_count > 0:
                    extracted[ioc_type] = matches
                    logger.debug(
                        f"Extracted {added_count} {ioc_type} IOCs "
                        f"from {source}"
                    )
            except Exception as e:
                logger.error(f"Error extracting {ioc_type}: {e}")
                continue

        return extracted

    # ------------------------------------------------------------------
    # Public API — backward-compatible entry-point
    # ------------------------------------------------------------------

    async def extract_iocs(
        self,
        article_id: int,
        text: str,
        source: str = "main_content",
    ) -> Dict[str, List[str]]:
        """Extract IOCs from article text (backward-compatible wrapper).

        Delegates to :meth:`extract_with_source_filter` with empty URL
        parameters so the infrastructure whitelist is still applied but no
        dynamic source-domain filtering occurs.

        Args:
            article_id: Article ID.
            text:       Article text to extract from.
            source:     Source of text (``main_content``, ``linked_page_N``,
                        etc.).

        Returns:
            ``{ioc_type: [values…]}`` dict of extracted IOCs.
        """
        return await self.extract_with_source_filter(
            article_id=article_id,
            text=text,
            article_url="",
            feed_url="",
            source=source,
        )

    # ------------------------------------------------------------------
    # Internal helpers — extraction pipeline
    # ------------------------------------------------------------------

    def _extract_type(
        self, text: str, ioc_type: str, pattern: str
    ) -> List[str]:
        """Extract a specific IOC type using regex.

        Performs defanging, matching, normalisation, basic whitelist
        filtering, and per-type validation.

        Args:
            text:     Text to search.
            ioc_type: IOC category name.
            pattern:  Compiled regex pattern string.

        Returns:
            Sorted list of unique, validated IOC values.
        """
        # Restore defanged indicators first
        defanged_text = self._attempt_defang(text, ioc_type)

        matches = re.findall(pattern, defanged_text, re.IGNORECASE)

        unique_iocs: set = set()
        for match in matches:
            # Handle tuple results from grouped regex
            if isinstance(match, tuple):
                ioc_value = "".join(filter(None, match))
            else:
                ioc_value = match

            # Normalise case
            ioc_value = (
                ioc_value.upper() if ioc_type == "CVE" else ioc_value.lower()
            )

            # Basic whitelist check
            if self._is_whitelisted(ioc_type, ioc_value):
                continue

            # Per-type format validation
            if self._validate_ioc(ioc_type, ioc_value):
                unique_iocs.add(ioc_value)

        return sorted(unique_iocs)

    def _attempt_defang(self, text: str, ioc_type: str) -> str:
        """Restore defanged IOCs in *text* for a given type.

        Args:
            text:     Potentially defanged text.
            ioc_type: IOC category name.

        Returns:
            Text with defanged indicators restored.
        """
        if ioc_type not in self.DEFANG_PATTERNS:
            return text

        result = text
        for pattern, replacement in self.DEFANG_PATTERNS[ioc_type]:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        return result

    def _is_whitelisted(self, ioc_type: str, ioc_value: str) -> bool:
        """Check if *ioc_value* is in the basic per-type whitelist.

        Args:
            ioc_type:  IOC category name.
            ioc_value: Candidate IOC value.

        Returns:
            ``True`` if the value should be excluded.
        """
        if ioc_type not in self.WHITELIST:
            return False
        return ioc_value.lower() in [w.lower() for w in self.WHITELIST[ioc_type]]

    # ------------------------------------------------------------------
    # Internal helpers — infrastructure filtering
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_domain(url: str) -> Optional[str]:
        """Parse a URL and return its lowercased hostname (or ``None``).

        Args:
            url: A full URL string, e.g.
                 ``https://news.ycombinator.com/item?id=123``.

        Returns:
            The hostname part (e.g. ``news.ycombinator.com``), or ``None``
            if parsing fails.
        """
        if not url:
            return None
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            return host.lower() if host else None
        except Exception:
            return None

    @staticmethod
    def _is_domain_whitelisted(
        domain: str, whitelist: Set[str]
    ) -> bool:
        """Return ``True`` if *domain* matches or is a subdomain of any
        entry in *whitelist*.

        Examples:
            - ``"news.ycombinator.com"`` is whitelisted by
              ``"ycombinator.com"``
            - ``"evil.com"`` is NOT whitelisted by ``"notevil.com"``

        Args:
            domain:    Candidate domain in lowercase.
            whitelist: Set of whitelisted root domains in lowercase.

        Returns:
            ``True`` if the domain should be excluded.
        """
        domain = domain.lower()
        for entry in whitelist:
            if domain == entry or domain.endswith("." + entry):
                return True
        return False

    @classmethod
    def _filter_whitelisted(
        cls,
        ioc_values: List[str],
        ioc_type: str,
        whitelist: Set[str],
    ) -> List[str]:
        """Remove domain/URL IOCs that belong to whitelisted infrastructure.

        For ``Domain`` IOCs the value itself is checked.  For ``URL`` IOCs
        the hostname is extracted first.

        Args:
            ioc_values: List of candidate IOC strings.
            ioc_type:   ``"Domain"`` or ``"URL"``.
            whitelist:  Combined set of whitelisted root domains.

        Returns:
            Filtered list with whitelisted entries removed.
        """
        filtered: List[str] = []
        for value in ioc_values:
            if ioc_type == "Domain":
                if cls._is_domain_whitelisted(value, whitelist):
                    continue
            elif ioc_type == "URL":
                domain = cls._extract_domain(value)
                if domain and cls._is_domain_whitelisted(domain, whitelist):
                    continue
            filtered.append(value)
        return filtered

    # ------------------------------------------------------------------
    # Per-type validation (kept from Phase 1)
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_ioc(ioc_type: str, ioc_value: str) -> bool:
        """Validate an IOC value against type-specific format rules.

        Args:
            ioc_type:  IOC category name.
            ioc_value: Candidate IOC value.

        Returns:
            ``True`` if the value passes validation.
        """
        if not ioc_value or len(ioc_value) < 3:
            return False

        if ioc_type == "IPv4":
            parts = ioc_value.split(".")
            if len(parts) != 4:
                return False
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False

        elif ioc_type == "IPv6":
            return ":" in ioc_value and len(ioc_value) >= 3

        elif ioc_type == "Domain":
            return (
                len(ioc_value) >= 4
                and "." in ioc_value
                and not ioc_value.startswith(".")
                and not ioc_value.endswith(".")
            )

        elif ioc_type == "Email":
            return "@" in ioc_value and "." in ioc_value.split("@")[1]

        elif ioc_type in ("MD5", "SHA1", "SHA256"):
            expected_lengths = {"MD5": 32, "SHA1": 40, "SHA256": 64}
            if len(ioc_value) != expected_lengths[ioc_type]:
                return False
            return all(c in "0123456789abcdef" for c in ioc_value)

        elif ioc_type == "CVE":
            return bool(
                re.match(r"CVE-\d{4}-\d{4,}", ioc_value, re.IGNORECASE)
            )

        elif ioc_type == "URL":
            return ioc_value.startswith(("http://", "https://"))

        return True
