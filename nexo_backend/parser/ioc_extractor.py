"""IOC extraction using iocextract library.

Extracts IOCs locally from full article text using regex-based iocextract.
Filters out private IPs, legitimate domains, and the article's own URL.
No API calls needed — pure regex-based extraction.
"""

import re
import ipaddress
from urllib.parse import urlparse
from loguru import logger

try:
    import iocextract
except ImportError:
    logger.error("iocextract not installed. Run: pip install iocextract")
    iocextract = None


# ─── Whitelist: Legitimate domains to exclude ───
WHITELIST_DOMAINS = {
    # Security vendors
    "microsoft.com", "google.com", "github.com", "crowdstrike.com",
    "mandiant.com", "sentinelone.com", "paloaltonetworks.com", "fortinet.com",
    "checkpoint.com", "trendmicro.com", "eset.com", "kaspersky.com",
    "sophos.com", "malwarebytes.com", "symantec.com", "mcafee.com",
    "fireeye.com", "recorded-future.com", "securelist.com", "resecurity.com",
    # Government / reference
    "fbi.gov", "cisa.gov", "nist.gov", "us-cert.gov", "mitre.org",
    "nsa.gov", "ic3.gov", "europol.europa.eu", "ncsc.gov.uk",
    "justice.gov", "treasury.gov", "state.gov",
    # Infrastructure / WHOIS / DNS
    "icann.org", "whois.com", "webnic.cc", "iwhois.webnic.cc",
    "godaddy.com", "namecheap.com", "cloudflare.com", "akamai.com",
    "domaintools.com", "shodan.io", "censys.io", "virustotal.com",
    "abuseipdb.com", "threatconnect.com", "otx.alienvault.com",
    "urlhaus.abuse.ch", "bazaar.abuse.ch",
    # Social media
    "twitter.com", "x.com", "linkedin.com", "facebook.com",
    "reddit.com", "youtube.com", "t.me", "telegram.org", "instagram.com",
    # Development
    "stackoverflow.com", "gitlab.com", "bitbucket.org", "npmjs.com",
    # News / research
    "bleepingcomputer.com", "thehackernews.com", "therecord.media",
    "krebsonsecurity.com", "darkreading.com", "securityweek.com",
    "any.run", "hybrid-analysis.com", "joesandbox.com",
    "urlscan.io", "abuse.ch",
    # Common benign
    "example.com", "example.org", "example.net",
    "wikipedia.org", "archive.org", "w3.org", "schema.org",
    "apple.com", "amazon.com", "aws.amazon.com",
    "googleapis.com", "gstatic.com", "googleusercontent.com",
    "windows.net", "azure.com", "office.com", "live.com",
}

# ─── Private/internal IP ranges ───
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
]

# CVE regex (iocextract doesn't extract CVEs)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/internal."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return True  # Invalid IP → exclude


def _get_domain(value: str) -> str:
    """Extract domain from a URL or return the value if it's already a domain."""
    try:
        parsed = urlparse(value)
        if parsed.netloc:
            return parsed.netloc.lower().split(":")[0]
    except Exception:
        pass
    return value.lower().strip()


def _is_whitelisted_domain(domain: str, extra_domains: set = None) -> bool:
    """Check if a domain matches any whitelisted domain."""
    domain = domain.lower().strip()
    all_whitelist = WHITELIST_DOMAINS | (extra_domains or set())

    for wd in all_whitelist:
        if domain == wd or domain.endswith("." + wd):
            return True
    return False


def extract_iocs_from_text(text: str, article_url: str = "") -> dict:
    """Extract IOCs from article text using iocextract.

    Args:
        text: Full article text to scan for IOCs.
        article_url: The article's own URL (excluded from results).

    Returns:
        Dict with keys: ipv4, ipv6, domains, urls, md5, sha1, sha256, emails, cves
    """
    if not iocextract:
        logger.warning("iocextract not available, returning empty IOCs")
        return _empty_iocs()

    if not text or len(text) < 20:
        return _empty_iocs()

    # Build extra whitelist from article's own domain
    extra_domains = set()
    if article_url:
        try:
            article_domain = urlparse(article_url).netloc.lower()
            if article_domain:
                extra_domains.add(article_domain)
                parts = article_domain.split(".")
                if len(parts) > 2:
                    extra_domains.add(".".join(parts[-2:]))
        except Exception:
            pass

    # ── Extract all IOC types ──
    try:
        # IPs — refang defanged indicators
        raw_ips = list(iocextract.extract_ips(text, refang=True))
        # URLs
        raw_urls = list(iocextract.extract_urls(text, refang=True))
        # Emails
        raw_emails = list(iocextract.extract_emails(text, refang=True))
        # Hashes (MD5, SHA1, SHA256)
        raw_hashes = list(iocextract.extract_hashes(text))
    except Exception as e:
        logger.error(f"iocextract error: {e}")
        return _empty_iocs()

    # ── Filter IPs ──
    clean_ips = []
    for ip in raw_ips:
        ip = ip.strip()
        if not _is_private_ip(ip):
            clean_ips.append(ip)

    # ── Extract domains from URLs + filter ──
    clean_urls = []
    extracted_domains = set()
    for url in raw_urls:
        url = url.strip()
        if url == article_url or article_url in url:
            continue
        domain = _get_domain(url)
        if _is_whitelisted_domain(domain, extra_domains):
            continue
        clean_urls.append(url)
        if domain:
            extracted_domains.add(domain)

    # ── Also extract standalone domains from text ──
    # Handle both normal and defanged domains (e.g. demo[.]evil[.]com)
    # First defang: replace [.] and (.) with .
    defanged_text = text.replace("[.]", ".").replace("(.)", ".")
    
    domain_pattern = re.compile(
        r"(?<![/@\w])"  # Not preceded by / @ or word char
        r"((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"  # subdomains
        r"[a-zA-Z]{2,63})"  # TLD
        r"(?![/\w])",  # Not followed by / or word char
        re.IGNORECASE
    )
    for match in domain_pattern.finditer(defanged_text):
        domain = match.group(1).lower().strip(".")
        if not _is_whitelisted_domain(domain, extra_domains):
            parts = domain.split(".")
            if len(parts) >= 2 and len(parts[-1]) >= 2:
                extracted_domains.add(domain)

    # Remove domains that are just IPs
    clean_domains = [d for d in extracted_domains if not _looks_like_ip(d)]

    # ── Classify hashes ──
    md5_list, sha1_list, sha256_list = [], [], []
    for h in raw_hashes:
        h = h.strip().lower()
        if len(h) == 32:
            md5_list.append(h)
        elif len(h) == 40:
            sha1_list.append(h)
        elif len(h) == 64:
            sha256_list.append(h)

    # ── Filter emails ──
    clean_emails = []
    for email in raw_emails:
        email = email.strip().lower()
        domain = email.split("@")[-1] if "@" in email else ""
        if not _is_whitelisted_domain(domain, extra_domains):
            clean_emails.append(email)

    # ── Extract CVEs ──
    cves = _unique(CVE_PATTERN.findall(text))

    result = {
        "ipv4": _unique(clean_ips),
        "ipv6": [],
        "domains": _unique(clean_domains),
        "urls": _unique(clean_urls),
        "md5": _unique(md5_list),
        "sha1": _unique(sha1_list),
        "sha256": _unique(sha256_list),
        "emails": _unique(clean_emails),
        "cves": [c.upper() for c in cves],
    }

    total = sum(len(v) for v in result.values())
    logger.info(
        f"iocextract found {total} IOCs: "
        f"{len(result['ipv4'])} IPs, {len(result['domains'])} domains, "
        f"{len(result['urls'])} URLs, {len(result['md5'])} MD5, "
        f"{len(result['sha1'])} SHA1, {len(result['sha256'])} SHA256, "
        f"{len(result['cves'])} CVEs, {len(result['emails'])} emails"
    )

    return result


def _looks_like_ip(s: str) -> bool:
    """Check if a string looks like an IP address."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _unique(items: list) -> list:
    """Deduplicate while preserving order."""
    seen = set()
    out = []
    for item in items:
        if item and isinstance(item, str):
            clean = item.strip()
            if clean and clean not in seen:
                seen.add(clean)
                out.append(clean)
    return out


def _empty_iocs() -> dict:
    """Return empty IOC structure."""
    return {
        "ipv4": [], "ipv6": [], "domains": [], "urls": [],
        "md5": [], "sha1": [], "sha256": [], "emails": [], "cves": [],
    }
