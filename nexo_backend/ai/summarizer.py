"""Article analysis and summarization using DeepSeek API.

Sends full article content to the DeepSeek chat/completions endpoint with
a senior CTI analyst system prompt.  The model returns structured JSON
containing classification, summary, IOCs, TTPs, threat actors, severity,
and category.  Results are persisted to the database.
"""

import asyncio
import aiohttp
import json
import re
from typing import Optional, Dict, List
from loguru import logger
from nexo_backend.config import get_settings
from nexo_backend.db import Database


# ---------------------------------------------------------------------------
# DeepSeek API endpoint and model
# ---------------------------------------------------------------------------
_DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
_DEEPSEEK_MODEL = "deepseek-chat"
_REQUEST_TIMEOUT = 60  # seconds
_MAX_CONTENT_CHARS = 5000  # Truncate content for API (saves tokens)

# ---------------------------------------------------------------------------
# IOC sub-keys expected inside the "iocs" dict
# ---------------------------------------------------------------------------
_IOC_KEYS = {
    "ipv4", "domains", "urls",
    "md5", "sha1", "sha256", "emails", "cves",
}

# ---------------------------------------------------------------------------
# System prompt — the brain of the entire CTI analysis pipeline
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = """\
You are a senior Cyber Threat Intelligence (CTI) analyst with 15+ years of \
experience at a Tier-1 SOC. Your job is to read an article and produce a \
precise, structured JSON analysis. You are methodical, accurate, and never \
speculate beyond the evidence in the text.

IMPORTANT: Do NOT extract IOCs (IPs, domains, hashes, etc.) — IOC extraction \
is handled separately. Focus ONLY on classification, summary, TTPs, and actors.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TASK 1 — CLASSIFY: Is this article security-related?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SECURITY-RELATED (is_security_related = true):
  • Active malware campaigns, ransomware incidents, or wiper attacks
  • Software vulnerabilities (with or without CVE IDs)
  • Zero-day exploits observed in the wild
  • Data breaches involving theft or exposure of sensitive data
  • Named threat actor / APT group operations
  • Phishing or social engineering campaigns
  • Supply chain compromises
  • DDoS attacks against organisations
  • Security patches or advisories addressing exploited flaws
  • Indicators of compromise (IOCs) being shared

NOT SECURITY-RELATED (is_security_related = false):
  • Programming languages, frameworks, libraries, code tutorials
  • Python, JavaScript, Rust, Go, C++ language updates or features
  • Software development, debugging, testing, CI/CD articles
  • Hardware reviews, GPUs, CPUs, benchmarks, PC builds
  • Gaming news, entertainment, sports, culture
  • Business news, startups, funding rounds, acquisitions, earnings
  • General AI/ML research, data science, academic papers
  • Career advice, hiring trends, job market articles
  • Open source project announcements (unless it IS a security tool)
  • Operating system features (unless discussing a security patch)
  • Database administration, web development, DevOps how-tos
  • Product launches, marketing, company culture articles

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TASK 2 — SUMMARISE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Write a comprehensive 3-4 sentence summary that a SOC analyst can act on. \
Focus on: WHAT happened, WHO is responsible, WHAT systems/software are \
affected, and WHAT the impact is. Be specific — include CVE IDs, malware \
family names, and targeted industries when mentioned.

CRITICAL: The summary MUST be complete, well-formed sentences. Every sentence \
MUST end with a period (.). Do NOT end with a comma, ellipsis, or incomplete \
phrase. If you are running out of space, finish the current sentence properly.

If the article is NOT security-related, write a neutral 1-2 sentence summary \
of the topic.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TASK 3 — IDENTIFY TTPs and THREAT ACTORS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  • ttps: List MITRE ATT&CK technique IDs (e.g. T1566.001) with a brief \
    name (e.g. "T1566.002 - Spear-Phishing Link"). Only list TTPs actually \
    described in the article.
  • threat_actors: List named threat actor groups mentioned (e.g. APT28, \
    Lazarus Group, LockBit, Scattered Spider). Include all known aliases. \
    Do NOT guess actors.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TASK 4 — ASSIGN CATEGORY AND SEVERITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

threat_category — choose exactly ONE:
  Malware | Vulnerability | Exploit | Zero-Day | Ransomware | Phishing | \
  APT | Data Breach | DDoS | Supply Chain | Non-Related

severity — choose exactly ONE:
  Critical | High | Medium | Low | Info

Severity guidelines:
  • Critical — Actively exploited zero-day, widespread ransomware, major \
    data breach (millions of records), critical infrastructure attack
  • High — Known exploited vulnerability with patch available, targeted APT \
    campaign, significant data exposure
  • Medium — Newly disclosed vulnerability (not yet exploited), contained \
    phishing campaign, minor data leak
  • Low — Theoretical vulnerability, unsuccessful attack attempt, limited \
    impact incident
  • Info — Security advisories, awareness articles, non-security content

If is_security_related is false, ALWAYS set:
  threat_category = "Non-Related"
  severity = "Info"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OUTPUT FORMAT — Reply with ONLY this JSON, nothing else:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{
  "is_security_related": true,
  "summary": "...",
  "threat_category": "...",
  "severity": "...",
  "ttps": [],
  "threat_actors": []
}
"""


class Summarizer:
    """Generate structured CTI analysis using the DeepSeek API."""

    def __init__(self, db: Database):
        """Initialize summarizer.

        Args:
            db: Database instance for article lookups and updates.
        """
        self.db = db
        self.settings = get_settings()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze_article(self, article_id: int) -> Optional[Dict]:
        """Analyse an article via DeepSeek and return structured CTI data.

        Workflow:
        1. Fetch the article row (title, url, content) from the database.
        2. Send FULL content to DeepSeek with the CTI analyst system prompt.
        3. Parse and validate the JSON response.
        4. Persist the summary and threat metadata in the database.

        Args:
            article_id: Primary-key ID of the article to analyse.

        Returns:
            A dict with keys ``is_security_related``, ``summary``,
            ``threat_category``, ``severity``, ``iocs`` (dict of lists),
            ``ttps`` (list), and ``threat_actors`` (list).
            Returns ``None`` when the article cannot be found, has no
            content, or the API call fails irrecoverably.
        """
        article = await self.db.get_article(article_id)
        if not article:
            logger.error(f"Article {article_id} not found in database")
            return None

        title = article.get("title", "")
        url = article.get("url", "")
        content = article.get("content", "")

        if not content:
            logger.warning(f"No content to analyse for article {article_id}")
            return None

        # Truncate content to save API tokens (ioc-hunter handles full text)
        if len(content) > _MAX_CONTENT_CHARS:
            content = content[:_MAX_CONTENT_CHARS]
            logger.info(f"Truncated content to {_MAX_CONTENT_CHARS} chars for DeepSeek")

        user_message = (
            f"TITLE: {title}\n"
            f"SOURCE URL: {url}\n"
            f"\n"
            f"ARTICLE CONTENT:\n{content}"
        )

        try:
            raw_response = await self._call_deepseek(user_message)

            if raw_response:
                analysis = self._parse_response(raw_response)
                if analysis:
                    # Persist summary to the DB
                    await self.db.update_article_summary(
                        article_id, analysis["summary"]
                    )
                    logger.info(
                        f"DeepSeek analysis complete for article "
                        f"{article.get('uid', article_id)} — "
                        f"security={analysis['is_security_related']}, "
                        f"category={analysis['threat_category']}, "
                        f"severity={analysis['severity']}"
                    )
                    return analysis

            logger.warning(
                f"DeepSeek produced no usable output for article {article_id}"
            )
            return None

        except Exception as e:
            logger.error(
                f"Error analysing article {article_id} via DeepSeek: "
                f"{type(e).__name__}: {e}"
            )
            return None

    async def check_health(self) -> bool:
        """Validate that the DeepSeek API key is configured and working.

        Sends a minimal request to the API and checks for a valid response.

        Returns:
            True if the API responds successfully, False otherwise.
        """
        api_key = self.settings.deepseek_api_key
        if not api_key:
            logger.error("DeepSeek API key is not configured")
            return False

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    _DEEPSEEK_URL,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": _DEEPSEEK_MODEL,
                        "messages": [
                            {"role": "user", "content": "ping"}
                        ],
                        "max_tokens": 5,
                    },
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        logger.info("DeepSeek API health check passed")
                        return True
                    elif resp.status == 401:
                        logger.error(
                            "DeepSeek API key is invalid (401 Unauthorized)"
                        )
                        return False
                    else:
                        body = await resp.text()
                        logger.warning(
                            f"DeepSeek health check returned {resp.status}: "
                            f"{body[:200]}"
                        )
                        return False

        except asyncio.TimeoutError:
            logger.error("DeepSeek health check timed out")
            return False
        except Exception as e:
            logger.error(
                f"DeepSeek health check failed: {type(e).__name__}: {e}"
            )
            return False

    # ------------------------------------------------------------------
    # DeepSeek API communication
    # ------------------------------------------------------------------

    async def _call_deepseek(self, user_message: str) -> Optional[str]:
        """Send a CTI analysis request to the DeepSeek API.

        Args:
            user_message: The formatted article text (title + URL + content).

        Returns:
            The raw content string from the assistant's message, or None
            on error.
        """
        api_key = self.settings.deepseek_api_key
        if not api_key:
            logger.error(
                "DeepSeek API key not set — cannot analyse article. "
                "Set the DEEPSEEK_API_KEY environment variable."
            )
            return None

        payload = {
            "model": _DEEPSEEK_MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": _SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": user_message,
                },
            ],
            "temperature": 0.1,  # Low temp for deterministic extraction
            "max_tokens": 1024,  # Only need summary + classification (no IOCs)
            "response_format": {"type": "json_object"},
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    _DEEPSEEK_URL,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.error(
                            f"DeepSeek API returned {resp.status}: "
                            f"{body[:300]}"
                        )
                        return None

                    data = await resp.json()

                    # DeepSeek response shape:
                    # {"choices": [{"message": {"content": "...json..."}}]}
                    choices = data.get("choices")
                    if not choices or not isinstance(choices, list):
                        logger.error(
                            "DeepSeek response missing 'choices' array"
                        )
                        return None

                    content = (
                        choices[0]
                        .get("message", {})
                        .get("content", "")
                        .strip()
                    )
                    if not content:
                        logger.warning(
                            "DeepSeek returned empty content in response"
                        )
                        return None

                    return content

        except asyncio.TimeoutError:
            logger.error(
                f"DeepSeek API timed out after {_REQUEST_TIMEOUT}s"
            )
            return None
        except aiohttp.ClientError as e:
            logger.error(
                f"DeepSeek API connection error: {type(e).__name__}: {e}"
            )
            return None
        except Exception as e:
            logger.error(
                f"Unexpected error calling DeepSeek: {type(e).__name__}: {e}"
            )
            return None

    # ------------------------------------------------------------------
    # Response parsing — robust multi-strategy JSON extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_response(response_text: str) -> Optional[Dict]:
        """Robustly parse the DeepSeek JSON response into a validated dict.

        Strategy:
        1. Try a direct ``json.loads`` on the full response.
        2. If that fails, strip markdown code fences and retry.
        3. If that fails, extract the outermost ``{ … }`` block and parse.
        4. Validate and back-fill any missing keys with safe defaults.

        Args:
            response_text: Raw content string from DeepSeek.

        Returns:
            A validated analysis dict, or None if parsing fails entirely.
        """
        if not response_text:
            return None

        parsed: Optional[Dict] = None

        # --- Strategy 1: direct parse ---
        try:
            parsed = json.loads(response_text)
        except (json.JSONDecodeError, TypeError):
            pass

        # --- Strategy 2: strip markdown code fences ---
        if parsed is None:
            cleaned = response_text.strip()
            # Remove ```json ... ``` or ``` ... ```
            cleaned = re.sub(
                r"^```(?:json)?\s*\n?", "", cleaned, flags=re.MULTILINE
            )
            cleaned = re.sub(
                r"\n?```\s*$", "", cleaned, flags=re.MULTILINE
            )
            try:
                parsed = json.loads(cleaned.strip())
            except (json.JSONDecodeError, TypeError):
                pass

        # --- Strategy 3: extract outermost JSON object ---
        if parsed is None:
            try:
                start = response_text.index("{")
                end = response_text.rindex("}") + 1
                parsed = json.loads(response_text[start:end])
            except (ValueError, json.JSONDecodeError, TypeError):
                logger.warning(
                    "Failed to extract JSON from DeepSeek response: "
                    f"{response_text[:200]}"
                )
                return None

        if not isinstance(parsed, dict):
            logger.warning("DeepSeek response parsed but is not a dict")
            return None

        # --- Back-fill missing top-level keys with safe defaults ---
        if "is_security_related" not in parsed:
            parsed["is_security_related"] = True

        # Normalise is_security_related to bool
        val = parsed["is_security_related"]
        if isinstance(val, str):
            parsed["is_security_related"] = val.lower() in (
                "true", "yes", "1"
            )

        if "summary" not in parsed:
            parsed["summary"] = ""

        if "threat_category" not in parsed:
            parsed["threat_category"] = (
                "Non-Related"
                if not parsed["is_security_related"]
                else "Unknown"
            )

        if "severity" not in parsed:
            parsed["severity"] = "Info"

        # --- Ensure IOC structure exists and is well-formed ---
        iocs = parsed.get("iocs")
        if not isinstance(iocs, dict):
            parsed["iocs"] = {}
            iocs = parsed["iocs"]

        for key in _IOC_KEYS:
            if key not in iocs or not isinstance(iocs[key], list):
                iocs[key] = []

        # Ensure every IOC value is a list of strings
        for key in _IOC_KEYS:
            iocs[key] = [
                str(item) for item in iocs[key]
                if item is not None
            ]

        # --- Ensure ttps and threat_actors are lists ---
        if not isinstance(parsed.get("ttps"), list):
            parsed["ttps"] = []
        if not isinstance(parsed.get("threat_actors"), list):
            parsed["threat_actors"] = []

        return parsed

    # ------------------------------------------------------------------
    # Fallback — backward compatibility with scheduler
    # ------------------------------------------------------------------

    @staticmethod
    def fallback_summary(
        text: str, title: str = "", max_sentences: int = 3
    ) -> str:
        """Quick extractive summary when no AI is available."""
        sentences = [s.strip() for s in text.split(".") if s.strip()]
        if not sentences:
            return title if title else "No content to summarize"
        summary = ". ".join(sentences[:max_sentences])
        if len(sentences) > max_sentences:
            summary += "..."
        return summary
