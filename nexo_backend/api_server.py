"""Flask REST API server for Nexo Sentinel dashboard.

Serves threat intelligence data from SQLite for the web dashboard.
"""

import asyncio
import json
from datetime import datetime, timezone
from flask import Flask, jsonify, request
from flask_cors import CORS
from loguru import logger

from nexo_backend.config import get_settings
from nexo_backend.db import Database


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_async(coro):
    """Run an async coroutine from sync Flask context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _serialize_row(row: dict) -> dict:
    """Ensure all values in a row dict are JSON-serializable."""
    out = {}
    for key, value in row.items():
        if isinstance(value, datetime):
            out[key] = value.isoformat()
        else:
            out[key] = value
    return out


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(db: Database = None) -> Flask:
    """Create and configure the Flask application.
    
    Args:
        db: Optional Database instance. If not provided, creates a new one.
    """
    settings = get_settings()
    if db is None:
        db = Database(settings.database_path)

    app = Flask(__name__)
    # SECURITY: Restrict CORS to localhost only (no wildcard)
    CORS(app, origins=["http://localhost:*", "http://127.0.0.1:*"])
    
    # SECURITY: Disable debug mode, suppress server header
    app.config['PROPAGATE_EXCEPTIONS'] = False

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------
    @app.route("/api/health")
    def health():
        return jsonify({
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    @app.route("/api/statistics")
    def statistics():
        try:
            stats = _run_async(db.get_statistics())
            return jsonify(stats)
        except Exception as exc:
            logger.error(f"Error fetching statistics: {exc}")
            return jsonify({"error": "Internal server error"}), 500

    # ------------------------------------------------------------------
    # Articles
    # ------------------------------------------------------------------
    @app.route("/api/articles")
    def articles_list():
        try:
            limit = min(request.args.get("limit", 50, type=int), 200)
            status = request.args.get("status")
            severity = request.args.get("severity")
            category = request.args.get("category")
            
            # Input validation
            valid_severities = {"Critical", "High", "Medium", "Low", "Info"}
            valid_statuses = {"pending", "processed", "ignored", "error"}
            if severity and severity not in valid_severities:
                return jsonify({"error": "Invalid severity"}), 400
            if status and status not in valid_statuses:
                return jsonify({"error": "Invalid status"}), 400

            if severity:
                rows = _run_async(db.get_articles_by_severity(severity, limit))
            elif category:
                rows = _run_async(db.get_articles_by_category(category, limit))
            elif status:
                rows = _run_async(db.get_articles_by_status(status, limit))
            else:
                rows = _run_async(
                    db.fetch_all(
                        "SELECT * FROM articles ORDER BY fetched_date DESC LIMIT ?",
                        (limit,),
                    )
                )

            return jsonify([_serialize_row(r) for r in rows])
        except Exception as exc:
            logger.error(f"Error fetching articles: {exc}")
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/articles/<uid>")
    def article_detail(uid: str):
        try:
            article = _run_async(db.get_article_by_uid(uid))
            if not article:
                return jsonify({"error": "Article not found"}), 404

            # Attach IOCs to the response
            iocs = _run_async(db.get_article_iocs(article["id"]))
            result = _serialize_row(article)
            result["iocs"] = [_serialize_row(i) for i in iocs]
            return jsonify(result)
        except Exception as exc:
            logger.error(f"Error fetching article {uid}: {exc}")
            return jsonify({"error": "Internal server error"}), 500

    # ------------------------------------------------------------------
    # IOCs
    # ------------------------------------------------------------------
    @app.route("/api/iocs")
    def iocs_all():
        try:
            iocs = _run_async(db.get_all_iocs())

            # Group by type
            grouped: dict = {}
            for ioc in iocs:
                ioc_type = ioc.get("ioc_type", "unknown")
                grouped.setdefault(ioc_type, []).append(_serialize_row(ioc))

            return jsonify(grouped)
        except Exception as exc:
            logger.error(f"Error fetching IOCs: {exc}")
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/iocs/<ioc_type>")
    def iocs_by_type(ioc_type: str):
        try:
            iocs = _run_async(db.get_iocs_by_type(ioc_type))
            return jsonify([_serialize_row(i) for i in iocs])
        except Exception as exc:
            logger.error(f"Error fetching IOCs by type {ioc_type}: {exc}")
            return jsonify({"error": "Internal server error"}), 500

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------
    @app.route("/api/metadata")
    def metadata():
        try:
            feeds = _run_async(db.get_feed_sources(enabled_only=False))
            return jsonify({
                "app_name": settings.app_name,
                "feed_count": len(feeds),
                "feed_fetch_interval_minutes": settings.feed_fetch_interval,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception as exc:
            logger.error(f"Error fetching metadata: {exc}")
            return jsonify({"error": "Internal server error"}), 500

    return app


# ---------------------------------------------------------------------------
# Standalone entry-point
# ---------------------------------------------------------------------------

def main():
    """Run the API server standalone."""
    settings = get_settings()
    app = create_app()
    logger.info(
        f"Starting Nexo Sentinel API on {settings.api_server_host}:{settings.api_server_port}"
    )
    app.run(
        host=settings.api_server_host,
        port=settings.api_server_port,
        debug=False,  # SECURITY: Never enable debug in production
    )


if __name__ == "__main__":
    main()
