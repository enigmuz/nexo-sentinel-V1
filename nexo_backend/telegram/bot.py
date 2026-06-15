"""Telegram bot for Nexo Sentinel CTI System — public read-only, admin-managed."""

import asyncio
import json
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
from telegram.error import TelegramError
from loguru import logger
from nexo_backend.config import get_settings
from nexo_backend.db import Database
from nexo_backend.export import CSVExporter


# Severity emoji mapping
SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
    "Info": "⚪",
}

# IOC type emoji mapping
IOC_EMOJI = {
    "IPv4": "🖥️",
    "IPv6": "🖥️",
    "Domain": "🌐",
    "URL": "🔗",
    "MD5": "#️⃣",
    "SHA1": "#️⃣",
    "SHA256": "#️⃣",
    "Email": "📧",
    "CVE": "🛡️",
}


class TelegramBot:
    """Telegram bot — public read access, admin-only exports.
    
    Access Levels:
    - PUBLIC: /start, /help, /latest, /stats, /search, /threats, /subscribe, /unsubscribe
    - ADMIN ONLY: /export_*, /admin_stats
    """

    def __init__(self, db: Database):
        self.db = db
        self.settings = get_settings()
        self.exporter = CSVExporter(db)
        self.application = None

    async def initialize(self):
        """Initialize bot and register handlers."""
        self.application = Application.builder().token(self.settings.telegram_token).build()
        
        # Public commands — anyone can use
        self.application.add_handler(CommandHandler("start", self._handle_start))
        self.application.add_handler(CommandHandler("help", self._handle_help))
        self.application.add_handler(CommandHandler("latest", self._handle_latest))
        self.application.add_handler(CommandHandler("stats", self._handle_stats))
        self.application.add_handler(CommandHandler("search", self._handle_search))
        self.application.add_handler(CommandHandler("threats", self._handle_threats))
        self.application.add_handler(CommandHandler("subscribe", self._handle_subscribe))
        self.application.add_handler(CommandHandler("unsubscribe", self._handle_unsubscribe))
        
        # Admin-only commands
        self.application.add_handler(CommandHandler("export_all_iocs", self._handle_export_all_iocs))
        self.application.add_handler(CommandHandler("export_new_iocs", self._handle_export_new_iocs))
        self.application.add_handler(CommandHandler("export_article_iocs", self._handle_export_article_iocs))
        self.application.add_handler(CommandHandler("admin", self._handle_admin_stats))
        
        # Inline button callbacks
        self.application.add_handler(CallbackQueryHandler(self._handle_ioc_download, pattern=r"^dl_iocs:"))
        
        # Register owner as admin
        owner_id = self.settings.telegram_user_id
        if owner_id:
            await self.db.add_telegram_user(owner_id, "owner", is_admin=True)
            logger.info(f"Owner {owner_id} registered as admin")
        
        logger.info("Telegram bot initialized (public mode)")

    async def start_polling(self):
        """Start bot polling loop."""
        if not self.application:
            await self.initialize()
        
        logger.info("Starting Telegram bot polling...")
        await self.application.initialize()
        await self.application.start()
        await self.application.updater.start_polling(
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
        )

    async def stop(self):
        """Stop bot gracefully."""
        if self.application:
            await self.application.stop()
            logger.info("Telegram bot stopped")

    # ============== Notification Broadcasting ==============

    async def send_article_notification(self, article_data: dict):
        """Send notification to ALL subscribers with inline buttons."""
        try:
            message = self._format_enriched_notification(article_data)
            uid = article_data.get("uid", "")
            url = article_data.get("url", "")
            
            # Build inline keyboard buttons
            buttons = []
            iocs = article_data.get("iocs", {})
            total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
            if total_iocs > 0:
                buttons.append([InlineKeyboardButton(
                    f"📥 Download IOCs ({total_iocs})",
                    callback_data=f"dl_iocs:{uid}"
                )])
            if url:
                buttons.append([InlineKeyboardButton(
                    "🔗 View Full Article",
                    url=url
                )])
            reply_markup = InlineKeyboardMarkup(buttons) if buttons else None
            
            subscribers = await self.db.get_all_subscribers()
            
            sent_count = 0
            for sub in subscribers:
                try:
                    await self.application.bot.send_message(
                        chat_id=sub["telegram_id"],
                        text=message,
                        parse_mode="HTML",
                        disable_web_page_preview=True,
                        reply_markup=reply_markup,
                    )
                    sent_count += 1
                except TelegramError as e:
                    logger.warning(f"Failed to notify user {sub['telegram_id']}: {e}")
                
                await asyncio.sleep(0.1)
            
            logger.info(f"Notification sent to {sent_count}/{len(subscribers)} subscribers for {uid}")
        except Exception as e:
            logger.error(f"Error broadcasting notification: {str(e)}")

    async def _handle_ioc_download(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle inline button press for IOC CSV download."""
        query = update.callback_query
        await query.answer("Generating IOC report...")

        try:
            uid = query.data.split(":", 1)[1]  # "dl_iocs:NEXO-2026-01137"

            # Find article by UID
            article = await self.db.get_article_by_uid(uid)
            if not article:
                await query.message.reply_text(f"❌ Article {uid} not found.")
                return

            article_id = article["id"]
            title = article["title"]

            # Fetch all IOCs for this article
            iocs = await self.db.get_article_iocs(article_id)

            if not iocs:
                await query.message.reply_text(f"ℹ️ No IOCs stored for {uid}.")
                return

            # Build CSV
            import io
            csv_buffer = io.StringIO()
            csv_buffer.write("Type,Value,Article_UID,Article_Title\n")
            for ioc in iocs:
                ioc_type = ioc.get("ioc_type", "")
                ioc_value = ioc.get("ioc_value", "").replace('"', '""')
                safe_title = title.replace('"', '""')
                csv_buffer.write(f'{ioc_type},"{ioc_value}",{uid},"{safe_title}"\n')

            csv_bytes = csv_buffer.getvalue().encode("utf-8")
            csv_buffer.close()

            # Send as document
            doc = io.BytesIO(csv_bytes)
            doc.name = f"IOCs_{uid}.csv"

            await query.message.reply_document(
                document=doc,
                filename=f"IOCs_{uid}.csv",
                caption=f"📥 <b>{len(iocs)} IOCs</b> from {uid}\n<i>{title[:80]}</i>",
                parse_mode="HTML",
            )
            logger.info(f"IOC CSV sent for {uid}: {len(iocs)} IOCs to user {query.from_user.id}")

        except Exception as e:
            logger.error(f"Error handling IOC download: {e}")
            await query.message.reply_text(f"❌ Error generating IOC report: {str(e)[:100]}")

    async def send_message_to_admin(self, text: str, parse_mode: str = "HTML"):
        """Send message to admin only."""
        try:
            if len(text) > 4000:
                text = text[:3997] + "..."
            await self.application.bot.send_message(
                chat_id=self.settings.telegram_user_id,
                text=text,
                parse_mode=parse_mode,
                disable_web_page_preview=True,
            )
        except TelegramError as e:
            logger.error(f"Telegram error: {str(e)}")

    async def send_document(self, chat_id: int, file_bytes: bytes, filename: str):
        """Send document to a specific user."""
        try:
            await self.application.bot.send_document(
                chat_id=chat_id,
                document=file_bytes,
                filename=filename
            )
        except TelegramError as e:
            logger.error(f"Telegram error sending document: {str(e)}")

    # ============== Auth Helpers ==============

    async def _is_admin(self, user_id: int) -> bool:
        """Check if user is admin (owner)."""
        return user_id == self.settings.telegram_user_id or await self.db.is_admin(user_id)

    # ============== Public Command Handlers ==============

    async def _handle_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start — register user and show welcome."""
        user = update.effective_user
        is_admin = await self._is_admin(user.id)
        
        # Auto-subscribe on /start
        await self.db.add_telegram_user(
            user.id, 
            user.username or user.first_name or "",
            is_admin=is_admin
        )
        
        sub_count = await self.db.get_subscriber_count()
        
        message = (
            "🔐 <b>Nexo Sentinel CTI System v2</b>\n\n"
            "AI-powered Cyber Threat Intelligence bot.\n"
            f"👥 <b>{sub_count}</b> subscribers\n\n"
            "<b>📡 Public Commands:</b>\n"
            "📰 /latest [N] - Last N CTI alerts\n"
            "🔍 /search &lt;query&gt; - Search articles\n"
            "📊 /stats - System statistics\n"
            "🎯 /threats - Active threats\n"
            "🔔 /subscribe - Get notifications\n"
            "🔕 /unsubscribe - Stop notifications\n"
            "ℹ️ /help - Show this help\n"
        )
        
        if is_admin:
            message += (
                "\n<b>🔧 Admin Commands:</b>\n"
                "📥 /export_all_iocs - Export all IOCs\n"
                "📥 /export_new_iocs - Export new IOCs\n"
                "📥 /export_article_iocs &lt;uid&gt; - Export article IOCs\n"
                "👑 /admin - Admin dashboard\n"
            )
        
        message += (
            "\n<b>✅ You are subscribed to CTI alerts!</b>\n"
            "You'll receive notifications for new threats, exploits, and vulnerabilities."
        )
        
        await update.message.reply_text(message, parse_mode="HTML")

    async def _handle_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command."""
        await self._handle_start(update, context)

    async def _handle_subscribe(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /subscribe — enable notifications."""
        user = update.effective_user
        await self.db.add_telegram_user(user.id, user.username or user.first_name or "")
        await self.db.set_notifications(user.id, True)
        await update.message.reply_text("🔔 <b>Subscribed!</b>\nYou'll receive CTI alert notifications.", parse_mode="HTML")

    async def _handle_unsubscribe(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /unsubscribe — disable notifications."""
        user = update.effective_user
        await self.db.set_notifications(user.id, False)
        await update.message.reply_text(
            "🔕 <b>Unsubscribed.</b>\nYou won't receive notifications.\n"
            "Use /subscribe to re-enable.", parse_mode="HTML"
        )

    async def _handle_latest(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /latest command — public."""
        limit = 5
        if context.args and context.args[0].isdigit():
            limit = min(int(context.args[0]), 20)
        
        articles = await self.db.get_latest_articles(limit=limit)
        
        if not articles:
            await update.message.reply_text("No articles found yet. Pipeline is processing...")
            return
        
        message = f"📰 <b>Latest {len(articles)} CTI Articles</b>\n\n"
        
        for article in articles:
            severity = article.get("severity", "Info")
            category = article.get("threat_category", "Info")
            emoji = SEVERITY_EMOJI.get(severity, "⚪")
            ioc_count = article.get("ioc_count", 0)
            summary = article.get("summary", "")
            if summary and len(summary) > 120:
                summary = summary[:117] + "..."
            
            message += f"{emoji} <b>{article['uid']}</b> | {category}\n"
            message += f"   {article['title'][:60]}\n"
            if summary:
                message += f"   📝 {summary}\n"
            message += f"   🔍 IOCs: {ioc_count}\n"
            message += f"   🔗 {article['url']}\n\n"
        
        await update.message.reply_text(message, parse_mode="HTML")

    async def _handle_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /stats command — public."""
        stats = await self.db.get_statistics()
        sub_count = await self.db.get_subscriber_count()
        
        ioc_lines = "\n".join([
            f"  {IOC_EMOJI.get(itype, '•')} {itype}: {count}"
            for itype, count in sorted(stats.get("iocs_by_type", {}).items())
        ]) or "  None yet"
        
        severity_lines = "\n".join([
            f"  {SEVERITY_EMOJI.get(sev, '⚪')} {sev}: {count}"
            for sev, count in sorted(stats.get("articles_by_severity", {}).items())
        ]) or "  None yet"
        
        category_lines = "\n".join([
            f"  • {cat}: {count}"
            for cat, count in sorted(stats.get("articles_by_category", {}).items())
        ]) or "  None yet"
        
        message = (
            f"📊 <b>Nexo Sentinel Statistics</b>\n\n"
            f"<b>Articles:</b> {stats.get('total_articles', 0)}\n"
            f"<b>Total IOCs:</b> {stats.get('total_iocs', 0)}\n"
            f"<b>Subscribers:</b> {sub_count}\n\n"
            f"<b>IOCs by Type:</b>\n{ioc_lines}\n\n"
            f"<b>By Severity:</b>\n{severity_lines}\n\n"
            f"<b>By Category:</b>\n{category_lines}\n"
        )
        
        actors = stats.get("threat_actors", [])
        if actors:
            actor_lines = "\n".join([f"  🎯 {a['name']}: {a['count']} articles" for a in actors[:10]])
            message += f"\n<b>Threat Actors:</b>\n{actor_lines}\n"
        
        await update.message.reply_text(message, parse_mode="HTML")

    async def _handle_threats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /threats command — public."""
        message = "🎯 <b>Active Threats</b>\n\n"
        
        for severity in ["Critical", "High", "Medium"]:
            try:
                articles = await self.db.get_articles_by_severity(severity, limit=5)
                if articles:
                    emoji = SEVERITY_EMOJI.get(severity, "⚪")
                    message += f"{emoji} <b>{severity}</b> ({len(articles)})\n"
                    for a in articles[:3]:
                        message += f"  • {a['uid']}: {a['title'][:50]}\n"
                    message += "\n"
            except Exception:
                continue
        
        if message == "🎯 <b>Active Threats</b>\n\n":
            message += "No critical/high/medium threats detected yet.\n"
        
        await update.message.reply_text(message, parse_mode="HTML")

    async def _handle_search(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /search command — public."""
        if not context.args:
            await update.message.reply_text("Usage: /search &lt;keyword&gt;", parse_mode="HTML")
            return
        
        query = " ".join(context.args)
        articles = await self.db.search_articles(query, limit=5)
        
        if not articles:
            await update.message.reply_text(f"No articles found for '{query}'")
            return
        
        message = f"🔍 <b>Search: '{query}'</b> ({len(articles)} results)\n\n"
        
        for article in articles:
            severity = article.get("severity", "Info")
            emoji = SEVERITY_EMOJI.get(severity, "⚪")
            message += f"{emoji} <b>{article['uid']}</b> - {article['title'][:50]}\n"
            message += f"   🔗 {article['url']}\n\n"
        
        await update.message.reply_text(message, parse_mode="HTML")

    # ============== Admin-Only Command Handlers ==============

    async def _handle_admin_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /admin — admin dashboard."""
        if not await self._is_admin(update.effective_user.id):
            await update.message.reply_text("🔒 Admin access required.")
            return
        
        subscribers = await self.db.get_all_subscribers()
        stats = await self.db.get_statistics()
        
        sub_list = "\n".join([
            f"  {'👑' if s.get('is_admin') else '👤'} {s['telegram_name'] or 'Unknown'} ({s['telegram_id']})"
            for s in subscribers
        ]) or "  No subscribers"
        
        message = (
            f"👑 <b>Admin Dashboard</b>\n\n"
            f"<b>Subscribers ({len(subscribers)}):</b>\n{sub_list}\n\n"
            f"<b>Pipeline:</b>\n"
            f"  📰 Articles: {stats.get('total_articles', 0)}\n"
            f"  🔍 IOCs: {stats.get('total_iocs', 0)}\n"
            f"  ✅ Complete: {stats.get('articles_by_status', {}).get('complete', 0)}\n"
            f"  ⏳ Pending: {stats.get('articles_by_status', {}).get('pending', 0)}\n"
            f"  🚫 Ignored: {stats.get('articles_by_status', {}).get('ignored', 0)}\n"
        )
        
        await update.message.reply_text(message, parse_mode="HTML")

    async def _handle_export_all_iocs(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /export_all_iocs — admin only."""
        if not await self._is_admin(update.effective_user.id):
            await update.message.reply_text("🔒 Admin access required.")
            return
        
        await update.message.reply_text("⏳ Generating CSV export of all IOCs...")
        
        try:
            user_id = update.effective_user.id
            await self.db.add_telegram_user(user_id, update.effective_user.username or "")
            csv_bytes, filename = await self.exporter.export_all_iocs(user_id)
            
            if csv_bytes:
                await self.send_document(user_id, csv_bytes, filename)
                ioc_count = len(csv_bytes.decode().split("\n")) - 2
                message = f"✅ Export complete!\n📄 {filename}\n📊 IOCs: {max(0, ioc_count)}"
            else:
                message = "ℹ️ No new IOCs to export."
            
            await update.message.reply_text(message)
        except Exception as e:
            logger.error(f"Error exporting all IOCs: {str(e)}")
            await update.message.reply_text(f"❌ Export failed: {str(e)}")

    async def _handle_export_new_iocs(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /export_new_iocs — admin only."""
        if not await self._is_admin(update.effective_user.id):
            await update.message.reply_text("🔒 Admin access required.")
            return
        
        await update.message.reply_text("⏳ Generating CSV export of new IOCs...")
        
        try:
            user_id = update.effective_user.id
            await self.db.add_telegram_user(user_id, update.effective_user.username or "")
            csv_bytes, filename = await self.exporter.export_new_iocs(user_id)
            
            if csv_bytes:
                await self.send_document(user_id, csv_bytes, filename)
                ioc_count = len(csv_bytes.decode().split("\n")) - 2
                message = f"✅ Export complete!\n📄 {filename}\n📊 IOCs: {max(0, ioc_count)}"
            else:
                message = "ℹ️ No new IOCs since last export."
            
            await update.message.reply_text(message)
        except Exception as e:
            logger.error(f"Error exporting new IOCs: {str(e)}")
            await update.message.reply_text(f"❌ Export failed: {str(e)}")

    async def _handle_export_article_iocs(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /export_article_iocs — admin only."""
        if not await self._is_admin(update.effective_user.id):
            await update.message.reply_text("🔒 Admin access required.")
            return
        
        if not context.args:
            await update.message.reply_text("Usage: /export_article_iocs &lt;article_uid&gt;", parse_mode="HTML")
            return
        
        article_uid = context.args[0]
        article = await self.db.get_article_by_uid(article_uid)
        if not article:
            await update.message.reply_text(f"Article {article_uid} not found.")
            return
        
        await update.message.reply_text(f"⏳ Exporting IOCs for {article_uid}...")
        
        try:
            user_id = update.effective_user.id
            await self.db.add_telegram_user(user_id, update.effective_user.username or "")
            csv_bytes, filename = await self.exporter.export_article_iocs(article["id"], user_id)
            
            if csv_bytes:
                await self.send_document(user_id, csv_bytes, filename)
                ioc_count = len(csv_bytes.decode().split("\n")) - 2
                message = f"✅ Export complete!\n📄 {filename}\n📊 IOCs: {max(0, ioc_count)}"
            else:
                message = f"ℹ️ No new IOCs for article {article_uid}."
            
            await update.message.reply_text(message)
        except Exception as e:
            logger.error(f"Error exporting article IOCs: {str(e)}")
            await update.message.reply_text(f"❌ Export failed: {str(e)}")

    # ============== Notification Formatting ==============

    @staticmethod
    def _format_enriched_notification(data: dict) -> str:
        """Format a clean CTI alert notification with IOC counts."""
        severity = data.get("severity", "Info")
        category = data.get("threat_category", "Info")
        emoji = SEVERITY_EMOJI.get(severity, "⚪")
        uid = data.get("uid", "")
        iocs = data.get("iocs", {})

        # ── Severity bar ──
        sev_bars = {
            "Critical": "🔴🔴🔴🔴🔴",
            "High": "🟠🟠🟠🟠⚫",
            "Medium": "🟡🟡🟡⚫⚫",
            "Low": "🔵🔵⚫⚫⚫",
            "Info": "⚪⚫⚫⚫⚫",
        }
        sev_bar = sev_bars.get(severity, "⚫⚫⚫⚫⚫")

        msg = f"{emoji} <b>NEXO SENTINEL — CTI ALERT</b>\n"
        msg += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"

        # ── Metadata ──
        msg += f"🆔  <code>{uid}</code>\n"
        msg += f"⚡  <b>{severity.upper()}</b>  {sev_bar}\n"
        msg += f"🏷  <b>{category}</b>\n\n"

        # ── Title ──
        title = data.get("title", "Unknown")
        if len(title) > 120:
            title = title[:117] + "..."
        msg += f"📰 <b>{title}</b>\n\n"

        # ── Summary ──
        summary = data.get("summary", "")
        if summary:
            if len(summary) > 500:
                summary = summary[:497] + "..."
            msg += f"📝 <b>Analysis:</b>\n{summary}\n\n"

        # ── Threat Actors ──
        actors = data.get("threat_actors", [])
        if actors:
            actor_badges = "  ".join(f"🎯 {a}" for a in actors[:5])
            msg += f"<b>Threat Actors:</b>\n{actor_badges}\n\n"

        # ── CVEs ──
        cves = iocs.get("cves", [])
        if cves:
            cve_list = "  ".join(f"<code>{c}</code>" for c in cves[:10])
            msg += f"🛡 <b>CVEs:</b>  {cve_list}\n"

        # ── TTPs (MITRE ATT&CK) ──
        ttps = data.get("ttps", [])
        if ttps:
            ttp_list = " │ ".join(ttps[:6])
            msg += f"⚔️ <b>TTPs:</b>  <i>{ttp_list}</i>\n"

        if cves or ttps:
            msg += "\n"

        # ── IOC Summary (counts only — download button provides details) ──
        total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))

        if total_iocs > 0:
            ioc_parts = []
            ioc_display = [
                ("ipv4", "🖥", "IPs"),
                ("domains", "🌐", "Domains"),
                ("urls", "🔗", "URLs"),
                ("sha256", "🔒", "SHA256"),
                ("sha1", "🔒", "SHA1"),
                ("md5", "🔒", "MD5"),
                ("cves", "🛡", "CVEs"),
                ("emails", "📧", "Emails"),
            ]
            for key, icon, label in ioc_display:
                cnt = len(iocs.get(key, []))
                if cnt > 0:
                    ioc_parts.append(f"{icon} {cnt} {label}")

            msg += f"🔍 <b>Indicators of Compromise ({total_iocs})</b>\n"
            msg += "  ".join(ioc_parts) + "\n"
        else:
            msg += "🔍 <b>IOCs:</b>  No indicators extracted\n"

        # ── Footer ──
        msg += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        msg += "🛡️ <i>Developed by Enigmuz</i>"

        return msg
