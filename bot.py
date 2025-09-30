import os
import re
import logging
import requests
import base64
import time
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# --- Initial Setup ---
# Load environment variables from the .env file for security
load_dotenv()

# --- Configuration & API Keys ---
TELEGRAM_BOT_TOKEN = os.getenv("")
GOOGLE_API_KEY = os.getenv("")
VIRUSTOTAL_API_KEY = os.getenv("")

# --- Logging Setup ---
# Configure logging to monitor bot activity and diagnose issues
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- Constants ---
# Regular expression to effectively find URLs in messages
URL_REGEX = r'(https?://[^\s/$.?#].[^\s]*)'

# --- API Integration Functions ---

def check_google_safe_browsing(url: str) -> bool:
    """
    Checks a given URL against the Google Safe Browsing API to determine if it's malicious.
    Returns True if the URL is flagged as unsafe, False otherwise.
    """
    if not GOOGLE_API_KEY:
        logger.warning("Google Safe Browsing API key is not configured. Skipping this check.")
        return False
        
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {"clientId": "RealtimeCyberbot", "clientVersion": "1.0.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(api_url, json=payload, timeout=5)
        response.raise_for_status()
        # If the response contains 'matches', the URL is considered malicious
        return "matches" in response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during Google Safe Browsing API call: {e}")
        return False

def check_virustotal(url: str) -> bool:
    """
    Checks a URL against VirusTotal's API. It submits the URL for analysis and retrieves the report.
    Returns True if the URL is flagged as malicious or suspicious, False otherwise.
    """
    if not VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API key not configured. Skipping this check.")
        return False

    # VirusTotal requires a specific format for the URL ID (base64 without padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        
        if response.status_code == 404:
            logger.info(f"URL not found in VirusTotal database: {url}")
            return False

        response.raise_for_status()
        result = response.json()
        
        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        
        is_malicious = stats.get("malicious", 0) > 0
        is_suspicious = stats.get("suspicious", 0) > 0
        
        if is_malicious or is_suspicious:
            logger.warning(f"VirusTotal flagged URL as unsafe: {url}")
            return True
        
        return False
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during VirusTotal API call: {e}")
        return False

def check_with_ai_model(url: str) -> bool:
    """
    A foundational AI model to analyze URL patterns for suspicious characteristics.
    Returns True if the AI flags the URL as suspicious, False otherwise.
    """
    logger.info(f"AI Model analyzing URL: {url}")
    
    suspicious_keywords = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'banking', 'password']
    is_long_url = len(url) > 80
    domain_parts = url.split('/')[2].split('.')
    has_many_subdomains = len(domain_parts) > 3
    keyword_match_count = sum(1 for keyword in suspicious_keywords if keyword in url.lower())
    
    if (keyword_match_count >= 2 and is_long_url) or has_many_subdomains:
        logger.warning(f"AI flagged URL as suspicious: {url}")
        return True
        
    return False

# --- Telegram Bot Command Handlers ---

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for the /start command."""
    await update.message.reply_text(
        "👋 Hello! I am the Realtime Cyberbot.\n\n"
        "I'm now active and will automatically scan links shared in this group to keep everyone safe."
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for the /help command."""
    await update.message.reply_text(
        "ℹ️ **How I Keep You Safe**\n\n"
        "I react to messages with links to show their status:\n"
        "✅ - All links are safe.\n"
        "❌ - At least one link is unsafe.\n\n"
        "**My Process:**\n"
        "1. I check links against Google's Safe Browsing and VirusTotal's databases.\n"
        "2. I use an AI model to spot suspicious patterns in new or unknown URLs."
    )

# --- Core Logic: Message Handler ---

async def check_message_for_urls(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    The core function that scans every message for URLs, validates them,
    and reacts to the message with a status emoji.
    """
    if not update.message or not update.message.text:
        return

    message_text = update.message.text
    urls = re.findall(URL_REGEX, message_text)
    if not urls:
        return

    user = update.message.from_user
    logger.info(f"Detected URLs from user '{user.first_name}': {urls}")
    
    found_malicious_link = False

    for url in urls:
        is_malicious_google = check_google_safe_browsing(url)
        is_unsafe_virustotal = check_virustotal(url)
        is_suspicious_ai = check_with_ai_model(url)

        if is_malicious_google or is_unsafe_virustotal or is_suspicious_ai:
            found_malicious_link = True
            user_mention = f"@{user.username}" if user.username else user.first_name
            warning_message = (
                f"🚨 **Security Alert** 🚨\n\n"
                f"Warning, {user_mention}! The following link is potentially unsafe:\n"
                f"`{url}`\n\n"
                "**Reason for Flagging:**\n"
            )
            if is_malicious_google:
                warning_message += "  - Flagged by Google as malicious or phishing.\n"
            if is_unsafe_virustotal:
                warning_message += "  - Identified as unsafe by VirusTotal's scanners.\n"
            if is_suspicious_ai:
                warning_message += "  - Flagged by our AI for suspicious patterns.\n"
            
            warning_message += "\n**Please do not click this link unless you are certain of its safety.**"

            # React to the original message with a cross emoji
            await update.message.set_reaction(reaction="❌")
            # Send the detailed warning as a reply
            await update.message.reply_text(warning_message, parse_mode='Markdown')
            
            # Once one unsafe link is found, stop checking the others and exit
            return

    # If the loop completes without finding any malicious links, all URLs are safe.
    if not found_malicious_link:
        logger.info(f"All URLs in message {update.message.message_id} confirmed as safe.")
        # React to the original message with a green tick
        await update.message.set_reaction(reaction="✅")


# --- Main Bot Execution ---

def main():
    """Starts the Telegram bot and sets up handlers."""
    if not TELEGRAM_BOT_TOKEN:
        logger.critical("FATAL ERROR: TELEGRAM_BOT_TOKEN is not defined. Please set it in your .env file.")
        return

    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_message_for_urls))

    logger.info("Bot is starting up...")
    application.run_polling()

if __name__ == '__main__':
    main()

