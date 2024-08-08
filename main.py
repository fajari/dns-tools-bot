import logging
import subprocess
import ssl
import socket
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, MessageHandler, ContextTypes, filters
import os
import whois

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)
logger = logging.getLogger(__name__)

TOKEN = '7403357711:AAFlpaRG277rERZYeGdJ1x9Nbl02ImS16qk'
DNS_SERVERS = ['8.8.8.8', '8.8.4.4']
LOG_DIR = 'logs'
LOG_DAYS = 30
MAX_MESSAGE_LENGTH = 4096
NSLOOKUP_PATH = '/usr/bin/nslookup'  # Full path to nslookup

# Function to get the log file for the current day
def get_log_file():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    current_day_index = (datetime.now().timetuple().tm_yday - 1) % LOG_DAYS
    log_file = os.path.join(LOG_DIR, f'usage_log_{current_day_index}.txt')
    return log_file

# Function to log usage
def log_usage(user, query):
    log_file = get_log_file()
    with open(log_file, "a") as f:
        f.write(f"{datetime.now()} - {user} - {query}\n")

# Function to split long messages
def split_message(message, max_length=MAX_MESSAGE_LENGTH):
    return [message[i:i + max_length] for i in range(0, len(message), max_length)]

# Function to start the bot
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = [
        [InlineKeyboardButton("DNS Record Check", callback_data='1')],
        [InlineKeyboardButton("Whois Check", callback_data='2')],
        [InlineKeyboardButton("SSL Expired Check", callback_data='3')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text('Please choose:', reply_markup=reply_markup)

# Function to handle button click
async def button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    if query.data == '1':
        keyboard = [
            [InlineKeyboardButton("A record", callback_data='1.2.1.a')],
            [InlineKeyboardButton("CNAME record", callback_data='1.2.1.b')],
            [InlineKeyboardButton("NS record", callback_data='1.2.1.c')],
            [InlineKeyboardButton("TXT record", callback_data='1.2.1.d')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(text="DNS Record Check:", reply_markup=reply_markup)

    elif query.data in ['1.2.1.a', '1.2.1.b', '1.2.1.c', '1.2.1.d']:
        record_type = {
            '1.2.1.a': 'A',
            '1.2.1.b': 'CNAME',
            '1.2.1.c': 'NS',
            '1.2.1.d': 'TXT'
        }[query.data]
        context.user_data['record_type'] = record_type
        await query.edit_message_text(text=f"Enter the domains separated by commas to check {record_type.upper()} records:")
        context.user_data['next_step'] = f'nslookup_multiple_{record_type.lower()}'

    elif query.data == '2':
        await query.edit_message_text(text="You selected Whois Check. Please enter the domain:")
        context.user_data['next_step'] = 'whois_check'

    elif query.data == '3':
        await query.edit_message_text(text="You selected SSL Expired Check. Please enter the domain:")
        context.user_data['next_step'] = 'ssl_check'

# Function to handle messages
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text
    next_step = context.user_data.get('next_step')
    record_type = context.user_data.get('record_type')

    if next_step:
        log_usage(update.message.from_user.username, f'{next_step} for {text}')
        if next_step.startswith('nslookup_multiple'):
            domains = [domain.strip() for domain in text.split(',')]
            results = [run_nslookup(domain, record_type) for domain in domains]
            result_text = '\n\n'.join(results)
            for msg in split_message(result_text):
                await update.message.reply_text(msg)
        elif next_step == 'whois_check':
            result = run_whois(text)
            for msg in split_message(result):
                await update.message.reply_text(msg)
        elif next_step == 'ssl_check':
            result = check_ssl_expiry(text)
            for msg in split_message(result):
                await update.message.reply_text(msg)
        context.user_data['next_step'] = None

# Function to run nslookup
def run_nslookup(domain, record_type):
    results = []
    for dns_server in DNS_SERVERS:
        try:
            result = subprocess.run([NSLOOKUP_PATH, '-type=' + record_type, domain, dns_server], capture_output=True, text=True)
            if result.returncode == 0:
                results.append(result.stdout)
                break  # If successful, break out of the loop
            else:
                results.append(f"Failed to query {dns_server} for {domain}: {result.stderr}")
        except Exception as e:
            results.append(f"Exception occurred while querying {dns_server} for {domain}: {str(e)}")
    return '\n'.join(results) if results else f"Failed to query DNS servers: {', '.join(DNS_SERVERS)}"

# Function to run whois using python-whois library
def run_whois(domain):
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return str(e)

# Function to check SSL expiry date
def check_ssl_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return f"SSL certificate for {domain} expires on {expiry_date}"
    except Exception as e:
        return str(e)

def main() -> None:
    # Create the Application and pass it your bot's token.
    application = ApplicationBuilder().token(TOKEN).build()

    # Add handlers for different commands
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    # Start the Bot
    application.run_polling()

if __name__ == '__main__':
    main()
