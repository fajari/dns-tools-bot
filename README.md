# DNS Tools Bot

DNS Tools Bot is a Telegram bot that allows users to check DNS records, WHOIS information, and SSL certificate expiration dates for given domains. This bot is useful for network administrators, cybersecurity experts, and anyone interested in domain information.

## Features

- **DNS Record Check**: Supports A, CNAME, NS, and TXT records.
- **WHOIS Check**: Retrieves WHOIS information for a given domain.
- **SSL Expiration Check**: Checks the expiration date of the SSL certificate for a given domain.

## Prerequisites

- Python 3.7+
- A Telegram Bot token. You can create a bot and get the token from [BotFather](https://core.telegram.org/bots#botfather) on Telegram.

## Installation

1. **Clone the repository**:

    ```bash
    git clone https://github.com/fajari/dns-tools-bot.git
    cd dns-tools-bot
    ```

2. **Install the dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

3. **Create a `.env` file**:

    Create a file named `.env` in the root directory and add your Telegram Bot token:

    ```plaintext
    TOKEN=YOUR_BOT_TOKEN_HERE
    ```

## Usage

Run the bot using the following command:

```bash
python3 bot.py
