import os

from dotenv import load_dotenv
load_dotenv()

SESSION_SECRET = os.environ['SESSION_SECRET']
CLIENT_SECRET = os.environ['CLIENT_SECRET']
CLIENT_ID = os.environ['CLIENT_ID']
DISCORD_TOKEN = os.environ['DISCORD_TOKEN']
BOT_TOKEN = os.environ["BOT_TOKEN"]
ACCESS_TOKEN = os.environ['ACCESS_TOKEN']
SENTRY_DSN = os.environ["SENTRY_DSN"]
CLOUDFLARE_TOKEN = os.environ["CLOUDFLARE_TOKEN"]
CF_EMAIL = os.environ["CF_EMAIL"]
