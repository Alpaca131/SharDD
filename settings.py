import os

if os.path.isfile('.env'):
    from dotenv import load_dotenv
    load_dotenv()

DATABASE_URL = os.environ['DB_URL']
SESSION_SECRET = os.environ['SESSION_SECRET']
CLIENT_SECRET = os.environ['CLIENT_SECRET']
CLIENT_ID = os.environ['CLIENT_ID']
