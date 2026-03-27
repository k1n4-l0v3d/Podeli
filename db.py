import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv

load_dotenv()

def get_conn():
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        # Railway / production
        return psycopg2.connect(
            database_url,
            cursor_factory=psycopg2.extras.RealDictCursor
        )
    else:
        # Local
        return psycopg2.connect(
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT"),
            dbname=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            cursor_factory=psycopg2.extras.RealDictCursor
        )
