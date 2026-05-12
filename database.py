from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from urllib.parse import quote_plus

import os

# Use environment variables from Render, falling back to local defaults
USERNAME = os.getenv("DB_USER", "aruvitest")
PASSWORD = os.getenv("DB_PASSWORD", "Ti*&#V*&urAtEst")
HOST = os.getenv("DB_HOST", "82.119.168.184.host.secureserver.net")
PORT = os.getenv("DB_PORT", "3306")
DATABASE = os.getenv("DB_NAME", "aruvi_test")

encoded_password = quote_plus(PASSWORD)

# Connecting to GoDaddy MySQL with increased timeout
SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{USERNAME}:{encoded_password}@{HOST}:{PORT}/{DATABASE}"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=180,
    pool_size=5,
    max_overflow=10,
    pool_use_lifo=True,  # Useful for remote DB connections
    connect_args={
        "connect_timeout": 60,
        "read_timeout": 60,
        "write_timeout": 60,
        "charset": "utf8mb4"
    }
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Startup test
def test_db_connection():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("✅ DB Connected successfully!")
        return True
    except Exception as e:
        print(f"❌ DB Connection FAILED: {e}")
        return False
