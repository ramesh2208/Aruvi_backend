import os
from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from urllib.parse import quote_plus

# DB Credentials
USERNAME = os.getenv("DB_USER", "aruvitest")
PASSWORD = os.getenv("DB_PASSWORD", "Ti*&#V*&urAtEst")
HOST = os.getenv("DB_HOST", "184.168.119.82")
PORT = os.getenv("DB_PORT", "3306")
DATABASE = os.getenv("DB_NAME", "aruvi_test")

# Encode password
encoded_password = quote_plus(PASSWORD)

# MySQL URL
SQLALCHEMY_DATABASE_URL = (
    f"mysql+mysqlconnector://{USERNAME}:{encoded_password}@{HOST}:{PORT}/{DATABASE}"
)

# Engine
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300
)

# Session
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

# DB Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Test Connection
def test_db_connection():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))

        print("✅ MySQL Connected Successfully!")
        return True

    except Exception as e:
        print(f"❌ Connection Failed: {e}")
        return False
