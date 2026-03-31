from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from urllib.parse import quote_plus
import os

# 🔐 Use environment variables (VERY IMPORTANT for Render)
USERNAME = os.getenv("DB_USERNAME", "aruvitest")
PASSWORD = os.getenv("DB_PASSWORD", "Ti*&#V*&urAtEst")
HOST = os.getenv("DB_HOST", "184.168.119.82")
PORT = os.getenv("DB_PORT", "3306")
DATABASE = os.getenv("DB_NAME", "aruvi_test")

# Encode password (handles special characters)
encoded_password = quote_plus(PASSWORD)

# DB URL
SQLALCHEMY_DATABASE_URL = (
    f"mysql+pymysql://{USERNAME}:{encoded_password}@{HOST}:{PORT}/{DATABASE}"
)

# Engine
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    connect_args={
        "connect_timeout": 10  # ⏱ prevents long hanging
    }
)

# Session
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base class
Base = declarative_base()


# Dependency (FastAPI)
def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        print("DB Error:", e)
        db.rollback()
        raise
    finally:
        db.close()
