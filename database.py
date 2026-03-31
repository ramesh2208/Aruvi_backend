from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from urllib.parse import quote_plus
from dotenv import load_dotenv
import os

load_dotenv()

# Database Credentials
USERNAME = os.getenv("DB_USER", "aruvitest")
PASSWORD = os.getenv("DB_PASSWORD", "Ti*&#V*&urAtEst")
HOST = os.getenv("DB_HOST", "184.168.119.82")
PORT = os.getenv("DB_PORT", "3306")
DATABASE = os.getenv("DB_NAME", "aruvi_test")

encoded_password = quote_plus(PASSWORD)
MYSQL_URL = f"mysql+pymysql://{USERNAME}:{encoded_password}@{HOST}:{PORT}/{DATABASE}"
SQLITE_URL = "sqlite:///./aruvi.db"

def get_engine():
    try:
        # Try MySQL connection with a short timeout to check availability
        engine = create_engine(
            MYSQL_URL, 
            pool_recycle=300, 
            pool_pre_ping=True,
            connect_args={"connect_timeout": 5}
        )
        # Attempt a simple connection to verify host is reachable
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print(" SUCCESS: Connected to Remote MySQL Database.")
        return engine
    except Exception as e:
        print(f" INFO: Remote MySQL unreachable ({e}). Falling back to local SQLite.")
        return create_engine(SQLITE_URL, connect_args={"check_same_thread": False})

engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
