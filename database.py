from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from urllib.parse import quote_plus

# Database Credentials
USERNAME = "aruvitest"
PASSWORD = "Ti*&#V*&urAtEst"
HOST = "184.168.119.82"
PORT = "3306"
DATABASE = "aruvi_test"

import socket
encoded_password = quote_plus(PASSWORD)

# Auto-resolve Host if it's an IP (often helps with GoDaddy firewall)
try:
    if HOST.replace('.', '').isdigit():
        RESOLVED_HOST = socket.gethostbyaddr(HOST)[0]
        print(f"DEBUG: Auto-resolved {HOST} to {RESOLVED_HOST}")
    else:
        RESOLVED_HOST = HOST
except Exception as e:
    print(f"DEBUG: Host resolution failed for {HOST}: {e}")
    RESOLVED_HOST = HOST

SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{USERNAME}:{encoded_password}@{RESOLVED_HOST}:{PORT}/{DATABASE}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_recycle=300,
    pool_pre_ping=True,
    connect_args={
        "connect_timeout": 30,
        "charset": "utf8mb4",
        "ssl": {"disabled": True}
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
