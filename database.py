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

encoded_password = quote_plus(PASSWORD)
SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{USERNAME}:{encoded_password}@{HOST}:{PORT}/{DATABASE}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_recycle=300,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
