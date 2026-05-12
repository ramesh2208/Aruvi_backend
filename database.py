from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from urllib.parse import quote_plus

USERNAME = "aruvitest"
PASSWORD = "Ti*&#V*&urAtEst"
HOST = "82.119.168.184.host.secureserver.net"
PORT = "3306"
DATABASE = "aruvi_test"

encoded_password = quote_plus(PASSWORD)

# Connecting to GoDaddy MySQL with increased timeout
SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{USERNAME}:{encoded_password}@{HOST}:{PORT}/{DATABASE}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_recycle=120,    # Reduced recycle to handle GoDaddy's aggressive connection closing
    pool_pre_ping=True,   # Heartbeat to check if connection is alive
    connect_args={
        "connect_timeout": 60,   # High timeout for cloud latency
        "read_timeout": 60,
        "write_timeout": 60
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
