from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, case
from datetime import datetime, timedelta, date
from typing import List, Optional
import shutil
import os
import requests
import random
import re
import string
import hashlib
import base64
import time
from jose import jwt
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel
from typing import Optional
import traceback
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pyotp
from cryptography.fernet import Fernet
from sqlalchemy import extract
import sqlalchemy
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
 
import models, schemas, database
from database import engine, SessionLocal
 
def safe_dt(d):
    if not d: return None
    s = str(d).strip()
    if "0000-00-00" in s: return None
    return d
 
# ═══════════════════════════════════════════════════════════════════════════════
# PRIVILEGE SYSTEM - COMPLETE FIXED
# ═══════════════════════════════════════════════════════════════════════════════
#
# MASTER MOD_ID LIST — positional order mirrors PHP session arrays.
# Backend always returns privileges aligned to this list.
# Frontend finds by mod_id value (not index).
#
# mod_id => module
#  1  = Attendance (own)
#  2  = Leave (own)
#  3  = Timesheet (own)
#  4  = Permission (own)
#  5-10 = reserved
#  11 = Employee list
#  12 = Timesheet (global/HR)
#  13 = HR Leave (global)
#  14 = HR Permission (global)
#  15 = Attendance (global)
#  16 = Client
#  17 = Project (admin + own)
#  18-32 = reserved
#  33 = OT (global/HR)
#  34-53 = reserved
#  54 = WFH (global)
#  55-56 = reserved
#  57 = WFH (own)
#
# PRIVILEGE VALUE MEANINGS:
#   create_prv = 1  → can create
#   read_prv   = 2  → can read/access page
#   update_prv = 3  → can update
#   delete_prv = 4  → can delete
#   view_prv= 5  → global/HR view (see all employees)
#   0 = no privilege
# ═══════════════════════════════════════════════════════════════════════════════
 
MASTER_MOD_IDS = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39,
    44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
    54, 55, 56, 57
]

MODULE_NAMES = {
    1: "Attendance",
    2: "Leave",
    3: "Timesheet",
    4: "Permission",
    11: "Employee List",
    12: "Timesheet (Global)",
    13: "HR Leave",
    14: "HR Permission",
    15: "Attendance (Global)",
    16: "Client",
    17: "Project",
    33: "OT (Global)",
    54: "WFH (Global)",
    57: "WFH"
}
 
 
def _build_empty_priv(mod_id_val: int = 0) -> dict:
    """Return a zero-filled privilege dict for a given mod_id."""
    return {
        "mod_id":      mod_id_val,
        "module_name": MODULE_NAMES.get(mod_id_val, f"Module {mod_id_val}"),
        "create_prv":  0,
        "read_prv":    0,
        "view_prv":    0,
        "update_prv":  0,
        "delete_prv":  0,
        "admin_prv":   0,
        "hr_prv":      0,
        "permissions": None,
    }
 
 
def parse_privilege_array(s):
    """Split a comma-separated privilege string into list of stripped strings."""
    if not s or not isinstance(s, str):
        return []
    s = s.strip()
    if s.startswith('[') and s.endswith(']'):
        s = s[1:-1]
    return [x.strip() for x in s.split(',')]
 
 
def _safe_int(arr, idx):
    """Return arr[idx] as int, or 0 on any failure."""
    try:
        if idx < len(arr) and arr[idx].strip().lstrip('-').isdigit():
            return int(arr[idx].strip())
    except Exception:
        pass
    return 0
 
 
def _build_privileges_from_arrays(source_obj) -> list:
    """
    Unified logic to build privileges from any object (EmpDet or RolePrivilege)
    that stores module access as parallel comma-separated strings (arrays).
    """
    # 1. Parse all arrays from the source object
    mid_raw = getattr(source_obj, 'mod_array', None) or getattr(source_obj, 'mod_id', None)
    
    mod_ids_raw = parse_privilege_array(mid_raw)
    create_prvs = parse_privilege_array(getattr(source_obj, 'create_prv', None))
    read_prvs   = parse_privilege_array(getattr(source_obj, 'read_prv',   None))
    view_prvs   = parse_privilege_array(getattr(source_obj, 'view_prv',   None))
    update_prvs = parse_privilege_array(getattr(source_obj, 'update_prv', None))
    delete_prvs = parse_privilege_array(getattr(source_obj, 'delete_prv', None))
    admin_prvs  = parse_privilege_array(getattr(source_obj, 'admin_prv',  None))
    hr_prvs     = parse_privilege_array(getattr(source_obj, 'hr_prv',     None))

    # 2. Build lookup: mod_id_value → position index in the source arrays
    user_mod_index: dict[int, int] = {}
    for i, m in enumerate(mod_ids_raw):
        m = m.strip()
        if m and m.isdigit():
            user_mod_index[int(m)] = i

    # 3. Align results to MASTER_MOD_IDS for consistent response order
    privileges = []
    for master_mod in MASTER_MOD_IDS:
        if master_mod in user_mod_index:
            i = user_mod_index[master_mod]
            # view_prv is treated as view_prv in this system (value 5)
            vg = _safe_int(view_prvs, i)
            privileges.append({
                "mod_id":      master_mod,
                "module_name": MODULE_NAMES.get(master_mod, f"Module {master_mod}"),
                "create_prv":  _safe_int(create_prvs, i), # 1 = Enabled
                "read_prv":    _safe_int(read_prvs,   i), # 2 = Enabled
                "view_prv":    vg,                        # 5 = Global View
                "update_prv":  _safe_int(update_prvs, i), # 3 = Enabled
                "delete_prv":  _safe_int(delete_prvs, i), # 4 = Enabled
                "admin_prv":   _safe_int(admin_prvs,  i),
                "hr_prv":      _safe_int(hr_prvs,     i),
                "permissions": getattr(source_obj, 'permissions', None),
            })
        else:
            # Module not assigned to user/role
            privileges.append(_build_empty_priv(master_mod))

    return privileges


def _build_module_based_privileges(user) -> list:
    """Helper for module-based users (arrays stored in EmpDet)."""
    return _build_privileges_from_arrays(user)


def _build_role_based_privileges(priv_rows) -> list:
    """Helper for role-based users (arrays stored in RolePrivilege)."""
    if not priv_rows:
        return [_build_empty_priv(m) for m in MASTER_MOD_IDS]
    
    # In 'array type' logic, the first matching row contains the full arrays
    return _build_privileges_from_arrays(priv_rows[0])
 
 
def get_user_privileges(user, db) -> list:
    """
    Single entry-point: return privilege list for any EmpDet user.
    Always returns list aligned to MASTER_MOD_IDS (same length, same order).
    """
    emp_role_type = (getattr(user, 'role_type', '') or '').strip().lower()
 
    if emp_role_type in ('module based', 'module_based'):
        print(f"[PRIV] module-based → {user.emp_id}")
        privs = _build_module_based_privileges(user)
        print(f"[PRIV] → {len(privs)} entries returned")
        return privs
 
    if getattr(user, 'rpd_id', None):
        try:
            print(f"[PRIV] role-based → {user.emp_id} (rpd_id={user.rpd_id})")
            # Convert rpd_id to int as it's the primary key in RolePrivilege
            r_id = int(str(user.rpd_id).strip())
            priv_rows = (
                db.query(models.RolePrivilege)
                .filter(models.RolePrivilege.rpd_id == r_id)
                .all()
            )
            privs = _build_role_based_privileges(priv_rows)
            print(f"[PRIV] → {len(privs)} entries, {len(priv_rows)} DB rows")
            return privs
        except Exception as e:
            print(f"[PRIV] Error fetching role privileges: {e}")
 
    print(f"[PRIV] No privileges found for {user.emp_id}, returning zeros")
    return [_build_empty_priv(m) for m in MASTER_MOD_IDS]
 
# ═══════════════════════════════════════════════════════════════════════════════
 
SECRET_KEY = "your-secret-key-here-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440
 
def create_access_token(data: dict):
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        print(f"JWT Token creation error: {e}")
        return f"fallback_token_{datetime.utcnow().timestamp()}"
 
def handle_db_error(e: Exception):
    err_msg = str(e)
    print(f"❌ DATABASE ERROR: {err_msg}")
    if "is not allowed to connect" in err_msg or "1130" in err_msg:
        import re
        ip_match = re.search(r"Host '([\d\.]+)' is not allowed", err_msg)
        server_ip = ip_match.group(1) if ip_match else "Unknown"
        try:
            real_ip = requests.get("https://api.ipify.org?format=json", timeout=1).json().get("ip")
            if real_ip: server_ip = real_ip
        except: pass
        raise HTTPException(
            status_code=503,
            detail=f"IP RESTRICTED: Please whitelist our server IP '{server_ip}' in your GoDaddy Remote MySQL settings. (Error: 1130)"
        )
    if "Connection refused" in err_msg or "Timed out" in err_msg or "timeout" in err_msg.lower():
        raise HTTPException(
            status_code=503,
            detail="Database connection timeout. The server/database is taking too long to respond. Please try again in 30 seconds."
        )
    raise HTTPException(
        status_code=503,
        detail="Database unavailable. The server may be waking up - please wait 30 seconds and try again."
    )
 
 
app = FastAPI()
 
def run_migrations_with_retry(max_retries: int = 3, delay: int = 5):
    for attempt in range(1, max_retries + 1):
        try:
            print(f"[DB] Migration check (attempt {attempt}/{max_retries})...")
            with engine.begin() as conn:
                try:
                    conn.execute(sqlalchemy.text("ALTER TABLE xxits_aruvi_wfh_det_t ADD COLUMN to_date VARCHAR(20)"))
                    print(" ✅ Migration: Added to_date to xxits_aruvi_wfh_det_t")
                except: pass
                try:
                    conn.execute(sqlalchemy.text("ALTER TABLE xxits_aruvi_emp_leave_t ADD COLUMN revision VARCHAR(10)"))
                    print(" ✅ Migration: Added revision to xxits_aruvi_emp_leave_t")
                except: pass
                try:
                    conn.execute(sqlalchemy.text("ALTER TABLE xxits_emp_det_t ADD COLUMN attribute7 VARCHAR(255)"))
                    print(" ✅ Migration: Added attribute7 to xxits_emp_det_t")
                except: pass
            return True
        except Exception as e:
            print(f"❌ Migration failed: {e}")
            time.sleep(delay)
    return False
 
def create_tables_with_retry(max_retries: int = 5, delay: int = 5):
    for attempt in range(1, max_retries + 1):
        try:
            print(f"[DB] Connecting to database (attempt {attempt}/{max_retries})...")
            models.Base.metadata.create_all(bind=engine)
            print("✅ Database tables created/verified.")
            return True
        except Exception as e:
            err_msg = str(e)
            print(f"❌ DB connection failed (attempt {attempt}): {err_msg}")
            if "is not allowed to connect" in err_msg or "1130" in err_msg:
                try:
                    current_ip = requests.get("https://api.ipify.org?format=json", timeout=2).json().get("ip")
                    print(f"⚠️  IP RESTRICTION DETECTED: Please add '{current_ip}' to GoDaddy Remote MySQL whitelists.")
                except: pass
            if attempt < max_retries:
                print(f"   Retrying in {delay}s...")
                time.sleep(delay)
            else:
                print("❌ CRITICAL: Could not connect to database after all retries. App will start anyway.")
                return False
 
@app.on_event("startup")
def startup_event():
    import threading
    def init_db():
        if create_tables_with_retry():
            run_migrations_with_retry()
    thread = threading.Thread(target=init_db)
    thread.setDaemon(True)
    thread.start()
 
otp_store = {}
 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
 
 
@app.get("/")
def read_root():
    return {"status": "online", "message": "Aruvi Backend is active"}
 
 
@app.get("/health")
def health_check():
    try:
        db = SessionLocal()
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db.close()
        return {"status": "healthy", "db": "connected"}
    except Exception as e:
        return {"status": "degraded", "db": "disconnected", "error": str(e)}
 
 
@app.get("/diag/ip")
def get_diag_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        return {"ip": response.json().get("ip"), "note": "Add this IP to GoDaddy Remote MySQL host list."}
    except Exception as e:
        return {"error": str(e)}
 
 
def get_db():
    db = database.SessionLocal()
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        yield db
    except Exception:
        db.rollback()
        db.close()
        db = database.SessionLocal()
        try:
            yield db
        finally:
            db.close()
    else:
        db.close()
 
 
def parse_date(d):
    if not d:
        return None
    if isinstance(d, datetime):
        return d
    if isinstance(d, date):
        return datetime.combine(d, datetime.min.time())
    d_str = str(d).strip()
    months_map = {
        'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
        'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
    }
    parts = d_str.split('-')
    if len(parts) == 3:
        try:
            day = int(parts[0])
            month_str = parts[1].lower()[:3]
            year = int(parts[2])
            if month_str in months_map:
                return datetime(year, months_map[month_str], day)
        except:
            pass
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(d_str, fmt)
        except:
            continue
    return None
 
 
def parse_time_str(t_str: str):
    if not t_str:
        return None
    t_str = t_str.strip().upper()
    formats = (
        "%I:%M:%S %p", "%I:%M %p", "%I:%M:%S%p", "%I:%M%p", "%H:%M:%S", "%H:%M",
    )
    for fmt in formats:
        try:
            return datetime.strptime(t_str, fmt).replace(year=1900, month=1, day=1)
        except ValueError:
            continue
    match = re.search(r"(\d{1,2})[:.](\d{2})(?::(\d{2}))?\s*([AP]M)?", t_str)
    if match:
        h_str, m_str, s_str, period = match.groups()
        h, m = int(h_str), int(m_str)
        s = int(s_str) if s_str else 0
        if period == "PM" and h < 12: h += 12
        if period == "AM" and h == 12: h = 0
        try:
            return datetime(1900, 1, 1, h, m, s)
        except ValueError:
            return None
    return None
 
 
def format_time_safe(t):
    if not t:
        return ""
    if isinstance(t, str):
        parsed = parse_time_str(t)
        if parsed:
            return parsed.strftime("%I:%M %p").lstrip('0') or "12:00 AM"
        return t
    if hasattr(t, "strftime"):
        return t.strftime("%I:%M %p").lstrip('0') or "12:00 AM"
    try:
        from datetime import timedelta
        if isinstance(t, timedelta):
            dummy = datetime(1900, 1, 1) + t
            return dummy.strftime("%I:%M %p").lstrip('0') or "12:00 AM"
    except:
        pass
    return str(t)
 
 
def auto_calculate_total_hours(emp_id: str, db: Session):
    try:
        today = datetime.now().date()
        checkin_record = db.query(models.CheckIn).filter(
            models.CheckIn.emp_id == emp_id,
            models.CheckIn.t_date == today
        ).first()
        if checkin_record and checkin_record.in_time and checkin_record.out_time:
            in_time = datetime.strptime(checkin_record.in_time, "%I:%M:%S")
            out_time = datetime.strptime(checkin_record.out_time, "%I:%M:%S")
            delta = out_time - in_time
            total_seconds = int(delta.total_seconds())
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            total_hours_str = f"{hours}h {minutes}m"
            checkin_record.Total_hours = total_hours_str
            checkin_record.last_update_date = datetime.now()
            db.commit()
            print(f"✅ Auto-calculated Total_hours: {total_hours_str} for {emp_id}")
            return {"message": f"Total_hours auto-calculated: {total_hours_str}"}
        else:
            return {"message": "No complete check-in record found for auto-calculation"}
    except Exception as e:
        print(f"❌ Auto-calculation error: {str(e)}")
        return {"error": str(e)}
 
@app.post("/auto-calculate-hours")
def auto_calculate_hours_endpoint(request: schemas.AutoCalculateHoursRequest, db: Session = Depends(get_db)):
    emp_id = request.emp_id.strip()
    result = auto_calculate_total_hours(emp_id, db)
    return result
 
 
# ─── LOGIN ────────────────────────────────────────────────────────────────────
 
@app.post("/login", response_model=schemas.Token)
def login(request: schemas.LoginRequest, db: Session = Depends(get_db)):
    try:
        print("\n" + "=" * 60)
        print(" LOGIN ATTEMPT")
        print("=" * 60)
        username_input = request.username.strip().lower()
        input_pwd = request.password.strip()
        print(f" Username input: {username_input}")

        if not db:
            raise HTTPException(status_code=500, detail="Database connection failed")

        try:
            user = db.query(models.EmpDet).filter(
                or_(
                    func.lower(func.trim(models.EmpDet.p_mail)) == username_input,
                    func.lower(func.trim(models.EmpDet.emp_id)) == username_input,
                    func.lower(func.replace(func.trim(models.EmpDet.emp_id), " ", "")) == username_input.replace(" ", "")
                )
            ).first()
        except Exception as db_err:
            print(f" Database query error: {db_err}")
            handle_db_error(db_err)

        if not user:
            raise HTTPException(status_code=404, detail="Invalid Username")

        print(f" User FOUND: {user.emp_id} ({user.p_mail})")

        input_md5 = hashlib.md5(input_pwd.encode()).hexdigest()
        password_valid = False

        if user.attribute15 and user.attribute15.strip():
            if user.attribute15.lower() == input_md5.lower():
                password_valid = True
                print(" Password matched via attribute15 (MD5)")

        if not password_valid and user.password and user.password.strip():
            if user.password.lower() == input_md5.lower():
                password_valid = True
                print(" Password matched via password field (MD5)")

        if not password_valid and user.password == input_pwd:
            password_valid = True
            print(" Password matched via direct comparison")

        if not password_valid and user.password and user.attribute15:
            try:
                AES_KEY = b"1234567890abcdef"
                encrypted_bytes = base64.b64decode(user.password)
                iv_bytes = base64.b64decode(user.attribute15)
                if len(iv_bytes) == 16:
                    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv_bytes)
                    decrypted = unpad(cipher.decrypt(encrypted_bytes), 16).decode()
                    if decrypted == input_pwd:
                        password_valid = True
                        print(" Password matched via AES decryption")
            except Exception as e:
                print(f" AES decrypt failed: {str(e)}")

        if not password_valid:
            raise HTTPException(status_code=401, detail="Invalid Password")

        print(" PASSWORD VERIFIED")

        try:
            access_token = create_access_token(data={"sub": user.emp_id})
        except Exception as token_err:
            raise HTTPException(status_code=500, detail="Token generation failed")

        # ── Role & Domain Logic ──────────────────────────────────────────
        top_roles = ["Admin", "Management", "Executive", "Project Management"]
        top_domains = [1, 2, 3, 9]
        
        role_name = ""
        if user.rpd_id:
            try:
                # rpd_id is stored as string in EmpDet but int in RolePrivilege primary key
                r_id = int(str(user.rpd_id).strip())
                role_priv = db.query(models.RolePrivilege).filter(models.RolePrivilege.rpd_id == r_id).first()
                if role_priv:
                    role_name = role_priv.role_prv_name or ""
            except:
                pass

        is_domain_top = False
        if user.dom_id:
            try:
                if int(str(user.dom_id).strip()) in top_domains:
                    is_domain_top = True
            except:
                pass

        is_super_global = any(tr.lower() in role_name.lower() for tr in top_roles) or is_domain_top

        is_manager = db.query(models.EmpDet).filter(
            or_(
                func.lower(func.trim(models.EmpDet.assign_manager)) == user.emp_id.lower().strip(),
                func.lower(func.trim(models.EmpDet.project_manager)) == user.emp_id.lower().strip()
            )
        ).first() is not None

        role_type = "Admin" if (is_manager or is_super_global) else "Employee"
        
        # As per requirement: "show everything" is STRICTLY limited to domain IDs 1, 2, 3, 9
        is_global_admin = is_domain_top

        has_2fa = bool(user.auth_key and user.auth_key.strip())
        print(f" 2FA: {has_2fa}, Role: {role_type}, Global Admin: {is_global_admin}, Role Name: {role_name}")

        privileges = get_user_privileges(user, db)
        print(f" Privileges: {len(privileges)} modules loaded")
        print("=" * 60)

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "username": user.p_mail or "",
            "role_type": role_type,
            "is_global_admin": is_global_admin,
            "role_name": role_name,
            "user_id": user.emp_id or "",
            "name": user.name or "User",
            "requires_2fa": has_2fa,
            "privileges": privileges
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f" LOGIN ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during login")
 
 
@app.post("/forgot-password")
def forgot_password(request: schemas.ForgotPasswordRequest, background_tasks: BackgroundTasks,
                    db: Session = Depends(get_db)):
    email = request.email.strip().lower()
    print(f"\n--- FORGOT PASSWORD ATTEMPT: {email} ---")
    try:
        user = db.query(models.EmpDet).filter(func.lower(models.EmpDet.p_mail) == email).first()
    except Exception as e:
        handle_db_error(e)
    if not user:
        raise HTTPException(status_code=404, detail="Email_id not found in our records")
    otp = ''.join(random.choices(string.digits, k=6))
    otp_store[email] = {"otp": otp, "expires_at": datetime.now() + timedelta(minutes=5)}
    print(f" Generated OTP: {otp}")
    content = f"""
    <p>We received a request to change the password for your account.</p>
    <p>To complete this process, please use the One-Time Password (OTP) provided below:</p>
    <div style="font-size: 24px; font-weight: 700; color: #4f46e5; margin: 20px 0; letter-spacing: 4px;">{otp}</div>
    <p>This OTP is valid for <strong>3 minutes</strong> and can only be used once.</p>
    <p style="margin-top: 25px; font-size: 13px; color: #64748b;">If you did not request a password change, please contact our support team immediately at <a href="mailto:info@ilantechsolutions.com" style="color: #4f46e5;">info@ilantechsolutions.com</a>.</p>
    """
    body = get_email_template(user.name or 'User', "Password Reset OTP", content, "Security Team")
    background_tasks.add_task(send_email_notification, email, "ITS - Password Reset Mail", body)
    return {"message": "OTP sent successfully"}
 
 
@app.post("/verify-otp")
def verify_otp(request: schemas.VerifyOtpRequest):
    email = request.email.strip().lower()
    otp = request.otp.strip()
    if email in otp_store:
        item = otp_store[email]
        if item["otp"] == otp:
            if datetime.now() < item["expires_at"]:
                return {"message": "OTP verified"}
            else:
                raise HTTPException(status_code=400, detail="OTP expired")
    raise HTTPException(status_code=400, detail="Invalid OTP")
 
 
FERNET_KEY = "8wXVu4azfUZx6g0yJOC4FFXG7O5WzFn1WyVTxmEtHQ0="
 
 
def decrypt_auth_key_fernet(encrypted_auth_key: str) -> str:
    try:
        fernet = Fernet(FERNET_KEY.encode())
        decrypted_secret = fernet.decrypt(encrypted_auth_key.encode()).decode()
        return decrypted_secret
    except Exception as e:
        print(f" Fernet decryption error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to decrypt 2FA secret")
 
 
class GetAuthKeyRequest(BaseModel):
    p_mail: str
 
 
class GetAuthKeyResponse(BaseModel):
    auth_key: str
    auth_timer: int
    p_mail: str
 
 
@app.post("/get-user-auth-key", response_model=GetAuthKeyResponse)
def get_user_auth_key(request: GetAuthKeyRequest, db: Session = Depends(get_db)):
    p_mail = request.p_mail.strip().lower()
    if not p_mail:
        raise HTTPException(status_code=400, detail="Email_id is required")
    try:
        user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.p_mail)) == p_mail).first()
    except Exception as e:
        handle_db_error(e)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.auth_key:
        raise HTTPException(status_code=400, detail="2FA not configured for this user")
    return GetAuthKeyResponse(auth_key=user.auth_key, auth_timer=user.auth_timer or 30, p_mail=user.p_mail)
 
 
def verify_authenticator_otp_for_user(user, otp_input: str) -> bool:
    try:
        encrypted_key = user.auth_key
        auth_timer = user.auth_timer or 30
        if not encrypted_key:
            return False
        fernet = Fernet(FERNET_KEY.encode())
        secret = fernet.decrypt(encrypted_key.encode()).decode()
        totp = pyotp.TOTP(secret, digits=6, interval=auth_timer)
        now = int(time.time())
        otp_clean = otp_input.strip()
        if not otp_clean.isdigit() or len(otp_clean) != 6:
            return False
        print(f" 2FA | Prev: {totp.at(now - auth_timer)} | Curr: {totp.now()} | Next: {totp.at(now + auth_timer)} | Got: {otp_clean}")
        return totp.verify(otp_clean, valid_window=1)
    except Exception as e:
        print(f" OTP verify error: {str(e)}")
        return False
 
 
@app.post("/verify-2fa")
def verify_2fa(request: schemas.Verify2FARequest, db: Session = Depends(get_db)):
    print("\n" + "=" * 60)
    print(" 2FA VERIFY")
    print("=" * 60)
    emp_id = request.user_id.strip().upper()
    otp_input = request.totp_code.strip()
    try:
        user = db.query(models.EmpDet).filter(func.trim(models.EmpDet.emp_id) == emp_id).first()
    except Exception as e:
        handle_db_error(e)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.auth_key:
        raise HTTPException(status_code=400, detail="2FA not configured")
    ok = verify_authenticator_otp_for_user(user, otp_input)
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid Authenticator code")
    print(" 2FA SUCCESS")
 
    is_global_admin = False
    role_type = "Employee"
    if user.dom_id:
        try:
            d_id = int(str(user.dom_id).strip())
            domain_obj = db.query(models.Domain).filter(models.Domain.dom_id == d_id).first()
            if domain_obj and domain_obj.domain:
                if any(x in domain_obj.domain.lower() for x in ["admin", "executive", "management"]):
                    role_type = "Admin"
                    is_global_admin = True
        except:
            pass
    is_manager = db.query(models.EmpDet).filter(
        or_(
            func.lower(func.trim(models.EmpDet.assign_manager)) == user.emp_id.lower().strip(),
            func.lower(func.trim(models.EmpDet.project_manager)) == user.emp_id.lower().strip()
        )
    ).first() is not None
    if is_manager and role_type != "Admin":
        role_type = "Admin"
 
    # ── Get privileges (works for BOTH module-based AND role-based) ──────────
    privileges = get_user_privileges(user, db)
    print(f" Privileges: {len(privileges)} modules loaded")
    print("=" * 60)
 
    return {
        "access_token": "REAL_TOKEN_HERE",
        "token_type": "bearer",
        "username": user.p_mail or "",
        "role_type": role_type,
        "is_global_admin": is_global_admin,
        "user_id": user.emp_id or "",
        "name": user.name or "User",
        "requires_2fa": False,
        "privileges": privileges
    }
 
 
@app.post("/reset-password")
def reset_password(request: schemas.ResetPasswordRequest, db: Session = Depends(get_db)):
    email = request.email.strip().lower()
    otp = request.otp.strip()
    new_pwd = request.new_password.strip()
    if email not in otp_store:
        raise HTTPException(status_code=400, detail="OTP not requested")
    item = otp_store[email]
    if item["otp"] != otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    if datetime.now() > item["expires_at"]:
        raise HTTPException(status_code=400, detail="OTP expired")
    try:
        user = db.query(models.EmpDet).filter(func.lower(models.EmpDet.p_mail) == email).first()
    except Exception as e:
        handle_db_error(e)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    AES_KEY = b"1234567890abcdef"
    iv = os.urandom(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    padded_data = pad(new_pwd.encode(), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    user.password = base64.b64encode(encrypted_bytes).decode()
    user.attribute15 = base64.b64encode(iv).decode()
    db.commit()
    otp_store.pop(email, None)
    return {"message": "Password reset successfully"}
 
 
# ─── SYNC PRIVILEGES ──────────────────────────────────────────────────────────
@app.get("/sync-privileges/{emp_id}")
def sync_privileges(emp_id: str, db: Session = Depends(get_db)):
    """
    Returns current privileges for an employee.
    Always returns list aligned to MASTER_MOD_IDS.
    Called by the app on pull-to-refresh.
    """
    emp_id = emp_id.strip()
    try:
        user = (
            db.query(models.EmpDet)
            .filter(func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower())
            .first()
        )
        if not user:
            raise HTTPException(status_code=404, detail="Employee not found")
 
        privileges = get_user_privileges(user, db)
        return {"privileges": privileges}
 
    except HTTPException:
        raise
    except Exception as e:
        handle_db_error(e)
 
 
@app.get("/admin/employees")
def get_employees(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        query = db.query(models.EmpDet).filter(
            (models.EmpDet.end_date == None) | (models.EmpDet.end_date == "")
        )
        if manager_id:
            query = query.filter(
                or_(
                    func.lower(func.trim(models.EmpDet.assign_manager)) == manager_id.strip().lower(),
                    func.lower(func.trim(models.EmpDet.project_manager)) == manager_id.strip().lower()
                )
            )
        employees = query.all()
    except Exception as e:
        handle_db_error(e)
    results = []
    for emp in employees:
        domain_name = "Employee"
        if emp.dom_id:
            domain = db.query(models.Domain).filter(models.Domain.dom_id == emp.dom_id).first()
            if domain:
                domain_name = domain.domain
        results.append({
            "id": emp.emp_id,
            "name": emp.name or "Unknown",
            "phone": emp.phone_number or emp.alt_phone_number or "N/A",
            "status": "active" if not emp.end_date else "inactive",
            "email": emp.p_mail or emp.mail_id or "",
            "department": domain_name,
            "designation": emp.role_type or "Employee",
            "doj": emp.date_of_joining or "",
            "manager": emp.assign_manager or "N/A",
            "location": emp.attribute1 or "Chennai",
            "shift": "General (9:30 AM - 6:30 PM)",
            "address": emp.address or ""
        })
    return results
 
 
@app.get("/employee-profile/{emp_id}", response_model=schemas.EmployeeProfileResponse)
def get_employee_profile(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    try:
        user = db.query(models.EmpDet).filter(
            func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
    except Exception as e:
        handle_db_error(e)
    if not user:
        raise HTTPException(status_code=404, detail="Employee not found")
    domain_name = "N/A"
    if user.dom_id:
        domain = db.query(models.Domain).filter(models.Domain.dom_id == user.dom_id).first()
        if domain:
            domain_name = domain.domain
    return {
        "emp_id": user.emp_id,
        "name": user.name or "",
        "dob": user.dob,
        "doj": user.date_of_joining,
        "mobile_number": user.phone_number,
        "alternative_phone_number": user.alt_phone_number,
        "age": user.age,
        "father_name": user.father_name,
        "mother_name": user.mother_name,
        "domain": domain_name,
        "department": user.dpt_id or "N/A",
        "role": user.role_type or "N/A",
        "email": user.mail_id or user.p_mail,
        "p_mail": user.p_mail,
        "mail": user.mail_id,
        "personal_mail": user.mail_id,
        "professional_mail": user.p_mail,
        "permanent_address": user.p_address,
        "password": user.password,
        "aadhaar_no": user.aadhar_no,
        "pan_no": user.pan_no,
        "passport_no": user.passport_no
    }
 
 
@app.get("/admin/attendance-logs")
def get_attendance_logs(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    today = datetime.now().date()
    try:
        query = db.query(models.EmpDet).filter(
            (models.EmpDet.end_date == None) | (models.EmpDet.end_date == "")
        )
        if manager_id:
            query = query.filter(
                or_(
                    func.lower(func.trim(models.EmpDet.assign_manager)) == manager_id.strip().lower(),
                    func.lower(func.trim(models.EmpDet.project_manager)) == manager_id.strip().lower()
                )
            )
        employees = query.all()
        logs = db.query(models.CheckIn).filter(models.CheckIn.t_date == today).all()
    except Exception as e:
        handle_db_error(e)
    logs_map = {log.emp_id.strip(): log for log in logs if log.emp_id}
    results = []
    for emp in employees:
        e_id = emp.emp_id.strip() if emp.emp_id else ""
        log = logs_map.get(e_id)
        results.append({
            "id": e_id,
            "name": emp.name or "Unknown",
            "empId": e_id,
            "inTime": log.in_time if log and log.in_time else "--:--",
            "outTime": log.out_time if log and log.out_time else "--:--",
            "totalHours": log.Total_hours if log and log.Total_hours else "0Hr 0Min",
            "status": log.status if log and log.status else "Absent"
        })
    return results
 
 
@app.post("/check-in")
def check_in(request: schemas.CheckInRequest, db: Session = Depends(get_db)):
    emp_id = request.emp_id.strip()
    now = datetime.now()
    today_date = now.date()
    try:
        existing = db.query(models.CheckIn).filter(
            models.CheckIn.emp_id == emp_id,
            models.CheckIn.t_date == today_date
        ).first()
        if existing:
            return {"message": "Already checked in today", "id": existing.check_in_id}
        new_checkin = models.CheckIn(
            emp_id=emp_id, in_time=request.in_time, t_date=today_date,
            t_day=now.strftime("%A"), month=now.strftime("%B"), status="P",
            Total_hours="0Hr 0Min", created_by=emp_id, creation_date=now,
            last_updated_by=emp_id, last_update_date=now
        )
        db.add(new_checkin)
        db.commit()
        db.refresh(new_checkin)
        return {"message": "Check-in successful", "id": new_checkin.check_in_id}
    except Exception as e:
        db.rollback()
        handle_db_error(e)
 
 
@app.post("/check-out")
def check_out(request: schemas.CheckOutRequest, db: Session = Depends(get_db)):
    emp_id = request.emp_id.strip()
    now = datetime.now()
    today_date = now.date()
 
    try:
        checkin_record = db.query(models.CheckIn).filter(
            models.CheckIn.emp_id == emp_id,
            models.CheckIn.t_date == today_date
        ).order_by(models.CheckIn.check_in_id.desc()).first()
    except Exception as e:
        handle_db_error(e)
 
    if not checkin_record:
        raise HTTPException(status_code=404, detail="No check-in found for today")
 
    try:
        raw_in_time = (checkin_record.in_time or "").strip()
        raw_out_time = (request.out_time or "").strip()
 
        print(f"DEBUG in_time from DB : '{raw_in_time}'")
        print(f"DEBUG out_time from request: '{raw_out_time}'")
 
        if not raw_in_time:
            checkin_record.in_time = raw_out_time
            raw_in_time = raw_out_time
 
        t1 = parse_time_str(raw_in_time)
        t2 = parse_time_str(raw_out_time)
 
        if not t1 or not t2:
            raise ValueError(f"Could not parse times: in={raw_in_time}, out={raw_out_time}")
 
        grace_start_time = parse_time_str("09:30:00")
        grace_end_time   = parse_time_str("10:00:00")
        checkout_grace_start = parse_time_str("18:30:00")
        checkout_grace_end   = parse_time_str("19:00:00")
 
        if grace_start_time and grace_end_time and grace_start_time <= t1 <= grace_end_time:
            t1 = grace_start_time
            checkin_record.in_time = "09:30:00"
 
        if checkout_grace_start and checkout_grace_end and checkout_grace_start <= t2 <= checkout_grace_end:
            t2 = checkout_grace_end
            checkin_record.out_time = "19:00:00"
        else:
            checkin_record.out_time = raw_out_time
 
        delta = t2 - t1
        total_seconds = int(delta.total_seconds())
        if total_seconds < 0: total_seconds += 24 * 3600
        hours   = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
 
        if request.total_hours and request.total_hours not in ["0Hr 0Min", "0Hr 00Min"]:
            calculated_total_hours = request.total_hours
            try:
                h_str = calculated_total_hours.split('Hr')[0].strip()
                m_str = calculated_total_hours.split('Hr')[1].split('Min')[0].strip()
                total_hours_float = int(h_str) + (int(m_str) / 60)
            except:
                total_hours_float = hours + (minutes / 60)
        else:
            calculated_total_hours = f"{hours}Hr {minutes:02d}Min"
            total_hours_float = hours + (minutes / 60)
 
        checkin_record.Total_hours      = calculated_total_hours
        checkin_record.last_update_date = now
        checkin_record.last_updated_by  = emp_id
        db.add(checkin_record)
        print(f"DEBUG: Processing {emp_id} - {calculated_total_hours} (float: {total_hours_float})")
 
        days_to_deduct = 0.0
        new_status = "P"
        leave_reason = ""
 
        if total_hours_float < 4.0:
            days_to_deduct = 1.0
            new_status = "CL"
            leave_reason = "Auto-deducted: Worked less than 4 hours"
        elif 4.0 <= total_hours_float <= 6.0:
            days_to_deduct = 0.5
            new_status = "0.5CL"
            leave_reason = "Auto-deducted: Worked 4-6 hours"
        else:
            new_status = "P"
            days_to_deduct = 0.0
 
        if days_to_deduct > 0:
            cl_balance = db.query(models.LeaveDet).filter(
                models.LeaveDet.emp_id == emp_id,
                or_(
                    func.lower(models.LeaveDet.leave_type).contains("casual"),
                    func.lower(models.LeaveDet.leave_type) == "cl"
                )
            ).first()
 
            actual_leave_type = "Casual Leave"
            l_det_id_val = None
 
            if cl_balance and float(cl_balance.available_leave or 0) >= days_to_deduct:
                cl_balance.available_leave = float(cl_balance.available_leave) - days_to_deduct
                cl_balance.availed_leave   = float(cl_balance.availed_leave or 0) + days_to_deduct
                cl_balance.last_update_date = now
                cl_balance.last_updated_by = emp_id
                db.add(cl_balance)
                actual_leave_type = cl_balance.leave_type or "Casual Leave"
                l_det_id_val = cl_balance.l_det_id
                checkin_record.status = new_status
            else:
                checkin_record.status = "LOP" if days_to_deduct == 1.0 else "0.5LOP"
                actual_leave_type = "Loss of Pay"
                print(f"⚠️ Status updated to {checkin_record.status} (No CL balance) for {emp_id}")
 
            new_leave = models.EmpLeave(
                l_det_id=l_det_id_val, emp_id=emp_id, leave_type=actual_leave_type,
                from_date=today_date.strftime("%d-%b-%Y"), to_date=today_date.strftime("%d-%b-%Y"),
                days=str(days_to_deduct), reason=leave_reason, status="Approved",
                applied_date=now.strftime("%d-%b-%Y"),
                mail_message_id="", hr_action="", hr_approval="", admin_approval="",
                lop_days=str(days_to_deduct) if "LOP" in checkin_record.status else "0",
                remarks="Auto-generated on check-out", approved_by="System",
                reporting_manager="", approver="", revision="0",
                attribute_category="AUTO", attribute1=str(days_to_deduct),
                attribute2="", attribute3="", attribute4="", attribute5="",
                attribute6="", attribute7="", attribute8="", attribute9="",
                attribute10="", attribute11="", attribute12="", attribute13="",
                attribute14="", file="",
                created_by=emp_id, creation_date=now,
                last_updated_by=emp_id, last_update_date=now
            )
            db.add(new_leave)
            print(f"✅ Leave history record ({actual_leave_type} - {days_to_deduct} days) created for {emp_id}")
        else:
            checkin_record.status = "P"
            print(f"ℹ️ Status remained P (Worked {total_hours_float} hrs) for {emp_id}")
 
        db.commit()
        db.refresh(checkin_record)
        print(f"✅ Successfully committed Total_hours: {checkin_record.Total_hours}")
 
    except Exception as e:
        db.rollback()
        print(f"❌ Check-out Error: {str(e)}")
        try:
            checkin_record.out_time = request.out_time
            if request.total_hours:
                checkin_record.Total_hours = request.total_hours
            checkin_record.last_update_date = now
            db.add(checkin_record)
            db.commit()
            print("⚠️ Saved partial check-out data after error.")
        except:
            db.rollback()
 
    return {
        "message"     : "Check-out successful",
        "total_hours" : checkin_record.Total_hours or "0Hr 0Min",
        "status"      : checkin_record.status
    }
 
 
@app.get("/check-status/{emp_id}")
def get_check_status(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    today_date = datetime.now().date()
    try:
        record = db.query(models.CheckIn).filter(
            models.CheckIn.emp_id == emp_id,
            models.CheckIn.t_date == today_date
        ).order_by(models.CheckIn.check_in_id.desc()).first()
    except Exception as e:
        handle_db_error(e)
    if record:
        return {
            "checked_in"  : True,
            "in_time"     : record.in_time,
            "out_time"    : record.out_time,
            "total_hours" : record.Total_hours or "0Hr 0Min"
        }
    return {"checked_in": False}
 
 
@app.get("/attendance-month/{emp_id}")
def get_attendance_month(emp_id: str, month: int, year: int, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    try:
        logs = db.query(models.CheckIn).filter(
            func.lower(func.trim(models.CheckIn.emp_id)) == emp_id.lower(),
            extract('month', models.CheckIn.t_date) == month,
            extract('year', models.CheckIn.t_date) == year
        ).all()
    except Exception as e:
        handle_db_error(e)
    for log in logs:
        if hasattr(log, 't_date') and log.t_date:
            if not isinstance(log.t_date, str):
                log.t_date = log.t_date.strftime("%Y-%m-%d")
    return logs
 
 
@app.get("/leave-stats/{emp_id}")
def get_leave_stats(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    try:
        leave_rows = db.query(models.LeaveDet).filter(
            func.lower(func.trim(models.LeaveDet.emp_id)) == emp_id.lower()).all()
    except Exception as e:
        handle_db_error(e)
    stats: dict = {
        "casualLeave": {"total": 0, "availed": 0},
        "sickLeave": {"total": 0, "availed": 0},
        "maternityPaternity": {"total": 0, "availed": 0},
        "marriageLeave": {"total": 5, "availed": 0},
        "total": 0, "availed": 0
    }
    cl_total = sl_total = mp_total = cl_availed = sl_availed = mp_availed = 0.0
    for row in leave_rows:
        l_type = (row.leave_type or "").lower()
        try:
            t_val = float(row.total_leave or 0)
            a_val = float(row.availed_leave or 0)
        except:
            t_val, a_val = 0.0, 0.0
        if 'casual' in l_type or l_type == 'cl':
            cl_total = t_val; cl_availed = a_val
        elif 'sick' in l_type or l_type == 'sl':
            sl_total = t_val; sl_availed = a_val
        elif 'maternity' in l_type or 'paternity' in l_type or l_type in ['ml', 'pl']:
            mp_total = t_val; mp_availed = a_val
    stats["casualLeave"] = {"total": cl_total, "availed": cl_availed}
    stats["sickLeave"] = {"total": sl_total, "availed": sl_availed}
    stats["maternityPaternity"] = {"total": mp_total, "availed": mp_availed}
    stats["total"] = cl_total + sl_total + mp_total
    stats["availed"] = cl_availed + sl_availed + mp_availed
    return {**stats, "has_record": len(leave_rows) > 0}
 
 
@app.get("/wfh-history/{emp_id}")
def get_wfh_history(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    try:
        history = db.query(models.WFHDet).filter(
            func.lower(func.trim(models.WFHDet.emp_id)) == emp_id.lower()
        ).order_by(models.WFHDet.wfh_id.desc()).all()
    except Exception as e:
        handle_db_error(e)
    return [
        {"wfh_id": row.wfh_id, "from_date": row.from_date, "to_date": row.to_date,
         "days": row.days, "reason": row.reason, "status": row.status}
        for row in history
    ]
 
 
@app.get("/leave-history/{emp_id}")
def get_leave_history(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    try:
        history = db.query(models.EmpLeave).filter(
            func.lower(func.trim(models.EmpLeave.emp_id)) == emp_id.lower()
        ).order_by(models.EmpLeave.l_id.desc()).all()
    except Exception as e:
        handle_db_error(e)
    return [
        {"l_id": row.l_id, "leaveType": row.leave_type, "leave_type": row.leave_type,
         "from_date": row.from_date, "to_date": row.to_date, "days": row.days,
         "reason": row.reason, "status": row.status, "remarks": row.remarks, "revision": row.revision}
        for row in history
    ]
 
 
def send_email_notification(to_email: str, subject: str, body_html: str):
    if not to_email:
        print(" Email_id notification skipped: No recipient email provided")
        return False
    url = "https://devbms.ilantechsolutions.com/attendance/send-mail/"
    api_key = "my_secret_key_123"
    payload = {"to_email": to_email, "subject": subject, "body": body_html, "content_type": "text/html"}
    headers = {"x-api-key": api_key, "Content-Type": "application/json"}
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=15)
        if response.status_code in [200, 201]:
            print(f" EMAIL SENT successfully to {to_email}")
            return True
        else:
            print(f" API FAILED: Status {response.status_code}")
            return False
    except Exception as e:
        print(f" ERROR calling email API for {to_email}: {str(e)}")
        return False
 
 
def send_expo_push_notification(tokens, title, message, data=None):
    url = "https://exp.host/--/api/v2/push/send"
    print(f"\n🔔 [EXPO PUSH] PREPARING TO SEND:")
    print(f"   Tokens: {tokens}")
    print(f"   Title: {title}")
    payloads = []
    for token in tokens:
        if token and str(token).strip().startswith("ExponentPushToken"):
            payloads.append({"to": token.strip(), "title": title, "body": message, "data": data or {}, "sound": "default"})
    if not payloads:
        print("   ⚠️ [EXPO PUSH] ABORTED: No valid ExponentPushTokens found.")
        return
    try:
        response = requests.post(url, json=payloads, headers={"Accept": "application/json"}, timeout=10)
        print(f"   [EXPO PUSH] RESPONSE CODE: {response.status_code}")
        if response.status_code == 200:
            print(f"   ✅ [EXPO PUSH] SENT successfully to {len(payloads)} devices!")
        else:
            print(f"   ❌ [EXPO PUSH] FAILED: {response.text}")
    except Exception as e:
        print(f"   ❌ [EXPO PUSH] ERROR: {str(e)}")
 
 
@app.post("/register-push-token")
def register_push_token(req: schemas.PushTokenRegisterRequest, db: Session = Depends(get_db)):
    emp_id = req.user_id.strip().upper()
    print(f"\n📥 [PUSH] REGISTER TOKEN REQUEST for: {emp_id}")
    print(f"   Token: {req.push_token[:30]}...")
    user = db.query(models.EmpDet).filter(
        func.lower(func.trim(models.EmpDet.emp_id)) == req.user_id.strip().lower()
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User {emp_id} not found")
    print(f"✅ [PUSH] USER FOUND: {user.name}")
    user.attribute7 = req.push_token
    user.last_update_date = datetime.now()
    try:
        db.commit()
        db.refresh(user)
        print(f"🚀 [PUSH] TOKEN SUCCESSFULLY SAVED to attribute7 for {user.emp_id}")
        return {"message": "Push token registered successfully", "user_id": user.emp_id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to save token to database")
 
 
@app.post("/test-push")
def test_push(req: schemas.PushTokenRegisterRequest, db: Session = Depends(get_db)):
    send_expo_push_notification([req.push_token], "Aruvi Test Notification", "If you see this, push notifications are working perfectly!")
    return {"message": "Test push triggered"}
 
 
def get_approvers(db: Session, user: models.EmpDet):
    approvers = []
    approver_ids = set()
    if user.assign_manager:
        m = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == user.assign_manager.strip().lower()).first()
        if m and m.emp_id not in approver_ids:
            approvers.append({"email": m.p_mail, "name": m.name, "token": m.attribute7})
            approver_ids.add(m.emp_id)
    if user.project_manager:
        pm = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == user.project_manager.strip().lower()).first()
        if pm and pm.emp_id not in approver_ids:
            approvers.append({"email": pm.p_mail, "name": pm.name, "token": pm.attribute7})
            approver_ids.add(pm.emp_id)
    try:
        all_doms = db.query(models.Domain).filter(
            or_(
                func.lower(models.Domain.domain).contains("admin"),
                func.lower(models.Domain.domain).contains("executive"),
                func.lower(models.Domain.domain).contains("management")
            )
        ).all()
        dom_ids = [str(d.dom_id) for d in all_doms]
        if dom_ids:
            management_users = db.query(models.EmpDet).filter(models.EmpDet.dom_id.in_(dom_ids)).all()
            for m_user in management_users:
                if m_user.emp_id not in approver_ids:
                    approvers.append({"email": m_user.p_mail, "name": m_user.name, "token": m_user.attribute7})
                    approver_ids.add(m_user.emp_id)
    except Exception as e:
        print(f" Error fetching management users for notification: {e}")
    return approvers
 
 
def fmt_days(d):
    try:
        val = float(d)
        if val.is_integer():
            return str(int(val))
        return f"{val:.2f}".rstrip('0').rstrip('.')
    except (ValueError, TypeError):
        return str(d)
 
 
def get_email_template(receiver_name, title, content_html, sender_name="Aruvi Team"):
    return f"""
    <html>
    <head>
        <style>
            body {{ font-family: 'Times New Roman', Times, serif; line-height: 1.6; color: #00008B; margin: 0; padding: 15px; }}
            a {{ color: #0ea5e9; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body style="font-family: 'Times New Roman', Times, serif; color: #00008B; padding: 15px;">
        <p style="margin-top: 0;"><strong>Dear {receiver_name},</strong></p>
        <div>{content_html}</div>
        <p style="margin-top: 40px; margin-bottom: 5px;">Thanks & Regards,</p>
        <strong style="color: #00008B;">{sender_name}</strong><br>
        Ilan Tech Solutions Pvt. Ltd.,
        <p style="margin-top: 5px; font-size: 14px; color: #00008B;">
            Website: <a href="http://www.ilantechsolutions.com" style="color: #0ea5e9;">www.ilantechsolutions.com</a>
        </p>
    </body>
    </html>
    """


@app.post("/apply-leave")
async def apply_leave(
        background_tasks: BackgroundTasks,
        emp_id: str = Form(...),
        leave_type: str = Form(...),
        from_date: str = Form(...),
        to_date: str = Form(...),
        days: float = Form(...),
        reason: str = Form(...),
        status: str = Form(...),
        is_half_day: Optional[str] = Form(None),
        half_day_date: Optional[str] = Form(None),
        attachments: Optional[List[UploadFile]] = File(None),
        db: Session = Depends(get_db)
):
    emp_id = emp_id.strip()
    print(f"DEBUG: apply_leave for emp_id={emp_id}, type={leave_type}, days={days}")
    try:
        user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
        print(f"DEBUG: user found? {user.name if user else 'No'}")
    except Exception as e:
        print(f"DEBUG: DB error fetching user: {e}")
        handle_db_error(e)

    if not user:
        raise HTTPException(status_code=404, detail=f"Employee with ID {emp_id} not found in the system.")

    if half_day_date and days % 1 != 0:
        reason += f" [Half Day Date: {half_day_date}]"

    emp_name = user.name if user else 'Unknown'
    normalized_leave_type = (leave_type or "").strip().lower()
    requested_days = float(days or 0)

    if normalized_leave_type == "sick leave" and requested_days >= 2:
        if not attachments or len(attachments) == 0:
            raise HTTPException(status_code=400, detail="Attachment is mandatory for Sick Leave requests lasting 2 days or more.")

    attachment_paths = []
    if attachments:
        upload_dir = "uploads/leave_attachments"
        os.makedirs(upload_dir, exist_ok=True)
        for i, file in enumerate(attachments):
            if not file.filename: continue
            file_extension = file.filename.split('.')[-1]
            file_name = f"{emp_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{i}.{file_extension}"
            file_path = os.path.join(upload_dir, file_name)
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            attachment_paths.append(f"uploads/leave_attachments/{file_name}")

    attr14_paths = ",".join(attachment_paths) if attachment_paths else None
    primary_attachment_path = attachment_paths[0] if attachment_paths else None
    lop_days_val = 0.0
    cl_days_to_deduct = requested_days

    try:
        req_from = parse_date(from_date)
        req_to = parse_date(to_date)
        if not req_from or not req_to:
            raise HTTPException(status_code=400, detail="Invalid From/To date format")
        if req_to < req_from:
            raise HTTPException(status_code=400, detail="To date must be on or after from date")
        if requested_days <= 0:
            raise HTTPException(status_code=400, detail="Invalid leave days")

        existing_leaves = db.query(models.EmpLeave).filter(
            func.lower(func.trim(models.EmpLeave.emp_id)) == emp_id.lower(),
            func.lower(func.trim(models.EmpLeave.status)).in_(["pending", "approved"])
        ).all()

        for row in existing_leaves:
            row_from = parse_date(row.from_date)
            row_to = parse_date(row.to_date) if row.to_date else row_from
            if not row_from or not row_to: continue
            if (req_from <= row_to) and (req_to >= row_from):
                existing_type = row.leave_type or "Leave Request"
                raise HTTPException(
                    status_code=400,
                    detail=f"You have already applied for {existing_type} on these dates ({row.from_date} to {row.to_date}). Please check your leave history."
                )

        l_type_lower = leave_type.lower()
        balance_row = None
        if 'casual' in l_type_lower or 'cl' == l_type_lower:
            search_key = 'casual'
        elif 'sick' in l_type_lower or 'sl' == l_type_lower:
            search_key = 'sick'
        elif 'maternity' in l_type_lower or 'paternity' in l_type_lower or l_type_lower in ['ml', 'pl']:
            balance_row = db.query(models.LeaveDet).filter(
                func.lower(func.trim(models.LeaveDet.emp_id)) == emp_id.strip().lower(),
                or_(
                    func.lower(func.trim(models.LeaveDet.leave_type)).contains('maternity'),
                    func.lower(func.trim(models.LeaveDet.leave_type)).contains('paternity'),
                    func.lower(func.trim(models.LeaveDet.leave_type)).in_(['ml', 'pl'])
                )
            ).first()
            search_key = None
        else:
            search_key = l_type_lower.split(' ')[0]

        if search_key and not balance_row:
            balance_row = db.query(models.LeaveDet).filter(
                func.lower(func.trim(models.LeaveDet.emp_id)) == emp_id.strip().lower(),
                func.lower(func.trim(models.LeaveDet.leave_type)).contains(search_key)
            ).first()

        print(f"DEBUG: balance_row found? {'Yes' if balance_row else 'No'} key={search_key}")

        lop_days_val = 0.0
        cl_days_to_deduct = requested_days

        if normalized_leave_type == "casual leave":
            month_usage: dict[str, float] = {}
            for row in existing_leaves:
                if (row.leave_type or "").strip().lower() != "casual leave": continue
                row_from = parse_date(row.from_date)
                row_to = parse_date(row.to_date) if row.to_date else row_from
                if row_from and row_to:
                    if row_to < row_from: row_from, row_to = row_to, row_from
                    delta_days = (row_to - row_from).days + 1
                    daily_share = float(row.days or 0) / (delta_days if delta_days > 0 else 1)
                    cur = row_from
                    while cur <= row_to:
                        key = f"{cur.year}-{cur.month:02d}"
                        month_usage[key] = month_usage.get(key, 0.0) + daily_share
                        cur = cur + timedelta(days=1)

            req_month_usage: dict[str, float] = {}
            req_cur = req_from
            req_daily_share = float(requested_days) / float((req_to - req_from).days + 1 or 1)
            while req_cur <= req_to:
                req_key = f"{req_cur.year}-{req_cur.month:02d}"
                req_month_usage[req_key] = req_month_usage.get(req_key, 0.0) + req_daily_share
                req_cur = req_cur + timedelta(days=1)

            max_excess = 0.0
            for month_key, req_value in req_month_usage.items():
                used_value = month_usage.get(month_key, 0.0)
                if used_value + req_value > 3.0:
                    excess = (used_value + req_value) - 3.0
                    if excess > max_excess: max_excess = excess

            if max_excess > 0:
                policy_lop = min(requested_days, max_excess)
                cl_days_to_deduct = requested_days - policy_lop
                lop_days_val = policy_lop

        if balance_row:
            avail = float(balance_row.available_leave or 0)
            print(f"DEBUG: checking balance: req_deduct={cl_days_to_deduct}, avail={avail}")
            if cl_days_to_deduct > avail:
                extra_lop = cl_days_to_deduct - avail
                lop_days_val += extra_lop
                cl_days_to_deduct = avail
        else:
            print(f"DEBUG: No balance_row for {leave_type}, forcing LOP")
            lop_days_val = requested_days
            cl_days_to_deduct = 0.0

        from decimal import Decimal, ROUND_HALF_UP
        _twodp = Decimal('0.01')
        cl_days_to_deduct = float(Decimal(str(cl_days_to_deduct)).quantize(_twodp, rounding=ROUND_HALF_UP))
        lop_days_val = float(Decimal(str(lop_days_val)).quantize(_twodp, rounding=ROUND_HALF_UP))

        det_id = balance_row.l_det_id if balance_row else None

        new_leave = models.EmpLeave(
            l_det_id=det_id, emp_id=emp_id.strip(), leave_type=leave_type,
            from_date=req_from.strftime('%d-%b-%Y'), to_date=req_to.strftime('%d-%b-%Y'),
            days=fmt_days(cl_days_to_deduct), reason=reason, status=status,
            file=primary_attachment_path, attribute14=attr14_paths,
            applied_date=datetime.now().strftime('%d-%b-%Y'),
            mail_message_id="", hr_action="", hr_approval="", admin_approval="",
            lop_days=fmt_days(lop_days_val), remarks="", approved_by="",
            reporting_manager=(user.assign_manager.strip() if user.assign_manager else "") if user else "",
            approver=(user.project_manager.strip() if user.project_manager else "") if user else "",
            revision="0", attribute_category=None, attribute1=None,
            attribute2="", attribute3="", attribute4="", attribute5="",
            last_update_login="", created_by=emp_id.strip(), creation_date=datetime.now(),
            last_updated_by=emp_id.strip(), last_update_date=datetime.now()
        )
        db.add(new_leave)
        db.flush()

        if balance_row and cl_days_to_deduct > 0:
            try:
                balance_row.availed_leave = float(balance_row.availed_leave or 0) + cl_days_to_deduct
                balance_row.available_leave = float(balance_row.available_leave or 0) - cl_days_to_deduct
                db.commit()
                print(f"✅ Updated balance for {emp_id}: Available={balance_row.available_leave}, Availed={balance_row.availed_leave}")
            except Exception as balance_err:
                print(f"❌ Error updating balance: {balance_err}")
                db.rollback()

        try:
            if user:
                approvers = get_approvers(db, user)
                month_str = req_from.strftime("%b-%y") if req_from else ""
                pure_days = fmt_days(requested_days)
                subject = f"ITS - {emp_name} - {leave_type} Request | {from_date}"

                if approvers:
                    appr = approvers[0] # Only the first approver
                    if appr["email"]:
                        content = f"""
                        <p>Good Day!</p>
                        <p>Please find below the details of my leave.</p>
                        <p>Let me know if you require any additional information.</p>
                        <br>
                        <table style="border-collapse: collapse; width: 100%; max-width: 600px; text-align: center; font-family: 'Times New Roman', Times, serif; border: 1px solid #000;">
                            <thead>
                                <tr style="background-color: darkblue; color: #000; font-weight: bold;">
                                    <th style="padding: 8px; border: 1px solid #000;">S.No</th>
                                    <th style="padding: 8px; border: 1px solid #000;">Month</th>
                                    <th style="padding: 8px; border: 1px solid #000; width: 40%;">Date</th>
                                    <th style="padding: 8px; border: 1px solid #000;">Days</th>
                                    <th style="padding: 8px; border: 1px solid #000;">Reason</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr style="color: darkblue; background-color: transparent;">
                                    <td style="padding: 8px; border: 1px solid #000;">1</td>
                                    <td style="padding: 8px; border: 1px solid #000;">{month_str}</td>
                                    <td style="padding: 8px; border: 1px solid #000;">{from_date} to {to_date}</td>
                                    <td style="padding: 8px; border: 1px solid #000;">{pure_days}</td>
                                    <td style="padding: 8px; border: 1px solid #000;">{reason}</td>
                                </tr>
                            </tbody>
                        </table>
                        <br>
                        """
                        body = get_email_template(appr["name"], "Leave Request", content, emp_name)
                        background_tasks.add_task(send_email_notification, appr["email"], subject, body)
                    
                    if appr["token"]:
                        background_tasks.add_task(send_expo_push_notification, [appr["token"]],
                            "New Leave Request", f"{emp_name} has requested {leave_type} from {from_date} to {to_date}.")
        except Exception as mail_err:
            print(f"❌ Error sending notifications: {mail_err}")

        print(f"✅ Leave request submitted successfully for {emp_id}")
        return {"message": "Leave request submitted successfully", "leave_id": new_leave.l_id}

    except HTTPException as http_err:
        db.rollback()
        raise http_err
    except Exception as e:
        print(f"❌ CRITICAL DATABASE ERROR: {str(e)}")
        traceback.print_exc()
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Leave application failed: {str(e)}")


@app.post("/send-leave-notification")
def send_leave_notification(notification: dict, db: Session = Depends(get_db)):
    try:
        emp_id = notification.get("emp_id", "").strip()
        emp_name = notification.get("emp_name", "Employee")
        leave_type = notification.get("leave_type", "Leave")
        from_date = notification.get("from_date", "")
        to_date = notification.get("to_date", "")
        days = notification.get("days", 0)
        is_half_day = notification.get("is_half_day", False)
        status = notification.get("status", "Pending")
        try:
            user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == emp_id).first()
            if not user:
                return {"message": "Employee not found"}
            approvers = get_approvers(db, user)
            if not approvers:
                return {"message": "No approvers found for this employee"}
            subject = f"Leave Request: {emp_name} - {leave_type} ({from_date} to {to_date})"
            sent_count = 0
            for appr in approvers:
                if appr["email"]:
                    body = get_email_template(appr["name"] or "Manager", subject, f"<p>{emp_name} applied for {leave_type}.</p>", "Aruvi Leave System")
                    if send_email_notification(appr["email"], subject, body):
                        sent_count += 1
            return {"message": f"Notification sent to {sent_count} approver(s)"}
        except Exception as e:
            return {"message": f"Error processing notification: {str(e)}"}
    except Exception as e:
        return {"message": f"General error: {str(e)}"}


@app.get("/admin/pending-leaves")
def get_pending_leaves(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        query = db.query(models.EmpLeave, models.EmpDet).join(
            models.EmpDet, models.EmpLeave.emp_id == models.EmpDet.emp_id
        ).filter(models.EmpLeave.status == "Pending")
        if manager_id:
            query = query.filter(
                or_(
                    func.lower(func.trim(models.EmpDet.assign_manager)) == manager_id.strip().lower(),
                    func.lower(func.trim(models.EmpDet.project_manager)) == manager_id.strip().lower()
                )
            )
        pending = query.order_by(models.EmpLeave.creation_date.desc()).all()
    except Exception as e:
        handle_db_error(e)
    results = []
    for leave, emp in pending:
        results.append({
            "l_id": leave.l_id, "emp_name": emp.name or "Unknown Employee",
            "emp_id": emp.emp_id.strip() if emp.emp_id else "",
            "leave_type": leave.leave_type, "from_date": leave.from_date, "to_date": leave.to_date,
            "days": leave.days, "reason": leave.reason, "remarks": leave.remarks or "",
            "status": leave.status, "file": leave.file
        })
    return results


@app.get("/admin/all-leave-history")
def get_all_leave_history(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        query = db.query(models.EmpLeave, models.EmpDet).join(
            models.EmpDet, models.EmpLeave.emp_id == models.EmpDet.emp_id
        )
        if manager_id:
            query = query.filter(
                or_(
                    func.lower(func.trim(models.EmpDet.assign_manager)) == manager_id.strip().lower(),
                    func.lower(func.trim(models.EmpDet.project_manager)) == manager_id.strip().lower()
                )
            )
        all_leaves = query.order_by(models.EmpLeave.creation_date.desc()).all()
    except Exception as e:
        handle_db_error(e)
    results = []
    for leave, emp in all_leaves:
        results.append({
            "l_id": leave.l_id, "emp_name": emp.name or "Unknown Employee",
            "emp_id": emp.emp_id.strip() if emp.emp_id else "",
            "leave_type": leave.leave_type, "from_date": leave.from_date, "to_date": leave.to_date,
            "days": leave.days, "reason": leave.reason, "remarks": leave.remarks or "",
            "status": leave.status, "file": leave.file, "revision": leave.revision
        })
    return results


@app.post("/admin/approve-leave")
def approve_leave(request_item: schemas.LeaveApprovalAction, background_tasks: BackgroundTasks,
                  db: Session = Depends(get_db)):
    try:
        leave = db.query(models.EmpLeave).filter(models.EmpLeave.l_id == request_item.l_id).first()
    except Exception as e:
        handle_db_error(e)
    if not leave:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Leave request not found")
    old_status = leave.status
    leave.status = request_item.action
    leave.remarks = request_item.remarks
    leave.last_update_date = datetime.now()
    if request_item.action == 'Approved':
        leave.admin_approval = 'Approved'; leave.hr_approval = 'Approved'
    elif request_item.action == 'Rejected':
        leave.admin_approval = 'Rejected'; leave.hr_approval = 'Rejected'
    admin_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == request_item.admin_id.strip()).first()
    if admin_user:
        leave.approved_by = admin_user.name
        leave.approver = admin_user.name

    try:
        val = str(leave.revision or "0")
        current_rev = int(''.join(filter(str.isdigit, val))) if any(c.isdigit() for c in val) else 0
    except (ValueError, TypeError):
        current_rev = 0

    if current_rev >= 3:
        raise HTTPException(status_code=400, detail="Maximum 3 revisions allowed for this leave request.")

    leave.revision = str(current_rev + 1)
    db.add(leave)

    if request_item.action == 'Rejected' and old_status != 'Rejected':
        l_type_key = leave.leave_type.strip().lower().split(' ')[0]
        balance = db.query(models.LeaveDet).filter(
            func.lower(func.trim(models.LeaveDet.emp_id)) == leave.emp_id.lower(),
            func.lower(func.trim(models.LeaveDet.leave_type)).contains(l_type_key)
        ).first()
        if balance:
            l_days = float(leave.days or 0)
            balance.availed_leave = max(0.0, float(balance.availed_leave or 0) - l_days)
            if balance.available_leave is not None:
                balance.available_leave = float(balance.available_leave) + l_days

    if request_item.action == 'Approved' and old_status != 'Approved':
        try:
            req_from = parse_date(leave.from_date)
            req_to = parse_date(leave.to_date) if leave.to_date else req_from
            if req_from and req_to:
                current_date = req_from
                cl_days = float(leave.days) if leave.days else 0.0
                lop_days = float(leave.lop_days) if leave.lop_days else 0.0
                requested_days = cl_days + lop_days
                temp_cl = cl_days
                temp_lop = lop_days
                prefix = "CL" if "casual" in (leave.leave_type or "").lower() else "SL" if "sick" in (leave.leave_type or "").lower() else "LOP"
                while current_date <= req_to:
                    day_val = 0.5 if requested_days == 0.5 else 1.0
                    day_status = ""
                    if temp_cl >= day_val:
                        day_status = f"{'0.5' if day_val == 0.5 else ''}{prefix}"; temp_cl -= day_val
                    elif temp_cl > 0:
                        day_status = f"0.5{prefix}"; temp_cl = 0
                    elif temp_lop >= day_val:
                        day_status = f"{'0.5' if day_val == 0.5 else ''}LOP"; temp_lop -= day_val
                    elif temp_lop > 0:
                        day_status = "0.5LOP"; temp_lop = 0
                    else:
                        day_status = f"{prefix}"
                    existing_checkin = db.query(models.CheckIn).filter(
                        models.CheckIn.emp_id == leave.emp_id,
                        models.CheckIn.t_date == current_date.date()
                    ).first()
                    if existing_checkin:
                        existing_checkin.status = day_status
                        existing_checkin.last_updated_by = request_item.admin_id
                        existing_checkin.last_update_date = datetime.now()
                        if not existing_checkin.in_time or existing_checkin.in_time == "--:--":
                            existing_checkin.in_time = ""; existing_checkin.out_time = ""; existing_checkin.Total_hours = ""
                    else:
                        db.add(models.CheckIn(
                            emp_id=leave.emp_id, t_date=current_date.date(),
                            t_day=current_date.strftime("%A"), month=current_date.strftime("%B"),
                            status=day_status, in_time="", out_time="", Total_hours="",
                            created_by=request_item.admin_id, creation_date=datetime.now(),
                            last_updated_by=request_item.admin_id, last_update_date=datetime.now()
                        ))
                    current_date += timedelta(days=1)
        except Exception as e:
            print(f"❌ Error syncing checkin for approval: {e}")

    db.commit()
    try:
        emp_user = db.query(models.EmpDet).filter(
            func.lower(func.trim(models.EmpDet.emp_id)) == (leave.emp_id or "").strip().lower()
        ).first()
        if emp_user and emp_user.p_mail:
            subject = f"ITS - {emp_user.name} - {leave.leave_type} Request | {leave.from_date}"
            
            # Original Table Content to be appended below the status
            month_str = ""
            try:
                from_dt = parse_date(leave.from_date)
                if from_dt: month_str = from_dt.strftime("%b-%y")
            except: pass
            
            pure_days = fmt_days(leave.days)
            
            status_content = f"""
            <p>Good Day!</p>
            <p>Your leave request has been <strong>{request_item.action}</strong>.</p>
            <br>
            <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #666; font-size: 14px;"><strong>Original Request Details:</strong></p>
            <table style="border-collapse: collapse; width: 100%; max-width: 600px; text-align: center; font-family: 'Times New Roman', Times, serif; border: 1px solid #000;">
                <thead>
                    <tr style="background-color: darkblue; color: #000; font-weight: bold;">
                        <th style="padding: 8px; border: 1px solid #000;">S.No</th>
                        <th style="padding: 8px; border: 1px solid #000;">Month</th>
                        <th style="padding: 8px; border: 1px solid #000; width: 40%;">Date</th>
                        <th style="padding: 8px; border: 1px solid #000;">Days</th>
                        <th style="padding: 8px; border: 1px solid #000;">Reason</th>
                    </tr>
                </thead>
                <tbody>
                    <tr style="color: darkblue; background-color: transparent;">
                        <td style="padding: 8px; border: 1px solid #000;">1</td>
                        <td style="padding: 8px; border: 1px solid #000;">{month_str}</td>
                        <td style="padding: 8px; border: 1px solid #000;">{leave.from_date} to {leave.to_date}</td>
                        <td style="padding: 8px; border: 1px solid #000;">{pure_days}</td>
                        <td style="padding: 8px; border: 1px solid #000;">{leave.reason}</td>
                    </tr>
                </tbody>
            </table>
            <br>
            """
            body = get_email_template(emp_user.name, f"Leave Request {request_item.action}", status_content, leave.approved_by or "Manager")
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
            if emp_user.attribute7:
                background_tasks.add_task(send_expo_push_notification, [emp_user.attribute7],
                    f"Leave Request {request_item.action}",
                    f"Your {leave.leave_type} request has been {request_item.action.lower()} by {leave.approved_by or 'Manager'}.")
    except Exception as e:
        print(f" Email_id notification failed: {e}")
    return {"message": f"Leave request {request_item.action.lower()} successfully", "approved_by": leave.approved_by}


from datetime import datetime, timedelta
from typing import Optional
import traceback

router = APIRouter()


def _status_type(s: str) -> str:
    s = (s or '').lower().strip()
    if s == 'pending':  return 'pending'
    if s == 'approved': return 'success'
    if s == 'rejected': return 'error'
    return 'info'


def _status_icon(s: str) -> str:
    s = (s or '').lower().strip()
    if s == 'pending':  return 'time-outline'
    if s == 'approved': return 'checkmark-circle'
    if s == 'rejected': return 'close-circle'
    return 'notifications-outline'


def _status_label(s: str) -> str:
    s = (s or '').lower().strip()
    if s == 'pending':  return 'Pending'
    if s == 'approved': return 'Approved'
    if s == 'rejected': return 'Rejected'
    return s.capitalize() or 'Unknown'


def _fmt_date(val) -> str:
    if val is None: return ''
    if hasattr(val, 'strftime'): return val.strftime('%d-%b-%Y')
    return str(val)


def _fmt_time(val) -> str:
    if val is None: return ''
    if hasattr(val, 'strftime'): return val.strftime('%I:%M %p')
    return str(val)


@router.get("/notifications/{user_id}")
def get_notifications(
    user_id: str,
    role: str = "employee",
    manager_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    user_id = user_id.strip().lower()
    role = (role or 'employee').strip().lower()
    notifications = []

    try:
        user = db.query(models.EmpDet).filter(
            func.lower(func.trim(models.EmpDet.emp_id)) == user_id
        ).first()
    except Exception as e:
        handle_db_error(e)

    last_clear_date: Optional[datetime] = None
    if user and user.attribute8 and str(user.attribute8).strip():
        raw = str(user.attribute8).strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                last_clear_date = datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue

    effective_cutoff: datetime = last_clear_date if last_clear_date else (datetime.now() - timedelta(days=30))

    def cutoff_filter(date_col, creation_col):
        return func.coalesce(date_col, creation_col) > effective_cutoff

    def standard_order(date_col, creation_col):
        return func.coalesce(date_col, creation_col).desc()

    if role in ('admin', 'manager', 'hr'):
        def apply_manager_filter(query, emp_model):
            if manager_id and manager_id.strip().lower() not in ('', 'all', 'none'):
                query = query.filter(
                    func.lower(func.trim(emp_model.assign_manager)) == manager_id.strip().lower()
                )
            return query

        try:
            q = (
                db.query(models.EmpPermission, models.EmpDet)
                .outerjoin(models.EmpDet,
                    func.lower(func.trim(models.EmpPermission.emp_id)) ==
                    func.lower(func.trim(models.EmpDet.emp_id)))
                .filter(func.lower(func.trim(models.EmpPermission.status)) == "pending")
                .filter(cutoff_filter(models.EmpPermission.last_update_date, models.EmpPermission.creation_date))
            )
            q = apply_manager_filter(q, models.EmpDet)
            for perm, emp in q.order_by(standard_order(models.EmpPermission.last_update_date, models.EmpPermission.creation_date)).limit(30).all():
                emp_name = (emp.name if emp else None) or "Unknown"
                st = (perm.status or 'Pending').strip()
                update_time = perm.last_update_date or perm.creation_date
                notifications.append({
                    "id": f"admin_permission_{perm.p_id}", "record_id": perm.p_id,
                    "type": _status_type(st), "notification_type": "permission",
                    "title": f"Permission Request – {emp_name}",
                    "message": f"{_status_label(st)} | {_fmt_date(perm.date)}: {_fmt_time(perm.f_time)} – {_fmt_time(perm.t_time)}",
                    "time": str(update_time or "Recently"), "icon": _status_icon(st),
                    "screen": f"/AdminPermission?tab=myApproval&p_id={perm.p_id}"
                })
        except Exception as e:
            print(f"  ❌ Admin permissions error: {e}")

        try:
            q = (
                db.query(models.EmpLeave, models.EmpDet)
                .outerjoin(models.EmpDet, func.lower(func.trim(models.EmpLeave.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id)))
                .filter(func.lower(func.trim(models.EmpLeave.status)) == "pending")
                .filter(cutoff_filter(models.EmpLeave.last_update_date, models.EmpLeave.creation_date))
            )
            q = apply_manager_filter(q, models.EmpDet)
            for leave, emp in q.order_by(standard_order(models.EmpLeave.last_update_date, models.EmpLeave.creation_date)).limit(30).all():
                emp_name = (emp.name if emp else None) or "Unknown"
                st = (leave.status or 'Pending').strip()
                update_time = leave.last_update_date or leave.creation_date or leave.applied_date
                notifications.append({
                    "id": f"admin_leave_{leave.l_id}", "record_id": leave.l_id,
                    "type": _status_type(st), "notification_type": "leave",
                    "title": f"Leave Request – {emp_name}",
                    "message": f"{_status_label(st)} | {leave.leave_type}: {leave.from_date} to {leave.to_date} ({fmt_days(leave.days)} {'Day' if float(leave.days or 0) == 1.0 else 'Days'})",
                    "time": str(update_time or "Recently"), "icon": _status_icon(st),
                    "screen": f"/AdminLeave?tab=myApproval&l_id={leave.l_id}"
                })
        except Exception as e:
            print(f"  ❌ Admin leaves error: {e}")

        try:
            q = (
                db.query(models.OverTimeDet, models.EmpDet)
                .outerjoin(models.EmpDet, func.lower(func.trim(models.OverTimeDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id)))
                .filter(func.lower(func.trim(models.OverTimeDet.status)) == "pending")
                .filter(cutoff_filter(models.OverTimeDet.last_update_date, models.OverTimeDet.creation_date))
            )
            q = apply_manager_filter(q, models.EmpDet)
            for ot, emp in q.order_by(standard_order(models.OverTimeDet.last_update_date, models.OverTimeDet.creation_date)).limit(30).all():
                emp_name = (emp.name if emp else None) or "Unknown"
                st = (ot.status or 'Pending').strip()
                update_time = ot.last_update_date or ot.creation_date
                notifications.append({
                    "id": f"admin_ot_{ot.ot_id}", "record_id": ot.ot_id,
                    "type": _status_type(st), "notification_type": "ot",
                    "title": f"OT Request – {emp_name}",
                    "message": f"{_status_label(st)} | {ot.ot_date}: {ot.duration} hrs",
                    "time": str(update_time or "Recently"), "icon": _status_icon(st),
                    "screen": f"/AdminOt?tab=myApproval&ot_id={ot.ot_id}"
                })
        except Exception as e:
            print(f"  ❌ Admin OT error: {e}")

        try:
            q = (
                db.query(models.WFHDet, models.EmpDet)
                .outerjoin(models.EmpDet, func.lower(func.trim(models.WFHDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id)))
                .filter(func.lower(func.trim(models.WFHDet.status)) == "pending")
                .filter(cutoff_filter(models.WFHDet.last_update_date, models.WFHDet.creation_date))
            )
            q = apply_manager_filter(q, models.EmpDet)
            for wfh, emp in q.order_by(standard_order(models.WFHDet.last_update_date, models.WFHDet.creation_date)).limit(30).all():
                emp_name = (emp.name if emp else None) or "Unknown"
                st = (wfh.status or 'Pending').strip()
                update_time = wfh.last_update_date or wfh.creation_date
                notifications.append({
                    "id": f"admin_wfh_{wfh.wfh_id}", "record_id": wfh.wfh_id,
                    "type": _status_type(st), "notification_type": "wfh",
                    "title": f"WFH Request – {emp_name}",
                    "message": f"{_status_label(st)} | {wfh.from_date} to {wfh.to_date}",
                    "time": str(update_time or "Recently"), "icon": _status_icon(st),
                    "screen": f"/AdminWfh?tab=myApproval&wfh_id={wfh.wfh_id}"
                })
        except Exception as e:
            print(f"  ❌ Admin WFH error: {e}")

        try:
            q = (
                db.query(models.TimesheetDet, models.EmpDet)
                .outerjoin(models.EmpDet, func.lower(func.trim(models.TimesheetDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id)))
                .filter(func.lower(func.trim(models.TimesheetDet.status)) == "pending")
                .filter(cutoff_filter(models.TimesheetDet.last_update_date, models.TimesheetDet.creation_date))
            )
            q = apply_manager_filter(q, models.EmpDet)
            for ts, emp in q.order_by(standard_order(models.TimesheetDet.last_update_date, models.TimesheetDet.creation_date)).limit(30).all():
                emp_name = (emp.name if emp else None) or "Unknown"
                st = (ts.status or 'Pending').strip()
                update_time = ts.last_update_date or ts.creation_date
                notifications.append({
                    "id": f"admin_timesheet_{ts.t_id}", "record_id": ts.t_id,
                    "type": _status_type(st), "notification_type": "timesheet",
                    "title": f"Timesheet – {emp_name}",
                    "message": f"{_status_label(st)} | {ts.date} – {ts.project or 'N/A'}",
                    "time": str(update_time or "Recently"), "icon": _status_icon(st),
                    "screen": "/AdminTimesheet"
                })
        except Exception as e:
            print(f"  ❌ Admin Timesheet error: {e}")

    try:
        for leave in (
            db.query(models.EmpLeave)
            .filter(
                func.lower(func.trim(models.EmpLeave.emp_id)) == user_id,
                func.lower(func.trim(models.EmpLeave.status)).in_(["approved", "rejected"]),
                cutoff_filter(models.EmpLeave.last_update_date, models.EmpLeave.creation_date)
            )
            .order_by(func.coalesce(models.EmpLeave.last_update_date, models.EmpLeave.creation_date).desc())
            .limit(30).all()
        ):
            st = (leave.status or 'Pending').strip()
            update_time = leave.last_update_date or leave.creation_date
            notifications.append({
                "id": f"emp_leave_{leave.l_id}", "record_id": leave.l_id,
                "type": _status_type(st), "notification_type": "leave",
                "title": f"Leave {_status_label(st)}",
                "message": f"{leave.leave_type}: {leave.from_date} to {leave.to_date} ({fmt_days(leave.days)} {'Day' if float(leave.days or 0) == 1.0 else 'Days'})",
                "time": str(update_time or "Recently"), "icon": _status_icon(st),
                "screen": f"/EmployeeLeave?tab=history&id={leave.l_id}"
            })
    except Exception as e:
        print(f"  ❌ Employee leaves error: {e}")

    try:
        for perm in (
            db.query(models.EmpPermission)
            .filter(
                func.lower(func.trim(models.EmpPermission.emp_id)) == user_id,
                func.lower(func.trim(models.EmpPermission.status)).in_(["approved", "rejected"]),
                cutoff_filter(models.EmpPermission.last_update_date, models.EmpPermission.creation_date)
            )
            .order_by(func.coalesce(models.EmpPermission.last_update_date, models.EmpPermission.creation_date).desc())
            .limit(30).all()
        ):
            st = (perm.status or 'Pending').strip()
            update_time = perm.last_update_date or perm.creation_date
            notifications.append({
                "id": f"emp_permission_{perm.p_id}", "record_id": perm.p_id,
                "type": _status_type(st), "notification_type": "permission",
                "title": f"Permission {_status_label(st)}",
                "message": f"Permission on {_fmt_date(perm.date)}",
                "time": str(update_time or "Recently"), "icon": _status_icon(st),
                "screen": f"/EmployeePermission?tab=history&id={perm.p_id}"
            })
    except Exception as e:
        print(f"  ❌ Employee permissions error: {e}")

    try:
        for ot in (
            db.query(models.OverTimeDet)
            .filter(
                func.lower(func.trim(models.OverTimeDet.emp_id)) == user_id,
                func.lower(func.trim(models.OverTimeDet.status)).in_(["pending", "approved", "rejected"]),
                cutoff_filter(models.OverTimeDet.last_update_date, models.OverTimeDet.creation_date)
            )
            .order_by(func.coalesce(models.OverTimeDet.last_update_date, models.OverTimeDet.creation_date).desc())
            .limit(30).all()
        ):
            st = (ot.status or 'Pending').strip()
            update_time = ot.last_update_date or ot.creation_date
            notifications.append({
                "id": f"emp_ot_{ot.ot_id}", "record_id": ot.ot_id,
                "type": _status_type(st), "notification_type": "ot",
                "title": f"OT {_status_label(st)}",
                "message": f"OT on {ot.ot_date}: {ot.duration} hrs",
                "time": str(update_time or "Recently"), "icon": _status_icon(st),
                "screen": f"/EmployeeOt?tab=history&id={ot.ot_id}"
            })
    except Exception as e:
        print(f"  ❌ Employee OT error: {e}")

    try:
        for wfh in (
            db.query(models.WFHDet)
            .filter(
                func.lower(func.trim(models.WFHDet.emp_id)) == user_id,
                func.lower(func.trim(models.WFHDet.status)).in_(["pending", "approved", "rejected"]),
                cutoff_filter(models.WFHDet.last_update_date, models.WFHDet.creation_date)
            )
            .order_by(func.coalesce(models.WFHDet.last_update_date, models.WFHDet.creation_date).desc())
            .limit(30).all()
        ):
            st = (wfh.status or 'Pending').strip()
            update_time = wfh.last_update_date or wfh.creation_date
            notifications.append({
                "id": f"emp_wfh_{wfh.wfh_id}", "record_id": wfh.wfh_id,
                "type": _status_type(st), "notification_type": "wfh",
                "title": f"WFH {_status_label(st)}",
                "message": f"WFH: {wfh.from_date} to {wfh.to_date}",
                "time": str(update_time or "Recently"), "icon": _status_icon(st),
                "screen": f"/EmployeeWfh?tab=history&id={wfh.wfh_id}"
            })
    except Exception as e:
        print(f"  ❌ Employee WFH error: {e}")

    try:
        for ts in (
            db.query(models.TimesheetDet)
            .filter(
                func.lower(func.trim(models.TimesheetDet.emp_id)) == user_id,
                func.lower(func.trim(models.TimesheetDet.status)).in_(["pending", "approved", "rejected"]),
                cutoff_filter(models.TimesheetDet.last_update_date, models.TimesheetDet.creation_date)
            )
            .order_by(func.coalesce(models.TimesheetDet.last_update_date, models.TimesheetDet.creation_date).desc())
            .limit(30).all()
        ):
            st = (ts.status or 'Pending').strip()
            update_time = ts.last_update_date or ts.creation_date
            notifications.append({
                "id": f"emp_timesheet_{ts.t_id}", "record_id": ts.t_id,
                "type": _status_type(st), "notification_type": "timesheet",
                "title": f"Timesheet {_status_label(st)}",
                "message": f"Timesheet: {ts.date} – {ts.project or 'N/A'}",
                "time": str(update_time or "Recently"), "icon": _status_icon(st),
                "screen": "/EmployeeTimesheet"
            })
    except Exception as e:
        print(f"  ❌ Employee Timesheet error: {e}")

    print(f"✅ Returning {len(notifications)} notifications for {user_id} (role={role})")
    return notifications


@router.post("/notifications/clear-all/{user_id}")
def clear_all_notifications(user_id: str, db: Session = Depends(get_db)):
    user_id = user_id.strip().lower()
    try:
        user = db.query(models.EmpDet).filter(
            func.lower(func.trim(models.EmpDet.emp_id)) == user_id
        ).first()
    except Exception as e:
        handle_db_error(e)
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{user_id}' not found")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user.attribute8 = now_str
    db.commit()
    return {"message": "All notifications cleared", "cleared_at": now_str}


@app.post("/apply-ot")
def apply_ot(request: schemas.OverTimeApplyRequest, background_tasks: BackgroundTasks,
             db: Session = Depends(get_db)):
    try:
        user = db.query(models.EmpDet).filter(func.trim(models.EmpDet.emp_id) == request.emp_id.strip()).first()
        if not user:
            raise HTTPException(status_code=404, detail="Employee not found")
        target_emp_id = user.emp_id
        ot_date_clean = (request.ot_date or "").strip()
        if not ot_date_clean:
            raise HTTPException(status_code=400, detail="Invalid OT date")
        duplicate_ot = db.query(models.OverTimeDet).filter(
            func.lower(func.trim(models.OverTimeDet.emp_id)) == target_emp_id.strip().lower(),
            func.lower(func.trim(models.OverTimeDet.ot_date)) == ot_date_clean.lower(),
            func.lower(func.trim(models.OverTimeDet.status)).in_(["pending", "approved"])
        ).first()
        if duplicate_ot:
            raise HTTPException(status_code=400, detail=f"OT already applied for {ot_date_clean}.")
        new_ot = models.OverTimeDet(
            emp_id=target_emp_id, ot_date=request.ot_date, from_time=request.from_time,
            to_time=request.to_time, duration=request.duration, reason=request.reason,
            applied_date=datetime.now().strftime("%d-%b-%Y"), status=request.status or "Pending",
            created_by=target_emp_id, creation_date=datetime.now(),
            last_updated_by=target_emp_id, last_update_date=datetime.now(), last_update_login=target_emp_id
        )
        db.add(new_ot)
        db.commit()
        db.refresh(new_ot)
        try:
            approvers = get_approvers(db, user)
            subject = f"ITS - {user.name} - OT Request | {ot_date_clean} | {request.from_time} to {request.to_time}"
            for appr in approvers:
                if appr["email"]:
                    content = f"<p>OT request from {user.name} for {ot_date_clean} ({request.from_time} to {request.to_time}).<br>Reason: {request.reason}</p>"
                    body = get_email_template(appr["name"], "New Overtime Request", content, user.name)
                    background_tasks.add_task(send_email_notification, appr["email"], subject, body)
                if appr["token"]:
                    background_tasks.add_task(send_expo_push_notification, [appr["token"]],
                        "New OT Request", f"{user.name} requested OT for {ot_date_clean} ({request.duration}).")
        except Exception as mail_err:
            print(f" Non-critical OT notification error: {mail_err}")
        return {"message": "OT request submitted successfully", "ot_id": new_ot.ot_id}
    except HTTPException:
        db.rollback(); raise
    except Exception as e:
        print(f" OT INSERT ERROR: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=503, detail="Database unavailable. Please try again shortly.")


@app.get("/admin/pending-permissions")
def get_pending_permissions(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        query = db.query(models.EmpPermission, models.EmpDet).join(
            models.EmpDet,
            func.lower(func.trim(models.EmpPermission.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
        ).filter(func.lower(func.trim(models.EmpPermission.status)) == "pending")
        if manager_id:
            query = query.filter(
                or_(
                    func.lower(func.trim(models.EmpDet.assign_manager)) == manager_id.strip().lower(),
                    func.lower(func.trim(models.EmpDet.project_manager)) == manager_id.strip().lower()
                )
            )
        pending = query.order_by(models.EmpPermission.creation_date.desc()).all()
    except Exception as e:
        handle_db_error(e)
    results = []
    for perm, emp in pending:
        try:
            date_str = perm.date.strftime("%d-%b-%Y") if perm.date else ""
        except Exception:
            date_str = str(perm.date) if perm.date else ""
        f_time_str = format_time_safe(perm.f_time)
        t_time_str = format_time_safe(perm.t_time)
        results.append({
            "p_id": perm.p_id, "emp_name": emp.name or "Unknown", "emp_id": emp.emp_id or "N/A",
            "date": date_str, "time": f"{f_time_str} to {t_time_str}",
            "fromTime": f_time_str, "toTime": t_time_str, "f_time": f_time_str, "t_time": t_time_str,
            "total_hours": str(perm.total_hours or "0"), "dis_total_hours": str(perm.dis_total_hours or "0"),
            "permitted_hours": str(perm.permitted_permission or "0"), "lop_hours": str(perm.lop_hours or "0"),
            "reason": perm.reason or "No reason", "remarks": perm.remarks or "",
            "status": perm.status or "Pending",
            "applied_date": str(perm.applied_date) if perm.applied_date else "",
            "creation_date": str(perm.creation_date) if perm.creation_date else "",
        })
    return results


@app.get("/admin/all-permission-history")
def get_all_permission_history(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        query = db.query(models.EmpPermission, models.EmpDet).join(
            models.EmpDet,
            func.lower(func.trim(models.EmpPermission.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
        )
        if manager_id:
            query = query.filter(
                or_(
                    func.lower(func.trim(models.EmpDet.assign_manager)) == manager_id.strip().lower(),
                    func.lower(func.trim(models.EmpDet.project_manager)) == manager_id.strip().lower()
                )
            )
        all_perms = query.order_by(models.EmpPermission.creation_date.desc()).all()
    except Exception as e:
        handle_db_error(e)
    results = []
    for perm, emp in all_perms:
        try:
            date_str = perm.date.strftime("%d-%b-%Y") if perm.date else ""
        except Exception:
            date_str = str(perm.date) if perm.date else ""
        f_time_str = format_time_safe(perm.f_time)
        t_time_str = format_time_safe(perm.t_time)
        results.append({
            "p_id": perm.p_id, "emp_name": emp.name or "Unknown", "emp_id": emp.emp_id or "N/A",
            "date": date_str, "time": f"{f_time_str} to {t_time_str}",
            "fromTime": f_time_str, "toTime": t_time_str, "f_time": f_time_str, "t_time": t_time_str,
            "total_hours": str(perm.total_hours or "0"), "dis_total_hours": str(perm.dis_total_hours or "0"),
            "permitted_hours": str(perm.permitted_permission or "0"), "lop_hours": str(perm.lop_hours or "0"),
            "reason": perm.reason or "No reason", "remarks": perm.remarks or "",
            "status": perm.status or "Pending",
            "applied_date": str(perm.applied_date) if perm.applied_date else "",
            "creation_date": str(perm.creation_date) if perm.creation_date else "",
            "last_update_date": str(perm.last_update_date) if perm.last_update_date else "",
        })
    return results


@app.post("/apply-permission")
def apply_permission(request: schemas.PermissionApplyRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        target_emp_id = (request.emp_id or "").strip().lower()
        user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == target_emp_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Employee not found")
        p_date_dt = parse_date(request.date)
        if not p_date_dt:
            raise HTTPException(status_code=400, detail=f"Invalid date format: {request.date}")
        p_date = p_date_dt.date()
        f_time_dt = parse_time_str(request.f_time)
        t_time_dt = parse_time_str(request.t_time)
        if not f_time_dt:
            raise HTTPException(status_code=400, detail=f"Invalid from time format: {request.f_time}")
        if not t_time_dt:
            raise HTTPException(status_code=400, detail=f"Invalid to time format: {request.t_time}")
        h1, m1 = f_time_dt.hour, f_time_dt.minute
        h2, m2 = t_time_dt.hour, t_time_dt.minute
        diff_mins = (h2 * 60 + m2) - (h1 * 60 + m1)
        if diff_mins <= 0:
            raise HTTPException(status_code=400, detail="To Time must be after From Time")
        if diff_mins <= 60:
            approved_hrs = 1.0; lop_hrs = 0.0
        elif diff_mins <= 120:
            approved_hrs = 2.0; lop_hrs = 0.0
        else:
            approved_hrs = 2.0; lop_hrs = (diff_mins - 120.0) / 60.0
        total_hrs_val = diff_mins / 60.0
        duplicate = db.query(models.EmpPermission).filter(
            func.lower(func.trim(models.EmpPermission.emp_id)) == target_emp_id,
            models.EmpPermission.date == p_date,
            func.lower(func.trim(models.EmpPermission.status)).in_(["pending", "approved"])
        ).first()
        if duplicate:
            raise HTTPException(status_code=400, detail=f"Permission already applied for {request.date}.")
        try:
            curr_val = str(user.remaining_perm or "").strip()
            if not curr_val or curr_val in ("None", ""):
                try:
                    curr_perm = float(str(user.permission or "0").strip())
                except Exception:
                    curr_perm = 4.0
            else:
                curr_perm = float(curr_val)
        except Exception:
            curr_perm = 4.0
        new_remaining = max(0.0, curr_perm - approved_hrs)
        user.remaining_perm = str(round(new_remaining, 2))
        new_perm = models.EmpPermission(
            emp_id=user.emp_id.strip(), date=p_date,
            f_time=f_time_dt.time(), t_time=t_time_dt.time(),
            reason=request.reason, total_hours=f"{total_hrs_val:.2f}",
            dis_total_hours=f"{lop_hrs:.2f}", available_hours=str(round(new_remaining, 2)),
            status="Pending", applied_date=datetime.now().strftime("%d-%b-%Y"),
            permitted_permission=approved_hrs, lop_hours=lop_hrs,
            created_by=user.emp_id.strip(), creation_date=datetime.now(),
            last_updated_by=user.emp_id.strip(), last_update_date=datetime.now(),
            reporting_to=user.assign_manager, attribute_category=user.project_manager, revision="0"
        )
        db.add(new_perm)
        db.commit()
        db.refresh(new_perm)
        try:
            approvers = get_approvers(db, user)
            f_display = f_time_dt.strftime("%I:%M %p").lstrip('0')
            t_display = t_time_dt.strftime("%I:%M %p").lstrip('0')
            subject = f"ITS - {user.name} - Permission Request | {request.date} | {f_display} to {t_display}"
            for appr in approvers:
                if appr["email"]:
                    content = f'''
                    <p><strong>Good Day!</strong></p>
                    <p>I would like to request permission on <strong>{request.date}</strong> from <strong>{f_display}</strong> to <strong>{t_display}</strong>.</p>
                    <p><strong>Approved Hours:</strong> {approved_hrs} hr</p>
                    {f'<p><strong>LOP Hours:</strong> {round(lop_hrs, 2)} hr</p>' if lop_hrs > 0 else ''}
                    <p><strong>Reason:</strong> {request.reason}</p>
                    '''
                    body = get_email_template(appr["name"], "Permission Request", content, user.name)
                    background_tasks.add_task(send_email_notification, appr["email"], subject, body)
                if appr["token"]:
                    background_tasks.add_task(send_expo_push_notification, [appr["token"]],
                        "New Permission Request", f"{user.name} requested permission for {request.date} ({f_display} to {t_display}).")
        except Exception as mail_err:
            print(f"   Non-critical email error: {mail_err}")
        return {"message": "Permission applied successfully", "p_id": new_perm.p_id, "approved_hrs": approved_hrs, "lop_hrs": round(lop_hrs, 2)}
    except HTTPException:
        db.rollback(); raise
    except Exception as e:
        db.rollback(); traceback.print_exc()
        raise HTTPException(status_code=503, detail="Database unavailable. Please try again shortly.")


@app.post("/admin/approve-permission")
def approve_permission(request: schemas.PermissionApprovalAction, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        perm = db.query(models.EmpPermission).filter(models.EmpPermission.p_id == request.p_id).first()
    except Exception as e:
        handle_db_error(e)
    if not perm:
        raise HTTPException(status_code=404, detail="Permission request not found")
    old_status = (perm.status or "").strip().lower()
    new_action = request.action.strip()
    perm.status = new_action
    perm.remarks = request.remarks or ""
    perm.last_update_date = datetime.now()
    perm.last_updated_by = request.admin_id.strip()
    try:
        curr_rev = int(perm.revision) if perm.revision and str(perm.revision).isdigit() else 0
        perm.revision = str(curr_rev + 1)
    except:
        perm.revision = "1"
    admin_user = db.query(models.EmpDet).filter(
        func.lower(func.trim(models.EmpDet.emp_id)) == request.admin_id.strip().lower()
    ).first()
    if admin_user:
        perm.approved_by = admin_user.name
        perm.remarks = (request.remarks or "").strip() + f" (Action by: {admin_user.name})"
    if new_action.lower() == "rejected" and old_status != "rejected":
        user = db.query(models.EmpDet).filter(
            func.lower(func.trim(models.EmpDet.emp_id)) == (perm.emp_id or "").strip().lower()
        ).first()
        if user:
            try:
                approved_to_refund = float(perm.permitted_permission) if perm.permitted_permission else 0.0
                curr_rem = float(user.remaining_perm or 0)
                user.remaining_perm = str(round(curr_rem + approved_to_refund, 2))
            except Exception as refund_err:
                print(f"Refund error: {refund_err}")
    db.commit()
    try:
        emp_user = db.query(models.EmpDet).filter(
            func.lower(func.trim(models.EmpDet.emp_id)) == (perm.emp_id or "").strip().lower()
        ).first()
        if emp_user and emp_user.p_mail:
            perm_date = perm.date.strftime("%d-%b-%Y") if perm.date else "N/A"
            f_time_str = format_time_safe(perm.f_time)
            t_time_str = format_time_safe(perm.t_time)
            subject = f"ITS - Permission Request {new_action} - {perm_date}"
            content = f'''
            <p>Your request for <strong>Permission</strong> has been processed.</p>
            <div style="font-size: 20px; font-weight: 700; color: #1f2937; margin: 20px 0;">{new_action}</div>
            <p>Permission on <strong>{perm_date}</strong> from <strong>{f_time_str}</strong> to <strong>{t_time_str}</strong> has been <strong>{new_action}</strong>.</p>
            {f'<p><strong>Remarks:</strong> {request.remarks}</p>' if request.remarks else ''}
            '''
            body = get_email_template(emp_user.name, f"Permission Request {new_action}", content, admin_user.name if admin_user else "Manager")
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
            if emp_user.attribute7:
                background_tasks.add_task(send_expo_push_notification, [emp_user.attribute7],
                    f"Permission Request {new_action}", f"Your permission request for {perm_date} has been {new_action.lower()}.")
    except Exception as e:
        print(f"Email_id notification failed: {e}")
    return {"message": f"Permission {new_action.lower()} successfully"}


@app.get("/admin/pending-ot")
def get_pending_ot(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        query = db.query(models.OverTimeDet, models.EmpDet).outerjoin(
            models.EmpDet,
            func.lower(func.trim(models.OverTimeDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
        ).filter(func.lower(models.OverTimeDet.status) == "pending")
        if manager_id:
            query = query.filter(
                or_(
                    func.lower(func.trim(models.EmpDet.assign_manager)) == manager_id.strip().lower(),
                    func.lower(func.trim(models.EmpDet.project_manager)) == manager_id.strip().lower()
                )
            )
        pending = query.order_by(models.OverTimeDet.creation_date.desc()).all()
    except Exception as e:
        handle_db_error(e)
    results = []
    for ot, emp in pending:
        results.append({
            "ot_id": ot.ot_id, "emp_name": emp.name if emp else f"Unknown ({ot.emp_id})",
            "emp_id": ot.emp_id or "N/A", "ot_date": ot.ot_date, "date": ot.ot_date,
            "startTime": ot.from_time, "endTime": ot.to_time,
            "start_time": ot.from_time, "end_time": ot.to_time,
            "duration": ot.duration, "reason": ot.reason or "No reason", "remarks": ot.remarks or "",
            "status": (ot.status or "Pending").strip().capitalize(),
            "submittedDate": ot.applied_date or (ot.creation_date.strftime("%d-%b-%Y") if ot.creation_date else "N/A")
        })
    return results


@app.get("/admin/all-ot-history")
def get_all_ot_history(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        query = db.query(models.OverTimeDet, models.EmpDet).outerjoin(
            models.EmpDet,
            func.lower(func.trim(models.OverTimeDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
        )
        if manager_id:
            query = query.filter(
                or_(
                    func.lower(func.trim(models.EmpDet.assign_manager)) == manager_id.strip().lower(),
                    func.lower(func.trim(models.EmpDet.project_manager)) == manager_id.strip().lower()
                )
            )
        all_ot = query.order_by(models.OverTimeDet.creation_date.desc()).all()
    except Exception as e:
        handle_db_error(e)
    results = []
    for ot, emp in all_ot:
        results.append({
            "ot_id": ot.ot_id, "emp_name": emp.name if emp else f"Unknown ({ot.emp_id})",
            "emp_id": ot.emp_id or "N/A", "ot_date": ot.ot_date, "date": ot.ot_date,
            "startTime": ot.from_time, "endTime": ot.to_time,
            "start_time": ot.from_time, "end_time": ot.to_time,
            "duration": ot.duration, "reason": ot.reason or "No reason", "remarks": ot.remarks or "",
            "status": (ot.status or "Pending").strip().capitalize(),
            "submittedDate": ot.applied_date or (ot.creation_date.strftime("%d-%b-%Y") if ot.creation_date else "N/A")
        })
    return results


@app.post("/admin/approve-ot")
def approve_ot(request: schemas.OverTimeApprovalAction, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        ot = db.query(models.OverTimeDet).filter(models.OverTimeDet.ot_id == request.ot_id).first()
    except Exception as e:
        handle_db_error(e)
    if not ot:
        raise HTTPException(status_code=404, detail="OT request not found")
    ot.status = request.action
    ot.remarks = request.remarks
    ot.last_update_date = datetime.now()
    ot.approved_date = datetime.now().strftime("%d-%b-%Y")
    admin_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == request.admin_id.strip()).first()
    if admin_user:
        ot.approved_by = admin_user.name
        ot.remarks = f"{(request.remarks or '').strip()} (Action by: {admin_user.name})".strip()
    db.commit()
    try:
        emp_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == ot.emp_id).first()
        if emp_user and emp_user.p_mail:
            subject = f"OT Request {request.action.upper()} - {ot.ot_date}"
            content = f"""
            <p>Your request for <strong>Overtime</strong> has been processed.</p>
            <div style="font-size: 20px; font-weight: 700; color: #1f2937; margin: 20px 0;">{request.action}</div>
            <p><strong>Date:</strong> {ot.ot_date}</p>
            <p><strong>Duration:</strong> {ot.duration}</p>
            <p><strong>Remarks:</strong> {request.remarks or 'No remarks provided.'}</p>
            """
            body = get_email_template(emp_user.name, "OT Request Update", content, "HR Team")
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
            if emp_user.attribute7:
                background_tasks.add_task(send_expo_push_notification, [emp_user.attribute7],
                    f"OT Request {request.action.upper()}", f"Your OT request for {ot.ot_date} has been {request.action.lower()}.")
    except Exception as e:
        print(f" Email_id notification failed: {e}")
    return {"message": f"OT request {request.action.lower()} successfully"}


@app.get("/admin/pending-wfh")
def get_pending_wfh(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        query = db.query(models.WFHDet, models.EmpDet).join(
            models.EmpDet,
            func.lower(func.trim(models.WFHDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
        ).filter(models.WFHDet.status == "Pending")
        if manager_id:
            query = query.filter(
                or_(
                    func.lower(func.trim(models.EmpDet.assign_manager)) == manager_id.strip().lower(),
                    func.lower(func.trim(models.EmpDet.project_manager)) == manager_id.strip().lower()
                )
            )
        pending = query.order_by(models.WFHDet.creation_date.desc()).all()
    except Exception as e:
        handle_db_error(e)
    results = []
    for wfh, emp in pending:
        results.append({
            "wfh_id": wfh.wfh_id, "emp_name": emp.name or "Unknown", "emp_id": emp.emp_id or "N/A",
            "date": wfh.from_date, "from_date": wfh.from_date, "to_date": wfh.to_date,
            "reason": wfh.reason or "No reason", "remarks": "", "status": wfh.status or "Pending",
            "submittedDate": wfh.creation_date.strftime("%d-%b-%Y") if wfh.creation_date else "N/A"
        })
    return results


@app.get("/admin/all-wfh-history")
def get_all_wfh_history(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        query = db.query(models.WFHDet, models.EmpDet).outerjoin(
            models.EmpDet,
            func.lower(func.trim(models.WFHDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
        )
        if manager_id:
            query = query.filter(
                or_(
                    func.lower(func.trim(models.EmpDet.assign_manager)) == manager_id.strip().lower(),
                    func.lower(func.trim(models.EmpDet.project_manager)) == manager_id.strip().lower()
                )
            )
        all_wfh = query.order_by(models.WFHDet.creation_date.desc()).all()
        results = []
        for wfh, emp in all_wfh:
            results.append({
                "wfh_id": wfh.wfh_id, "emp_name": emp.name if emp else "Unknown",
                "emp_id": wfh.emp_id, "date": wfh.from_date, "from_date": wfh.from_date,
                "to_date": wfh.to_date, "days": wfh.days, "reason": wfh.reason or "No reason",
                "remarks": "", "status": wfh.status or "Pending",
                "submittedDate": wfh.creation_date.strftime("%d-%b-%Y") if wfh.creation_date else "N/A"
            })
        return results
    except Exception as e:
        handle_db_error(e)


@app.post("/admin/approve-wfh")
def approve_wfh(request: schemas.WFHApprovalAction, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        wfh = db.query(models.WFHDet).filter(models.WFHDet.wfh_id == request.wfh_id).first()
    except Exception as e:
        handle_db_error(e)
    if not wfh:
        raise HTTPException(status_code=404, detail="WFH request not found")
    wfh.status = request.action
    wfh.last_update_date = datetime.now()
    admin_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == request.admin_id.strip()).first()
    db.commit()
    try:
        emp_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == wfh.emp_id).first()
        if emp_user and emp_user.p_mail:
            subject = f"WFH Request {request.action.upper()} - {wfh.from_date}"
            content = f"""
            <p>Your request for <strong>Work From Home</strong> has been processed.</p>
            <div style="font-size: 20px; font-weight: 700; color: #1f2937; margin: 20px 0;">{request.action}</div>
            <p><strong>Duration:</strong> {wfh.from_date} to {wfh.to_date}</p>
            <p><strong>No of Days:</strong> {fmt_days(wfh.days)} {"Day" if float(wfh.days or 0) == 1.0 else "Days"}</p>
            <p><strong>Remarks:</strong> {request.remarks or 'No remarks provided.'}</p>
            """
            body = get_email_template(emp_user.name, "WFH Request Update", content, "HR Team")
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
            if emp_user.attribute7:
                background_tasks.add_task(send_expo_push_notification, [emp_user.attribute7],
                    f"WFH Request {request.action.upper()}", f"Your WFH request for {wfh.from_date} has been {request.action.lower()}.")
    except Exception as e:
        print(f" Email_id notification failed: {e}")
    return {"message": f"WFH request {request.action.lower()} successfully"}


@app.get("/wfh-stats/{emp_id}")
def get_wfh_stats(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    try:
        wfh_records = db.query(models.WFHDet).filter(
            func.lower(func.trim(models.WFHDet.emp_id)) == emp_id.lower()).all()
    except Exception as e:
        handle_db_error(e)
    total_wfh = len(wfh_records)
    approved_wfh = sum(1 for r in wfh_records if r.status and r.status.lower() == 'approved')
    rejected_wfh = sum(1 for r in wfh_records if r.status and r.status.lower() == 'rejected')
    return {"total": total_wfh, "approved": approved_wfh, "rejected": rejected_wfh}


@app.post("/apply-wfh")
def apply_wfh(request: schemas.WFHApplyRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        clean_emp_id = request.emp_id.strip()
        from_date_input = request.from_date or request.date
        if not from_date_input:
            raise HTTPException(status_code=400, detail="from_date is required")
        from_date = from_date_input.strip()
        to_date = (request.to_date or from_date).strip()
        days_val = str(request.days) if request.days is not None else "1"
        req_from = parse_date(from_date)
        req_to = parse_date(to_date)
        if not req_from or not req_to:
            raise HTTPException(status_code=400, detail="Invalid WFH from/to date format")
        if req_to < req_from:
            raise HTTPException(status_code=400, detail="To date must be on or after from date")
        existing_wfh = db.query(models.WFHDet).filter(
            func.lower(func.trim(models.WFHDet.emp_id)) == clean_emp_id.lower(),
            func.lower(func.trim(models.WFHDet.status)).in_(["pending", "approved"])
        ).all()
        for row in existing_wfh:
            row_from = parse_date(row.from_date)
            row_to = parse_date(row.to_date) if row.to_date else row_from
            if not row_from or not row_to: continue
            if not (req_to < row_from or req_from > row_to):
                raise HTTPException(status_code=400,
                    detail=f"WFH already applied for overlapping dates ({row.from_date} to {row.to_date}).")
        submitter = db.query(models.EmpDet).filter(
            func.lower(func.trim(models.EmpDet.emp_id)) == clean_emp_id.lower()
        ).first()
        normalized_status = (request.status or "Pending").strip() or "Pending"
        if normalized_status.lower() == "pending":
            normalized_status = "Pending"
        new_wfh = models.WFHDet(
            emp_id=clean_emp_id, from_date=from_date, to_date=to_date, days=days_val,
            reason=request.reason, status=normalized_status,
            created_by=clean_emp_id, creation_date=datetime.now(),
            last_updated_by=clean_emp_id, last_update_date=datetime.now(), last_update_login=clean_emp_id
        )
        db.add(new_wfh)
        db.commit()
        db.refresh(new_wfh)
        user = submitter
        try:
            if user:
                approvers = get_approvers(db, user)
                try:
                    from_dt = parse_date(from_date)
                    to_dt = parse_date(to_date)
                    from_str = from_dt.strftime("%d-%b-%Y") if from_dt else from_date
                    to_str = to_dt.strftime("%d-%b-%Y") if to_dt else to_date
                except:
                    from_str = from_date; to_str = to_date
                wfh_days_fmt = fmt_days(days_val)
                wfh_day_label = "Day" if float(days_val or 0) == 1.0 else "Days"
                subject = f"ITS - {user.name} - WFH | {from_str} to {to_str} ({wfh_days_fmt} {wfh_day_label})"
                for appr in approvers:
                    if appr["email"]:
                        content = f"<p>{user.name} requested WFH from {from_str} to {to_str} ({wfh_days_fmt} {wfh_day_label}).<br>Reason: {request.reason}</p>"
                        body = get_email_template(appr["name"], "Work From Home Request", content, user.name)
                        background_tasks.add_task(send_email_notification, appr["email"], subject, body)
                    if appr["token"]:
                        background_tasks.add_task(send_expo_push_notification, [appr["token"]],
                            "New WFH Request", f"{user.name} requested WFH from {from_str} to {to_str}.")
        except Exception as mail_err:
            print(f" Non-critical WFH notification error: {mail_err}")
        return {"message": "WFH request submitted successfully", "wfh_id": new_wfh.wfh_id}
    except HTTPException:
        db.rollback(); raise
    except Exception as e:
        db.rollback(); traceback.print_exc()
        raise HTTPException(status_code=503, detail="Database unavailable. Please try again shortly.")


@app.get("/permission-stats/{emp_id}")
def get_permission_stats(emp_id: str, db: Session = Depends(get_db)):
    try:
        emp_id_clean = (emp_id or "").strip()
        user = db.query(models.EmpDet).filter(
            func.lower(func.trim(models.EmpDet.emp_id)) == emp_id_clean.lower()
        ).first()
        if not user:
            return {"total": 0, "remaining": 0}
        try:
            total_raw = str(user.permission or "0").strip()
            total = float(total_raw) if total_raw and total_raw not in ("", "None") else 0.0
        except (ValueError, TypeError):
            total = 0.0
        try:
            rem_raw = str(user.remaining_perm or "").strip()
            if not rem_raw or rem_raw in ("None", ""):
                remaining = total
                user.remaining_perm = str(round(total, 2))
                db.commit()
            else:
                remaining = float(rem_raw)
        except (ValueError, TypeError):
            remaining = total
        return {"total": round(total, 2), "remaining": round(remaining, 2)}
    except Exception as e:
        print(f"permission-stats error: {e}")
        return {"total": 0, "remaining": 0}


@app.get("/permission-history/{emp_id}")
def get_permission_history(emp_id: str, db: Session = Depends(get_db)):
    try:
        emp_id_clean = (emp_id or "").strip()
        history = db.query(models.EmpPermission).filter(
            func.lower(func.trim(models.EmpPermission.emp_id)) == emp_id_clean.lower()
        ).order_by(models.EmpPermission.p_id.desc()).all()
        result = []
        for row in history:
            try:
                date_str = row.date.strftime("%d-%b-%Y") if row.date and hasattr(row.date, 'strftime') else str(row.date or "")
            except Exception:
                date_str = str(row.date) if row.date else ""
            result.append({
                "p_id": row.p_id, "emp_id": row.emp_id or "",
                "date": date_str,
                "f_time": format_time_safe(row.f_time), "t_time": format_time_safe(row.t_time),
                "total_hours": str(row.total_hours or "0"), "dis_total_hours": str(row.dis_total_hours or "0"),
                "permitted_hours": str(row.permitted_permission or "0"), "lop_hours": str(row.lop_hours or "0"),
                "reason": row.reason or "", "status": row.status or "Pending",
                "remarks": row.remarks or "", "approved_by": row.approved_by or "",
                "applied_date": str(row.applied_date) if row.applied_date else "",
                "creation_date": str(row.creation_date) if row.creation_date else "",
                "last_update_date": str(row.last_update_date) if row.last_update_date else "",
            })
        return result
    except Exception as e:
        print(f"permission-history error: {e}")
        traceback.print_exc()
        return []


@app.get("/dashboard/{emp_id}", response_model=schemas.DashboardResponse)
def get_dashboard(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    try:
        user = db.query(models.EmpDet).filter(
            func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
    except Exception as e:
        handle_db_error(e)
    if not user:
        raise HTTPException(status_code=404, detail=f"User {emp_id} not found")
    today = datetime.now()
    domain_name = "Employee"
    if user.dom_id:
        try:
            d_id = int(str(user.dom_id).strip())
            domain = db.query(models.Domain).filter(models.Domain.dom_id == d_id).first()
            if domain:
                domain_name = domain.domain
        except:
            pass
    all_emps = db.query(models.EmpDet).filter(
        (models.EmpDet.end_date == None) | (models.EmpDet.end_date == "")
    ).all()

    upcoming_events = []
    today_flat = today.replace(hour=0, minute=0, second=0, microsecond=0)

    try:
        all_holidays = db.query(models.HolidayDet).all()
        for h in all_holidays:
            h_date = parse_date(h.Office_Holiday_Date)
            if h_date:
                h_date_flat = h_date.replace(hour=0, minute=0, second=0, microsecond=0)
                show_h = (h_date_flat.month == today.month and h_date_flat.year == today.year) or \
                         (0 <= (h_date_flat - today_flat).days <= 90)
                if show_h:
                    upcoming_events.append({
                        "id": f"holiday_{h.holiday_id}", "name": h.Holiday_Name, "type": "holiday",
                        "date": h_date.strftime("%d %b"), "day": h_date.strftime("%A"),
                        "raw_date": h_date_flat
                    })
    except Exception as e:
        print(f" Error fetching holidays: {e}")

    for emp in all_emps:
        if emp.dob:
            bday = parse_date(emp.dob)
            if bday:
                this_year_bday = bday.replace(year=today.year)
                this_year_bday_flat = this_year_bday.replace(hour=0, minute=0, second=0, microsecond=0)
                if this_year_bday_flat.month == today.month or (0 <= (this_year_bday_flat - today_flat).days <= 60):
                    upcoming_events.append({
                        "id": f"bday_{emp.emp_id}_{this_year_bday.strftime('%Y%m%d')}",
                        "name": f"{emp.name}'s Birthday", "type": "birthday",
                        "date": this_year_bday.strftime("%d %b"), "day": this_year_bday.strftime("%A"),
                        "raw_date": this_year_bday_flat
                    })
        if emp.date_of_joining:
            join_date = parse_date(emp.date_of_joining)
            if join_date:
                this_anniv = join_date.replace(year=today.year)
                this_anniv_flat = this_anniv.replace(hour=0, minute=0, second=0, microsecond=0)
                if this_anniv_flat.month == today.month or (0 <= (this_anniv_flat - today_flat).days <= 60):
                    upcoming_events.append({
                        "id": f"anniv_{emp.emp_id}_{this_anniv.strftime('%Y%m%d')}",
                        "name": f"{emp.name}'s Anniversary", "type": "anniversary",
                        "date": this_anniv.strftime("%d %b"), "day": this_anniv.strftime("%A"),
                        "raw_date": this_anniv_flat
                    })

    upcoming_events.sort(key=lambda x: x["raw_date"])
    for event in upcoming_events:
        del event["raw_date"]

    notifications = []
    is_admin = False
    if user.dom_id:
        try:
            d_id = int(str(user.dom_id).strip())
            user_domain = db.query(models.Domain).filter(models.Domain.dom_id == d_id).first()
            if user_domain:
                dn = user_domain.domain.lower()
                if 'admin' in dn or 'management' in dn:
                    is_admin = True
        except:
            pass
    recent_date_limit = datetime.now() - timedelta(days=7)
    is_manager = db.query(models.EmpDet).filter(
        or_(
            func.lower(func.trim(models.EmpDet.assign_manager)) == emp_id.lower(),
            func.lower(func.trim(models.EmpDet.project_manager)) == emp_id.lower()
        )
    ).first() is not None

    if is_admin:
        try:
            pending_leaves = db.query(models.EmpLeave, models.EmpDet.name) \
                .join(models.EmpDet, models.EmpLeave.emp_id == models.EmpDet.emp_id) \
                .filter(models.EmpLeave.status == 'Pending') \
                .order_by(models.EmpLeave.creation_date.desc()).limit(5).all()
            for leave, name in pending_leaves:
                notifications.append({
                    "id": f"admin_leave_{leave.l_id}", "title": "New Leave Request",
                    "message": f"{name} applied for {leave.leave_type} ({leave.days} days)",
                    "time": leave.creation_date.strftime("%Y-%m-%d %H:%M") if leave.creation_date else "",
                    "type": "alert", "icon": "mail_id-unread-outline"
                })
        except Exception as e:
            print(f"Error fetching admin notifications: {e}")
    elif is_manager:
        try:
            pending_leaves = db.query(models.EmpLeave, models.EmpDet.name) \
                .join(models.EmpDet, models.EmpLeave.emp_id == models.EmpDet.emp_id) \
                .filter(models.EmpLeave.status == 'Pending') \
                .filter(func.lower(func.trim(models.EmpDet.assign_manager)) == emp_id.lower()) \
                .order_by(models.EmpLeave.creation_date.desc()).limit(5).all()
            for leave, name in pending_leaves:
                notifications.append({
                    "id": f"mgr_leave_{leave.l_id}", "title": "New Leave Request (Team)",
                    "message": f"{name} applied for {leave.leave_type} ({leave.days} days)",
                    "time": leave.creation_date.strftime("%Y-%m-%d %H:%M") if leave.creation_date else "",
                    "type": "alert", "icon": "mail_id-unread-outline"
                })
        except Exception as e:
            print(f"Error fetching manager notifications: {e}")

    try:
        my_leave_updates = db.query(models.EmpLeave) \
            .filter(models.EmpLeave.emp_id == emp_id) \
            .filter(models.EmpLeave.status.in_(['Approved', 'Rejected'])) \
            .filter(models.EmpLeave.last_update_date >= recent_date_limit) \
            .order_by(models.EmpLeave.last_update_date.desc()).limit(5).all()
        for leave in my_leave_updates:
            notifications.append({
                "id": f"emp_leave_{leave.l_id}", "title": f"Leave {leave.status}",
                "message": f"Your {leave.leave_type} request for {leave.from_date} was {leave.status}",
                "time": leave.last_update_date.strftime("%Y-%m-%d %H:%M") if leave.last_update_date else "",
                "type": "success" if leave.status == 'Approved' else "error",
                "icon": "checkmark-circle-outline" if leave.status == 'Approved' else "close-circle-outline"
            })
    except Exception as e:
        print(f"Error fetching employee notifications: {e}")

    return {
        "emp_name": user.name or "User",
        "domain_name": domain_name,
        "upcoming_events": upcoming_events,
        "notifications": notifications
    }


@app.get("/birthdays-this-month")
def get_birthdays_this_month(db: Session = Depends(get_db)):
    try:
        today = datetime.now()
        current_month = today.month
        current_year = today.year
        all_emps = db.query(models.EmpDet).all()
        birthdays = []
        for emp in all_emps:
            is_active = not emp.end_date or str(emp.end_date).strip() in ("", "none", "None")
            if is_active and emp.dob and emp.name:
                dob = parse_date(emp.dob)
                if dob and dob.month == current_month:
                    display_date = f"{dob.day:02d}-{dob.strftime('%b')}-{current_year}"
                    birthdays.append({"emp_id": emp.emp_id, "name": emp.name, "display_dob": display_date, "original_dob": str(emp.dob), "day": dob.day})
        birthdays.sort(key=lambda x: x["day"])
        return birthdays
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=503, detail="Database unavailable. Please try again shortly.")


@app.get("/timesheet-month/{emp_id}", response_model=List[schemas.TimesheetResponse])
def get_timesheet_month(emp_id: str, month: Optional[str] = None, year: Optional[str] = None, requester_id: Optional[str] = None, db: Session = Depends(get_db)):
    from sqlalchemy import or_, func
    clean_id = emp_id.replace(" ", "")
    
    # 1. Authorization check
    if requester_id and requester_id.strip().lower() != emp_id.strip().lower():
        req_id = requester_id.strip()
        # Check if requester is global admin or manager
        is_authorized = False
        requester = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == req_id.lower()).first()
        if requester:
            # Global Admin check
            top_domains = [1, 2, 3, 9]
            try:
                if requester.dom_id and int(str(requester.dom_id).strip()) in top_domains:
                    is_authorized = True
            except: pass
            
            if not is_authorized and requester.rpd_id:
                try:
                    r_id = int(str(requester.rpd_id).strip())
                    role_priv = db.query(models.RolePrivilege).filter(models.RolePrivilege.rpd_id == r_id).first()
                    if role_priv and role_priv.role_prv_name:
                        top_roles = ["Admin", "Management", "Executive", "Project Management"]
                        if any(tr.lower() in role_priv.role_prv_name.lower() for tr in top_roles):
                            is_authorized = True
                except: pass
            
            # Manager check
            if not is_authorized:
                target_emp = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
                if target_emp:
                    if (target_emp.assign_manager and target_emp.assign_manager.strip().lower() == req_id.lower()) or \
                       (target_emp.project_manager and target_emp.project_manager.strip().lower() == req_id.lower()):
                        is_authorized = True
        
        if not is_authorized:
             raise HTTPException(status_code=403, detail="Not authorized to view this timesheet")

    query = db.query(models.TimesheetDet).filter(
        or_(models.TimesheetDet.emp_id == emp_id, func.replace(models.TimesheetDet.emp_id, " ", "") == clean_id)
    )
    if month:
        month_map = {"January": "01", "February": "02", "March": "03", "April": "04", "May": "05", "June": "06",
                     "July": "07", "August": "08", "September": "09", "October": "10", "November": "11", "December": "12"}
        m_num = month_map.get(month)
        if m_num:
            query = query.filter(or_(models.TimesheetDet.month.ilike(f"%{month}%"), models.TimesheetDet.month.ilike(f"%{m_num}%"), models.TimesheetDet.date.ilike(f"%-{month[:3]}-%")))
        else:
            query = query.filter(models.TimesheetDet.month.ilike(f"%{month}%"))
    if year:
        query = query.filter(models.TimesheetDet.date.ilike(f"%{year}%"))
    return query.all()


@app.get("/admin/timesheet-employees")
def get_admin_timesheet_employees(month: Optional[str] = None, year: Optional[str] = None, requester_id: Optional[str] = None, db: Session = Depends(get_db)):
    # 1. Determine if requester is global admin
    is_global = False
    if requester_id:
        requester_id = requester_id.strip()
        user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == requester_id.lower()).first()
        if user:
            top_domains = [1, 2, 3, 9]
            try:
                if user.dom_id and int(str(user.dom_id).strip()) in top_domains:
                    is_global = True
            except: pass
            
            if not is_global and user.rpd_id:
                try:
                    r_id = int(str(user.rpd_id).strip())
                    role_priv = db.query(models.RolePrivilege).filter(models.RolePrivilege.rpd_id == r_id).first()
                    if role_priv and role_priv.role_prv_name:
                        top_roles = ["Admin", "Management", "Executive", "Project Management"]
                        if any(tr.lower() in role_priv.role_prv_name.lower() for tr in top_roles):
                            is_global = True
                except: pass

    # 2. Start building employee query
    emp_query = db.query(models.EmpDet).filter((models.EmpDet.end_date == None) | (models.EmpDet.end_date == ""))
    if not is_global and requester_id:
        emp_query = emp_query.filter(
            or_(
                func.lower(func.trim(models.EmpDet.assign_manager)) == requester_id.lower(),
                func.lower(func.trim(models.EmpDet.project_manager)) == requester_id.lower()
            )
        )
    
    employees = emp_query.all()
    if not employees:
        return []

    # 3. Filter by those who have timesheets in the given month/year
    emp_ids = [e.emp_id for e in employees if e.emp_id]
    
    ts_query = db.query(models.TimesheetDet.emp_id).filter(models.TimesheetDet.emp_id.in_(emp_ids))
    month_filter = None
    if month:
        month_map = {"January": "01", "February": "02", "March": "03", "April": "04", "May": "05", "June": "06",
                     "July": "07", "August": "08", "September": "09", "October": "10", "November": "11", "December": "12"}
        m_num = month_map.get(month)
        if m_num:
            month_filter = or_(models.TimesheetDet.month.ilike(f"%{month}%"), models.TimesheetDet.month.ilike(f"%{m_num}%"), models.TimesheetDet.date.ilike(f"%-{month[:3]}-%"))
        else:
            month_filter = models.TimesheetDet.month.ilike(f"%{month}%")
    if month_filter is not None:
        ts_query = ts_query.filter(month_filter)
    if year:
        ts_query = ts_query.filter(models.TimesheetDet.date.ilike(f"%{year}%"))
    
    ts_results = ts_query.distinct().all()
    matched_ids = {r.emp_id.replace(" ", "") for r in ts_results if r.emp_id}

    if not matched_ids:
        return []

    # 4. Filter employees list to those with timesheets
    final_employees = [e for e in employees if e.emp_id and e.emp_id.replace(" ", "") in matched_ids]

    # 5. Get pending counts
    pending_query = db.query(models.TimesheetDet.emp_id, func.count(models.TimesheetDet.t_id).label('pending_count')).filter(
        models.TimesheetDet.status.ilike('Pending'),
        models.TimesheetDet.emp_id.in_(list(matched_ids))
    )
    if month_filter is not None:
        pending_query = pending_query.filter(month_filter)
    if year:
        pending_query = pending_query.filter(models.TimesheetDet.date.ilike(f"%{year}%"))
    
    pending_results = pending_query.group_by(models.TimesheetDet.emp_id).all()
    pending_map = {r.emp_id.replace(" ", ""): r.pending_count for r in pending_results}

    # 6. Format results
    results = []
    for emp in final_employees:
        domain_name = "Employee"
        if emp.dom_id:
            domain = db.query(models.Domain).filter(models.Domain.dom_id == emp.dom_id).first()
            if domain:
                domain_name = domain.domain
        cid = emp.emp_id.replace(" ", "")
        results.append({
            "id": emp.emp_id, 
            "name": emp.name or "Unknown", 
            "department": domain_name, 
            "requests": pending_map.get(cid, 0)
        })
    return results


@app.get("/holidays")
def get_holidays(db: Session = Depends(get_db)):
    current_year = datetime.now().year
    try:
        holidays = db.query(models.HolidayDet).filter(models.HolidayDet.year == current_year).all()
    except Exception as e:
        handle_db_error(e)
    return [{"id": h.holiday_id, "date": h.Office_Holiday_Date, "name": h.Holiday_Name, "year": h.year, "month": h.Month} for h in holidays]


@app.post("/admin/timesheet/action")
def timesheet_action(action_req: schemas.TimesheetApprovalAction, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        ts = db.query(models.TimesheetDet).filter(models.TimesheetDet.t_id == action_req.t_id).first()
    except Exception as e:
        handle_db_error(e)
    if not ts:
        raise HTTPException(status_code=404, detail="Timesheet record not found")
    ts.status = action_req.action
    ts.approved_by = action_req.admin_id
    ts.approved_on = datetime.now()
    ts.remarks = action_req.remarks
    ts.last_update_date = datetime.now()
    ts.last_updated_by = action_req.admin_id
    db.commit()
    try:
        emp_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == ts.emp_id).first()
        if emp_user and emp_user.p_mail:
            admin_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == action_req.admin_id.strip()).first()
            manager_name = admin_user.name if admin_user else "Manager"
            subject = f"Timesheet {action_req.action.upper()} - {ts.date}"
            body = f"""<html><body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                <p>Dear {emp_user.name},</p>
                <p>Your Timesheet for <strong>{ts.date}</strong> ({ts.project or 'N/A'}) has been <strong>{action_req.action.upper()}</strong>.</p>
                <p><strong>Remarks:</strong> {action_req.remarks or 'N/A'}</p>
                <p><strong>Action By:</strong> {manager_name}</p>
                <br><p>Thanks & Regards,<br>Ilan Tech Solutions</p>
            </body></html>"""
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
    except Exception as e:
        print(f" Email_id notification failed: {e}")
    return {"message": f"Timesheet {action_req.action} successfully"}


@app.get("/admin/projects/next-ref")
def get_next_project_ref(db: Session = Depends(get_db)):
    all_refs = db.query(models.Project.project_ref_no).all()
    max_num = 0
    prefix = "ITS-PRO-"
    for (ref_no,) in all_refs:
        if ref_no and ref_no.startswith(prefix):
            try:
                match = re.search(r'(\d+)', ref_no[len(prefix):])
                if match:
                    num = int(match.group(1))
                    if num > max_num: max_num = num
            except: continue
    return {"next_ref": f"{prefix}{max_num + 1:04d}"}


@app.get("/admin/projects")
def get_projects(
    manager_id: Optional[str] = None, 
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    paginated: bool = False,
    db: Session = Depends(get_db)
):
    query = db.query(models.Project)
    
    if manager_id:
        query = query.filter(models.Project.project_manager == manager_id)
    
    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            or_(
                models.Project.project_name.ilike(search_filter),
                models.Project.project_ref_no.ilike(search_filter),
                models.Project.client_ref_no.ilike(search_filter)
            )
        )
    
    if paginated:
        total = query.count()
        data = query.order_by(models.Project.pro_id.desc()).offset(skip).limit(limit).all()
        return {"data": data, "total": total}
        
    return query.order_by(models.Project.pro_id.desc()).all()


@app.get("/admin/projects/{pro_id}", response_model=schemas.ProjectResponse)
def get_project(pro_id: int, db: Session = Depends(get_db)):
    project = db.query(models.Project).filter(models.Project.pro_id == pro_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@app.post("/admin/projects", response_model=schemas.ProjectResponse)
def create_project(project_req: schemas.ProjectCreateRequest, db: Session = Depends(get_db)):
    now = datetime.now()
    new_project = models.Project(
        project_ref_no=project_req.project_ref_no, project_name=project_req.project_name,
        project_type=project_req.project_type, team_size=project_req.team_size, budget=project_req.budget,
        start_date=project_req.start_date, end_date=project_req.end_date,
        project_manager=project_req.project_manager, status=project_req.status, duration=project_req.duration,
        description=project_req.description, client_ref_no=project_req.client_ref_no,
        attribute1=project_req.attribute1 or "", attribute2=project_req.attribute2 or "",
        attribute3=project_req.attribute3 or "", attribute4=project_req.attribute4 or "",
        attribute5=project_req.attribute5 or "", attribute6=project_req.attribute6 or "",
        attribute7=project_req.attribute7 or "", attribute8=project_req.attribute8 or "",
        attribute9=project_req.attribute9 or "", attribute10=project_req.attribute10 or "",
        attribute11=project_req.attribute11 or "", attribute12=project_req.attribute12 or "",
        attribute13=project_req.attribute13 or "", attribute14=project_req.attribute14 or "",
        attribute15=project_req.attribute15 or "", creation_date=now, dom_id=project_req.dom_id,
        last_update_date=now, created_by=project_req.created_by,
        last_updated_by=project_req.created_by or "Admin", last_update_login=project_req.created_by or "Admin",
        files=project_req.files, project_priority=project_req.project_priority
    )
    db.add(new_project)
    db.commit()
    db.refresh(new_project)
    return new_project


@app.put("/admin/projects/{pro_id}", response_model=schemas.ProjectResponse)
def update_project(pro_id: int, project_req: schemas.ProjectCreateRequest, db: Session = Depends(get_db)):
    now = datetime.now()
    project = db.query(models.Project).filter(models.Project.pro_id == pro_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project.project_ref_no = project_req.project_ref_no
    project.project_name = project_req.project_name
    project.project_type = project_req.project_type
    project.team_size = project_req.team_size
    project.budget = project_req.budget
    project.start_date = project_req.start_date
    project.end_date = project_req.end_date
    project.project_manager = project_req.project_manager
    project.status = project_req.status
    project.duration = project_req.duration
    project.description = project_req.description
    project.client_ref_no = project_req.client_ref_no
    for i in range(1, 16):
        setattr(project, f"attribute{i}", getattr(project_req, f"attribute{i}", None))
    project.dom_id = project_req.dom_id
    project.last_update_date = now
    project.last_updated_by = project_req.created_by or "Admin"
    project.last_update_login = project_req.created_by or "Admin"
    project.files = project_req.files
    project.project_priority = project_req.project_priority
    db.commit()
    db.refresh(project)
    return project


@app.get("/ot-stats/{emp_id}")
def get_ot_stats(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    try:
        ot_records = db.query(models.OverTimeDet).filter(
            func.lower(func.trim(models.OverTimeDet.emp_id)) == emp_id.lower()).all()
    except Exception as e:
        handle_db_error(e)
    total_ot = 0.0
    approved_ot = 0.0

    def parse_duration(duration_str):
        if not duration_str: return 0.0
        duration_str = str(duration_str).strip()
        try: return float(duration_str)
        except ValueError: pass
        hr_match = re.search(r'(\d+)\s*(h|hr)', duration_str, re.IGNORECASE)
        min_match = re.search(r'(\d+)\s*(m|min)', duration_str, re.IGNORECASE)
        if hr_match or min_match:
            hours = float(hr_match.group(1)) if hr_match else 0.0
            minutes = float(min_match.group(1)) if min_match else 0.0
            return hours + (minutes / 60.0)
        if ':' in duration_str:
            parts = duration_str.split(':')
            if len(parts) == 2:
                try: return float(parts[0]) + float(parts[1]) / 60.0
                except: pass
        return 0.0

    for row in ot_records:
        try:
            d = parse_duration(row.duration or "0")
            total_ot += d
            if row.status and row.status.lower() == 'approved':
                approved_ot += d
        except Exception:
            continue
    return {"total": round(total_ot, 2), "approved": round(approved_ot, 2)}


@app.get("/ot-history/{emp_id}")
def get_ot_history(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    try:
        return db.query(models.OverTimeDet).filter(
            func.lower(func.trim(models.OverTimeDet.emp_id)) == emp_id.lower()
        ).order_by(models.OverTimeDet.ot_id.desc()).all()
    except Exception as e:
        handle_db_error(e)


@app.get("/admin/roles", response_model=List[schemas.RoleResponse])
def get_roles(db: Session = Depends(get_db)):
    return db.query(models.Role).all()


@app.get("/admin/departments", response_model=List[schemas.DepartmentResponse])
def get_departments(dpt_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.Department)
    if dpt_id:
        ids = [int(i.strip()) for i in dpt_id.split(",") if i.strip().isdigit()]
        query = query.filter(models.Department.dpt_id.in_(ids))
    return query.all()


@app.get("/admin/domains", response_model=List[schemas.DomainResponse])
def get_domains(dom_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.Domain)
    if dom_id:
        ids = [int(i.strip()) for i in dom_id.split(",") if i.strip().isdigit()]
        query = query.filter(models.Domain.dom_id.in_(ids))
    return query.all()


@app.get("/admin/employees/brief", response_model=List[schemas.EmployeeBriefResponse])
def get_employees_brief(db: Session = Depends(get_db)):
    employees = db.query(models.EmpDet.emp_id, models.EmpDet.name, models.EmpDet.role_id, models.EmpDet.dpt_id, models.EmpDet.dom_id).all()
    return [{"emp_id": e.emp_id, "name": e.name, "role_id": e.role_id, "dpt_id": e.dpt_id, "dom_id": e.dom_id} for e in employees]


@app.get("/admin/projects/{pro_id}/allocations", response_model=List[schemas.ProjectAllocationResponse])
def get_project_allocations(pro_id: int, db: Session = Depends(get_db)):
    allocs = db.query(models.ProjectAllocation).filter(models.ProjectAllocation.pro_id == pro_id).all()
    res = []
    for a in allocs:
        emp = db.query(models.EmpDet.name).filter(models.EmpDet.emp_id == a.emp_id).first()
        role = db.query(models.Role.role).filter(models.Role.role_id == a.role_id).first()
        dept = db.query(models.Department.department).filter(models.Department.dpt_id == a.dpt_id).first()
        dom = db.query(models.Domain.domain).filter(models.Domain.dom_id == a.dom_id).first()
        res.append(schemas.ProjectAllocationResponse(
            assign_id=a.assign_id, emp_id=a.emp_id, role_id=a.role_id, dom_id=a.dom_id, dpt_id=a.dpt_id,
            lead_id=a.lead_id, from_date=a.from_date, to_date=a.to_date, task_description=a.task_description,
            allocation_pct=a.allocation_pct, emp_name=emp[0] if emp else "Unknown",
            role_name=role[0] if role else "Unknown", dept_name=dept[0] if dept else "Unknown",
            dom_name=dom[0] if dom else "Unknown"
        ))
    return res


@app.post("/admin/projects/{pro_id}/allocations", response_model=schemas.ProjectAllocationResponse)
def create_project_allocation(pro_id: int, alloc_req: schemas.ProjectAllocationCreate, db: Session = Depends(get_db)):
    now = datetime.now()
    new_alloc = models.ProjectAllocation(
        pro_id=pro_id, emp_id=alloc_req.emp_id, role_id=alloc_req.role_id, dom_id=alloc_req.dom_id,
        dpt_id=alloc_req.dpt_id, lead_id=alloc_req.lead_id, from_date=alloc_req.from_date, to_date=alloc_req.to_date,
        task_description=alloc_req.task_description, allocation_pct=alloc_req.allocation_pct,
        created_by=alloc_req.created_by, creation_date=now,
        last_updated_by=alloc_req.created_by or "Admin", last_update_date=now
    )
    db.add(new_alloc)
    db.commit()
    db.refresh(new_alloc)
    return new_alloc


@app.get("/admin/allocations", response_model=List[schemas.ProjectAllocationResponse])
def get_all_allocations(db: Session = Depends(get_db)):
    allocs = db.query(models.ProjectAllocation).all()
    res = []
    for a in allocs:
        emp = db.query(models.EmpDet.name).filter(models.EmpDet.emp_id == a.emp_id).first()
        role = db.query(models.Role.role).filter(models.Role.role_id == a.role_id).first()
        dept = db.query(models.Department.department).filter(models.Department.dpt_id == a.dpt_id).first()
        dom = db.query(models.Domain.domain).filter(models.Domain.dom_id == a.dom_id).first()
        proj = db.query(models.Project.project_name).filter(models.Project.pro_id == a.pro_id).first()
        res.append(schemas.ProjectAllocationResponse(
            assign_id=a.assign_id, emp_id=a.emp_id, role_id=a.role_id, dom_id=a.dom_id, dpt_id=a.dpt_id,
            lead_id=a.lead_id, from_date=a.from_date, to_date=a.to_date, task_description=a.task_description,
            allocation_pct=a.allocation_pct, emp_name=emp[0] if emp else "Unknown",
            role_name=role[0] if role else "Unknown", dept_name=dept[0] if dept else "Unknown",
            dom_name=dom[0] if dom else "Unknown", project_name=proj[0] if proj else "Unknown"
        ))
    return res


@app.get("/admin/employees/{emp_id}/allocations", response_model=List[schemas.ProjectAllocationResponse])
def get_employee_allocations(emp_id: str, db: Session = Depends(get_db)):
    allocs = db.query(models.ProjectAllocation).filter(models.ProjectAllocation.emp_id == emp_id).all()
    res = []
    for a in allocs:
        emp = db.query(models.EmpDet.name).filter(models.EmpDet.emp_id == a.emp_id).first()
        role = db.query(models.Role.role).filter(models.Role.role_id == a.role_id).first()
        dept = db.query(models.Department.department).filter(models.Department.dpt_id == a.dpt_id).first()
        dom = db.query(models.Domain.domain).filter(models.Domain.dom_id == a.dom_id).first()
        proj = db.query(models.Project.project_name).filter(models.Project.pro_id == a.pro_id).first()
        res.append(schemas.ProjectAllocationResponse(
            assign_id=a.assign_id, emp_id=a.emp_id, role_id=a.role_id, dom_id=a.dom_id, dpt_id=a.dpt_id,
            lead_id=a.lead_id, from_date=a.from_date, to_date=a.to_date, task_description=a.task_description,
            allocation_pct=a.allocation_pct, emp_name=emp[0] if emp else "Unknown",
            role_name=role[0] if role else "Unknown", dept_name=dept[0] if dept else "Unknown",
            dom_name=dom[0] if dom else "Unknown", project_name=proj[0] if proj else "Unknown"
        ))
    return res


@app.get("/admin/clients/next-ref")
def get_next_client_ref(db: Session = Depends(get_db)):
    clients = db.query(models.CompanyClient).filter(
        models.CompanyClient.client_ref_no.like('ITS-CLI-%')
    ).all()
    max_num = 25
    for c in clients:
        if c.client_ref_no:
            match = re.search(r'ITS-CLI-(\d+)$', c.client_ref_no)
            if match:
                num = int(match.group(1))
                if num > max_num: max_num = num
    return {"next_ref": f"ITS-CLI-{max_num + 1:04d}"}


@app.get("/admin/clients")
def get_clients(
    manager_id: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    try:
        query = db.query(models.CompanyClient)
        
        if manager_id:
            # Filtering clients by creator if restricted to own view
            query = query.filter(models.CompanyClient.created_by == manager_id)
            
        if search:
            search_filter = f"%{search}%"
            query = query.filter(
                or_(
                    models.CompanyClient.client_name.ilike(search_filter),
                    models.CompanyClient.client_ref_no.ilike(search_filter),
                    models.CompanyClient.company_name.ilike(search_filter)
                )
            )
            
        clients = query.order_by(models.CompanyClient.cl_id.desc()).all()
    except Exception as e:
        raise HTTPException(status_code=503, detail="Database unavailable. Please try again shortly.")
    res = []
    for c in clients:
        subs = db.query(models.SubClient).filter(models.SubClient.client_ref_no == c.client_ref_no).all()
        sites_list = [schemas.SubClientSchema(
            sub_cl_id=s.sub_cl_id, sub_client_name=s.sub_client_name, client_ref_no=s.client_ref_no,
            sub_gst_no=s.sub_gst_no, sub_msme_no=s.sub_msme_no, sub_pan=s.sub_pan, sub_tds_p=s.sub_tds_p,
            sub_gst_p=s.sub_gst_p, sub_short_code=s.sub_short_code, sub_location=s.sub_location,
            ship_to=s.ship_to, currency=s.currency, status=s.status
        ) for s in subs]
        creation_dt = safe_dt(c.creation_date)
        last_update_dt = safe_dt(c.last_update_date)
        res.append({
            "client_id": c.cl_id, "client_ref_no": c.client_ref_no, "client_name": c.client_name,
            "mobile_no": c.mobile_no, "country_code": c.country_code, "email_id": c.email,
            "gst_available": c.gst, "gst": c.gst_no, "msme_available": c.msme, "msme": c.msme_no,
            "pan_no": c.pan, "address": c.address, "status": c.status or "Active",
            "company_name": c.company_name, "website": c.website, "short_code": c.short_code,
            "currency": c.currency, "gst_value": c.gst_value, "attribute_category": c.attribute_category,
            "creation_date": creation_dt, "last_update_date": last_update_dt,
            "created_by": c.created_by, "last_updated_by": c.last_updated_by,
            "last_update_login": c.last_update_login,
            "attribute1": c.attribute1, "attribute2": c.attribute2, "attribute3": c.attribute3,
            "attribute4": c.attribute4, "attribute5": c.attribute5, "attribute6": c.attribute6,
            "attribute7": c.attribute7, "attribute8": c.attribute8, "attribute9": c.attribute9,
            "attribute10": c.attribute10, "attribute11": c.attribute11, "attribute12": c.attribute12,
            "attribute13": c.attribute13, "attribute14": c.attribute14, "sites": sites_list
        })
    return res


@app.get("/admin/clients/{client_id}", response_model=schemas.ClientResponse)
def get_client(client_id: int, db: Session = Depends(get_db)):
    client = db.query(models.CompanyClient).filter(models.CompanyClient.cl_id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    subs = db.query(models.SubClient).filter(models.SubClient.client_ref_no == client.client_ref_no).all()
    sites_list = [schemas.SubClientSchema(
        sub_cl_id=s.sub_cl_id, sub_client_name=s.sub_client_name, client_ref_no=s.client_ref_no,
        sub_gst_no=s.sub_gst_no, sub_msme_no=s.sub_msme_no, sub_pan=s.sub_pan, sub_tds_p=s.sub_tds_p,
        sub_gst_p=s.sub_gst_p, sub_short_code=s.sub_short_code, sub_location=s.sub_location,
        ship_to=s.ship_to, currency=s.currency, status=s.status
    ) for s in subs]
    creation_dt = safe_dt(client.creation_date)
    last_update_dt = safe_dt(client.last_update_date)
    return {
        "client_id": client.cl_id, "client_ref_no": client.client_ref_no, "client_name": client.client_name,
        "company_name": client.company_name, "mobile_no": client.mobile_no, "email_id": client.email,
        "gst_available": client.gst, "gst": client.gst_no, "msme_available": client.msme,
        "msme": client.msme_no, "pan_no": client.pan, "status": client.status or "Active",
        "website": client.website, "short_code": client.short_code, "currency": client.currency,
        "address": client.address, "sites": sites_list, "creation_date": creation_dt, "last_update_date": last_update_dt
    }


@app.put("/admin/update-client/{client_id}")
def update_client(client_id: int, client_req: schemas.ClientApplyRequest, db: Session = Depends(get_db)):
    client = db.query(models.CompanyClient).filter(models.CompanyClient.cl_id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    now = datetime.now()
    client.client_name = client_req.client_name
    client.company_name = client_req.company_name
    client.mobile_no = client_req.mobile_no
    client.email = client_req.email_id
    client.gst = client_req.gst_available
    client.gst_no = client_req.gst
    client.msme = client_req.msme_available
    client.msme_no = client_req.msme
    client.pan = client_req.pan_no
    client.website = client_req.website
    client.short_code = client_req.short_code
    client.currency = client_req.currency
    client.address = client_req.address
    client.status = client_req.status
    client.last_update_date = now
    if client_req.sites is not None:
        db.query(models.SubClient).filter(models.SubClient.client_ref_no == client.client_ref_no).delete()
        for s in client_req.sites:
            db.add(models.SubClient(
                sub_client_name=s.sub_client_name, client_ref_no=client.client_ref_no,
                sub_gst_no=s.sub_gst_no or "", sub_msme_no=s.sub_msme_no or "", sub_pan=s.sub_pan or "",
                sub_tds_p=s.sub_tds_p or 0, sub_gst_p=s.sub_gst_p or "", sub_short_code=s.sub_short_code or "",
                sub_location=s.sub_location or "", ship_to=s.ship_to or "", currency=s.currency or "INR",
                status=s.status or "Active", creation_date=now, last_update_date=now,
                created_by="Admin", last_updated_by="Admin", last_update_login="Admin"
            ))
    db.commit()
    return {"message": "Client updated successfully"}


@app.get("/holiday-dates")
def get_holiday_dates(db: Session = Depends(get_db)):
    try:
        holidays = db.query(models.HolidayDet.Office_Holiday_Date).all()
    except Exception as e:
        raise HTTPException(status_code=503, detail="Database unavailable. Please try again shortly.")
    return [h[0] for h in holidays if h[0]]


@app.post("/admin/create-client")
def create_client(client_req: schemas.ClientApplyRequest, db: Session = Depends(get_db)):
    now = datetime.now()
    if not client_req.client_ref_no or client_req.client_ref_no.strip() == "":
        last_client = db.query(models.CompanyClient).order_by(models.CompanyClient.cl_id.desc()).first()
        if not last_client or not last_client.client_ref_no:
            client_req.client_ref_no = "CLI-001"
        else:
            ref_no = last_client.client_ref_no
            match = re.search(r'(\d+)$', ref_no)
            if match:
                num = int(match.group(1)) + 1
                prefix = ref_no[:match.start()]
                client_req.client_ref_no = f"{prefix}{num:03d}"
            else:
                client_req.client_ref_no = f"{ref_no}-1"
    try:
        new_client = models.CompanyClient(
            client_ref_no=client_req.client_ref_no, client_name=client_req.client_name,
            company_name=client_req.company_name, country_code="",
            mobile_no=client_req.mobile_no or "", gst=client_req.gst_available or "No",
            gst_value="", gst_no=client_req.gst or "", website=client_req.website or "",
            email=client_req.email_id or "", msme=client_req.msme_available or "No",
            msme_no=client_req.msme or "", pan=client_req.pan_no or "",
            short_code=client_req.short_code or "", currency=client_req.currency or "INR",
            address=client_req.address or "", status=client_req.status or "Active",
            attribute_category="",
            attribute1="", attribute2="", attribute3="", attribute4="", attribute5="",
            attribute6="", attribute7="", attribute8="", attribute9="", attribute10="",
            attribute11="", attribute12="", attribute13="", attribute14="",
            creation_date=now, last_update_date=now,
            created_by="Admin", last_updated_by="Admin", last_update_login="Admin"
        )
        db.add(new_client)
        db.flush()
        if client_req.sites:
            for sub_req in client_req.sites:
                new_sub = models.SubClient(
                    sub_client_name=sub_req.sub_client_name, client_ref_no=new_client.client_ref_no,
                    sub_gst_no=sub_req.sub_gst_no or "", sub_msme_no=sub_req.sub_msme_no or "",
                    sub_pan=sub_req.sub_pan or "", sub_tds_p=sub_req.sub_tds_p or 0,
                    sub_gst_p=sub_req.sub_gst_p or "", sub_short_code=sub_req.sub_short_code or "",
                    sub_location=sub_req.sub_location or "", ship_to=sub_req.ship_to or "",
                    currency=sub_req.currency or "INR", status=sub_req.status or "Active",
                    creation_date=now, last_update_date=now,
                    created_by="Admin", last_updated_by="Admin", last_update_login="Admin"
                )
                db.add(new_sub)
        db.commit()
        db.refresh(new_client)
        return {"message": "Client and sub-clients created successfully", "client_id": new_client.cl_id}
    except Exception as e:
        db.rollback()
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/attendance-report/{emp_id}")
def get_attendance_report(emp_id: str, start_date: str, end_date: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    try:
        start_dt = parse_date(start_date)
        end_dt = parse_date(end_date)
        if not start_dt or not end_dt:
            raise HTTPException(status_code=400, detail="Invalid date format")
    except:
        raise HTTPException(status_code=400, detail="Invalid date format")
    try:
        emp = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
        if not emp:
            raise HTTPException(status_code=404, detail="Employee not found")
        attendance_reports = db.query(models.DailyAttendanceReport).filter(
            models.DailyAttendanceReport.Employee_Code == emp.emp_id,
            models.DailyAttendanceReport.Date >= start_date,
            models.DailyAttendanceReport.Date <= end_date
        ).all()
        checkin_data = db.query(models.CheckIn).filter(
            func.lower(func.trim(models.CheckIn.emp_id)) == emp_id.lower(),
            models.CheckIn.t_date >= start_dt.date(), models.CheckIn.t_date <= end_dt.date()
        ).all()
        bms_data = db.query(models.BMS).filter(
            func.lower(func.trim(models.BMS.emp_id)) == emp_id.lower(),
            models.BMS.attendance_date >= start_dt.date(), models.BMS.attendance_date <= end_dt.date()
        ).all()
        result = []
        checkin_map = {str(checkin.t_date): checkin for checkin in checkin_data}
        bms_map = {str(bms.attendance_date): bms for bms in bms_data}
        for report in attendance_reports:
            report_date = report.Date
            checkin = checkin_map.get(report_date)
            bms = bms_map.get(report_date)
            min_in = bms.min_in if bms else None
            max_out = bms.max_out if bms else None
            if not min_in and checkin: min_in = checkin.in_time
            if not max_out and checkin: max_out = checkin.out_time
            result.append({
                "date": report_date, "employee_code": report.Employee_Code,
                "employee_name": report.Employee_Name, "company": report.Company,
                "department": report.Department, "category": report.Category,
                "designation": report.Degination, "grade": report.Grade,
                "team": report.Team, "shift": report.Shift,
                "in_time": report.In_Time, "out_time": report.Out_Time,
                "duration": report.Duration, "late_by": report.Late_By,
                "early_by": report.Early_By, "status": report.Status,
                "punch_records": report.Punch_Records, "overtime": report.Overtime,
                "min_in": min_in, "max_out": max_out,
                "checkin_in_time": checkin.in_time if checkin else None,
                "checkin_out_time": checkin.out_time if checkin else None,
                "checkin_total_hours": checkin.Total_hours if checkin else None,
                "checkin_status": checkin.status if checkin else None
            })
        return {
            "employee": {"emp_id": emp.emp_id, "name": emp.name, "department": emp.dpt_id, "designation": emp.role_type},
            "attendance_data": result,
            "summary": {
                "total_days": len(result),
                "present": len([r for r in result if r["status"] == "P"]),
                "absent": len([r for r in result if r["status"] == "A"]),
                "late": len([r for r in result if r["late_by"] and r["late_by"] != ""]),
                "early": len([r for r in result if r["early_by"] and r["early_by"] != ""])
            }
        }
    except Exception as e:
        handle_db_error(e)


@app.get("/attendance-summary/{emp_id}")
def get_attendance_summary(emp_id: str, month: int, year: int, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    try:
        emp = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
        if not emp:
            raise HTTPException(status_code=404, detail="Employee not found")
        attendance_reports = db.query(models.DailyAttendanceReport).filter(
            models.DailyAttendanceReport.Employee_Code == emp.emp_id,
            extract('month', func.str_to_date(models.DailyAttendanceReport.Date, '%d-%b-%Y')) == month,
            extract('year', func.str_to_date(models.DailyAttendanceReport.Date, '%d-%b-%Y')) == year
        ).all()
        checkin_data = db.query(models.CheckIn).filter(
            func.lower(func.trim(models.CheckIn.emp_id)) == emp_id.lower(),
            extract('month', models.CheckIn.t_date) == month,
            extract('year', models.CheckIn.t_date) == year
        ).all()
        bms_data = db.query(models.BMS).filter(
            func.lower(func.trim(models.BMS.emp_id)) == emp_id.lower(),
            extract('month', models.BMS.attendance_date) == month,
            extract('year', models.BMS.attendance_date) == year
        ).all()
        total_days = len(attendance_reports)
        present = len([r for r in attendance_reports if r.Status == "P"])
        absent = len([r for r in attendance_reports if r.Status == "A"])
        late = len([r for r in attendance_reports if r.Late_By and r.Late_By != ""])
        early = len([r for r in attendance_reports if r.Early_By and r.Early_By != ""])
        total_overtime = 0
        for checkin in checkin_data:
            if checkin.Total_hours and "Hr" in checkin.Total_hours:
                try:
                    hours = int(checkin.Total_hours.split("Hr")[0].strip())
                    if hours > 8: total_overtime += (hours - 8)
                except: pass
        return {
            "employee": {"emp_id": emp.emp_id, "name": emp.name, "department": emp.dpt_id, "designation": emp.role_type},
            "month": month, "year": year,
            "summary": {
                "total_days": total_days, "present": present, "absent": absent, "late": late, "early": early,
                "attendance_percentage": round((present / total_days * 100) if total_days > 0 else 0, 2),
                "total_overtime_hours": total_overtime
            },
            "data_sources": {"daily_attendance_reports": len(attendance_reports), "checkin_records": len(checkin_data), "bms_records": len(bms_data)}
        }
    except Exception as e:
        handle_db_error(e)


@app.get("/team-attendance/{requester_id}")
def get_team_attendance(requester_id: str, start_date: str, end_date: str, db: Session = Depends(get_db)):
    requester_id = requester_id.strip()
    try:
        start_dt = parse_date(start_date)
        end_dt = parse_date(end_date)
        if not start_dt or not end_dt:
            raise HTTPException(status_code=400, detail="Invalid date format")
    except:
        raise HTTPException(status_code=400, detail="Invalid date format")
    
    try:
        # Check if requester is global admin
        user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == requester_id.lower()).first()
        is_global = False
        if user:
            top_domains = [1, 2, 3, 9]
            try:
                if user.dom_id and int(str(user.dom_id).strip()) in top_domains:
                    is_global = True
            except: pass
            
            # Also check role name for "Admin" etc.
            if not is_global and user.rpd_id:
                try:
                    r_id = int(str(user.rpd_id).strip())
                    role_priv = db.query(models.RolePrivilege).filter(models.RolePrivilege.rpd_id == r_id).first()
                    if role_priv and role_priv.role_prv_name:
                        top_roles = ["Admin", "Management", "Executive", "Project Management"]
                        if any(tr.lower() in role_priv.role_prv_name.lower() for tr in top_roles):
                            is_global = True
                except: pass

        # Fetch employees
        query = db.query(models.EmpDet).filter((models.EmpDet.end_date == None) | (models.EmpDet.end_date == ""))
        if not is_global:
            query = query.filter(
                or_(
                    func.lower(func.trim(models.EmpDet.assign_manager)) == requester_id.lower(),
                    func.lower(func.trim(models.EmpDet.project_manager)) == requester_id.lower()
                )
            )
        employees = query.all()
        
        if not employees:
            return {"message": "No employees found", "team_attendance": []}
            
        team_attendance = []
        for emp in employees:
            attendance_reports = db.query(models.DailyAttendanceReport).filter(
                models.DailyAttendanceReport.Employee_Code == emp.emp_id,
                models.DailyAttendanceReport.Date >= start_date,
                models.DailyAttendanceReport.Date <= end_date
            ).all()
            
            present = len([r for r in attendance_reports if r.Status == "P"])
            absent = len([r for r in attendance_reports if r.Status == "A"])
            total_days = len(attendance_reports)
            
            team_attendance.append({
                "emp_id": emp.emp_id, 
                "name": emp.name or "Unknown", 
                "department": emp.dpt_id or "N/A",
                "designation": emp.role_type or "Employee", 
                "total_days": total_days, 
                "present": present, 
                "absent": absent,
                "attendance_percentage": round((present / total_days * 100) if total_days > 0 else 0, 2)
            })
            
        return {
            "requester_id": requester_id,
            "is_global_view": is_global,
            "period": {"start_date": start_date, "end_date": end_date},
            "team_size": len(employees),
            "team_attendance": team_attendance
        }
    except Exception as e:
        handle_db_error(e)


@app.get("/module-privileges/{user_id}")
def get_module_privileges(user_id: str, db: Session = Depends(get_db)):
    """Get module privileges for a user with proper privilege mapping"""
    try:
        # Get user privileges
        user = db.query(models.User).filter(models.User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Module IDs and their corresponding privilege arrays
        mod_id = [1, 2, 3, 4, 11, 12, 13, 14, 15, 16, 17, 33, 54, 57]
        
        # Initialize privilege arrays (0 = no privilege, actual number = has privilege)
        create_prv = [0] * len(mod_id)
        read_prv = [0] * len(mod_id)
        update_prv = [0] * len(mod_id)
        delete_prv = [0] * len(mod_id)
        view_prv = [0] * len(mod_id)
        
        # Get user's actual privileges from database
        user_privileges = db.query(models.UserPrivilege).filter(
            models.UserPrivilege.user_id == user_id
        ).all()
        
        # Map privileges to arrays
        for priv in user_privileges:
            try:
                mod_index = mod_id.index(priv.mod_id)
                create_prv[mod_index] = 1 if priv.create_prv else 0
                read_prv[mod_index] = 2 if priv.read_prv else 0
                update_prv[mod_index] = 3 if priv.update_prv else 0
                delete_prv[mod_index] = 4 if priv.delete_prv else 0
                view_prv[mod_index] = 5 if priv.view_prv else 0
            except ValueError:
                continue  # Skip if module ID not in our list
        
        # Build result array
        result = []
        for i in range(len(mod_id)):
            data = {
                "mod_id": mod_id[i],
                "create": create_prv[i],
                "read": read_prv[i],
                "update": update_prv[i],
                "delete": delete_prv[i],
                "view": view_prv[i]
            }
            result.append(data)
        
        return {
            "user_id": user_id,
            "privileges": result,
            "total_modules": len(result)
        }
        
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/filtered-data/{user_id}")
def get_filtered_data_by_modules(user_id: str, db: Session = Depends(get_db)):
    """Get data filtered by user's module privileges"""
    try:
        # Get user's module privileges
        privileges_response = get_module_privileges(user_id, db)
        privileges = privileges_response["privileges"]
        
        # Helper function to check if user has access to a module
        def has_module_access(mod_id: int) -> bool:
            for priv in privileges:
                if priv["mod_id"] == mod_id:
                    return (priv["create"] > 0 or priv["read"] > 0 or 
                           priv["update"] > 0 or priv["delete"] > 0 or priv["view"] > 0)
            return False
        
        # Helper function to check specific privilege
        def has_privilege(mod_id: int, privilege_type: str) -> bool:
            for priv in privileges:
                if priv["mod_id"] == mod_id:
                    return priv.get(privilege_type, 0) > 0
            return False
        
        filtered_data = {
            "user_id": user_id,
            "accessible_modules": [],
            "data": {}
        }
        
        # Check each module and add data if user has access
        module_mapping = {
            1: "attendance",
            2: "leave", 
            3: "timesheet",
            4: "permission",
            11: "employee",
            12: "leave_admin",
            13: "timesheet_admin", 
            14: "permission_admin",
            15: "attendance_admin",
            16: "client",
            17: "project",
            33: "overtime",
            54: "wfh_admin",
            57: "wfh"
        }
        
        for mod_id, module_name in module_mapping.items():
            if has_module_access(mod_id):
                filtered_data["accessible_modules"].append({
                    "mod_id": mod_id,
                    "module_name": module_name,
                    "can_create": has_privilege(mod_id, "create"),
                    "can_read": has_privilege(mod_id, "read"),
                    "can_update": has_privilege(mod_id, "update"),
                    "can_delete": has_privilege(mod_id, "delete"),
                    "can_view": has_privilege(mod_id, "view")
                })
                
                # Add specific data based on module
                if module_name == "attendance" and has_privilege(mod_id, "read"):
                    # Get user's attendance data
                    attendance_data = db.query(models.CheckIn).filter(
                        models.CheckIn.emp_id == user_id
                    ).limit(10).all()
                    filtered_data["data"]["attendance"] = [
                        {
                            "date": str(record.t_date),
                            "in_time": record.in_time,
                            "out_time": record.out_time,
                            "total_hours": record.Total_hours,
                            "status": record.status
                        } for record in attendance_data
                    ]
                
                elif module_name == "leave" and has_privilege(mod_id, "read"):
                    # Get user's leave data
                    leave_data = db.query(models.LeaveRequest).filter(
                        models.LeaveRequest.emp_id == user_id
                    ).limit(10).all()
                    filtered_data["data"]["leave"] = [
                        {
                            "leave_id": record.l_id,
                            "leave_type": record.leave_type,
                            "from_date": record.from_date,
                            "to_date": record.to_date,
                            "days": record.days,
                            "status": record.status,
                            "reason": record.reason
                        } for record in leave_data
                    ]
                
                elif module_name == "permission" and has_privilege(mod_id, "read"):
                    # Get user's permission data
                    permission_data = db.query(models.PermissionRequest).filter(
                        models.PermissionRequest.emp_id == user_id
                    ).limit(10).all()
                    filtered_data["data"]["permission"] = [
                        {
                            "permission_id": record.p_id,
                            "date": record.date,
                            "from_time": record.f_time,
                            "to_time": record.t_time,
                            "total_hours": record.total_hours,
                            "status": record.status,
                            "reason": record.reason
                        } for record in permission_data
                    ]
        
        return filtered_data
        
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=str(e))


app.include_router(router)
