from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, case
from datetime import datetime, timedelta, date
from typing import List, Optional
import shutil
import os
import requests
import random
import string
import hashlib
import base64
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

import models, schemas, database
from database import engine, SessionLocal


# Create tables if they don't exist
models.Base.metadata.create_all(bind=engine)


# Proactive Migration for WFH table
def migrate_wfh_table():
    from sqlalchemy import text
    db = SessionLocal()
    try:
        try:
            db.execute(text("SELECT to_date FROM xxits_aruvi_wfh_det_t LIMIT 1"))
        except Exception:
            print(" Migration: Adding to_date to xxits_aruvi_wfh_det_t")
            db.execute(text("ALTER TABLE xxits_aruvi_wfh_det_t ADD COLUMN to_date VARCHAR(20)"))
            db.commit()

        try:
            db.execute(text("SELECT days FROM xxits_aruvi_wfh_det_t LIMIT 1"))
        except Exception:
            print(" Migration: Adding days to xxits_aruvi_wfh_det_t")
            db.execute(text("ALTER TABLE xxits_aruvi_wfh_det_t ADD COLUMN days VARCHAR(15)"))
            db.commit()
    except Exception as e:
        print(f" Migration Error: {e}")
    finally:
        db.close()


migrate_wfh_table()
 
 
def migrate_revision_column():
    from sqlalchemy import text
    db = SessionLocal()
    try:
        try:
            db.execute(text("SELECT revision FROM xxits_aruvi_emp_leave_t LIMIT 1"))
        except Exception:
            print(" Migration: Adding revision to xxits_aruvi_emp_leave_t")
            db.execute(text("ALTER TABLE xxits_aruvi_emp_leave_t ADD COLUMN revision VARCHAR(240)"))
            db.commit()
        # Always ensure NULLs are converted to '0'
        db.execute(text("UPDATE xxits_aruvi_emp_leave_t SET revision = '0' WHERE revision IS NULL OR revision = ''"))
        db.commit()
    except Exception as e:
        print(f" Migration Error (Revision): {e}")
    finally:
        db.close()

migrate_revision_column()

# In-memory OTP storage
otp_store = {}

app = FastAPI()

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


def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
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


# FIX: Added missing parse_time_str function
def parse_time_str(t_str: str):
    """Parse time string into a datetime object (date part set to 1900-01-01)"""
    if not t_str: return None
    t_str = t_str.strip().upper()
    formats = (
        "%I:%M:%S %p", "%I:%M %p", 
        "%I:%M %p", "%I:%M%p",
        "%H:%M:%S", "%H:%M",
        "%H:%M %p"
    )
    for fmt in formats:
        try:
            return datetime.strptime(t_str, fmt).replace(year=1900, month=1, day=1)
        except:
            continue
    # Last ditch effort: regex for simple extraction
    import re
    match = re.search(r"(\d{1,2})[:.](\d{2})(?::(\d{2}))?\s*([AP]M)?", t_str)
    if match:
        h, m, s, p = match.groups()
        h, m = int(h), int(m)
        s = int(s) if s else 0
        if p == "PM" and h < 12: h += 12
        if p == "AM" and h == 12: h = 0
        return datetime(1900, 1, 1, h, m, s)
    return None


def format_time_safe(t):
    if not t: return ""
    if isinstance(t, str): return t
    if hasattr(t, "strftime"): return t.strftime("%H:%M")
    return str(t)


@app.post("/login", response_model=schemas.Token)
def login(request: schemas.LoginRequest, db: Session = Depends(get_db)):
    print("\n" + "=" * 60)
    print(" LOGIN ATTEMPT (DEBUG MODE)")
    print("=" * 60)

    username_input = request.username.strip().lower()
    input_pwd = request.password.strip()
    print(f" Username input: {username_input}")
    user = db.query(models.EmpDet).filter(
        or_(
            func.lower(func.trim(models.EmpDet.p_mail)) == username_input,
            func.lower(func.trim(models.EmpDet.mail)) == username_input,
            func.lower(func.trim(models.EmpDet.emp_id)) == username_input,
            func.lower(func.replace(func.trim(models.EmpDet.emp_id), " ", "")) == username_input.replace(" ", "")
        )
    ).first()

    if not user:
        print(f" User not found for input: {username_input}")
        raise HTTPException(status_code=404, detail="Invalid Username")

    print(f" User FOUND: {user.emp_id} ({user.p_mail})")

    input_md5 = hashlib.md5(input_pwd.encode()).hexdigest()
    print("\n PASSWORD DEBUG")
    print("Input password:", input_pwd)
    print("Input MD5:", input_md5)
    print("DB attribute15:", user.attribute15)
    print("DB password column:", user.password)

    password_valid = False
    if user.attribute15 and user.attribute15.lower() == input_md5.lower():
        print(" Match via attribute15 MD5")
        password_valid = True
    if not password_valid and user.password and user.password.lower() == input_md5.lower():
        print(" Match via password column MD5")
        password_valid = True
    if not password_valid and user.password == input_pwd:
        print(" Match via PLAINTEXT password")
        password_valid = True
    if not password_valid and user.password and user.attribute15:
        try:
            AES_KEY = b"1234567890abcdef"
            encrypted_bytes = base64.b64decode(user.password)
            iv_bytes = base64.b64decode(user.attribute15)
            if len(iv_bytes) == 16:
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv_bytes)
                decrypted = unpad(cipher.decrypt(encrypted_bytes), 16).decode()
                print(" AES decrypted password:", decrypted)
                if decrypted == input_pwd:
                    print(" Match via AES decrypted password")
                    password_valid = True
        except Exception as e:
            print(" AES decrypt failed:", str(e))

    if not password_valid:
        print(" PASSWORD FAILED")
        raise HTTPException(status_code=401, detail="Invalid Password")

    print(" PASSWORD VERIFIED")

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
        func.lower(func.trim(models.EmpDet.manager_id)) == user.emp_id.lower().strip()
    ).first() is not None
    if is_manager and role_type != "Admin":
        role_type = "Admin"

    has_2fa = bool(user.auth_key and user.auth_key.strip())
    print(f" 2FA Enabled: {has_2fa}")
    print(f" Role: {role_type}, Global Admin: {is_global_admin}, Manager: {is_manager}")
    print("=" * 60)

    return {
        "access_token": "temp",
        "token_type": "bearer",
        "username": user.p_mail or "",
        "role_type": role_type,
        "is_global_admin": is_global_admin,
        "user_id": user.emp_id or "",
        "name": user.name or "User",
        "requires_2fa": has_2fa
    }


@app.post("/forgot-password")
def forgot_password(request: schemas.ForgotPasswordRequest, background_tasks: BackgroundTasks,
                    db: Session = Depends(get_db)):
    email = request.email.strip().lower()
    print(f"\n---  FORGOT PASSWORD ATTEMPT: {email} ---")
    user = db.query(models.EmpDet).filter(func.lower(models.EmpDet.p_mail) == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found in our records")
    print(f" User found: {user.name} (Emp ID: {user.emp_id})")
    otp = ''.join(random.choices(string.digits, k=6))
    otp_store[email] = {"otp": otp, "expires_at": datetime.now() + timedelta(minutes=5)}
    print(f" Generated OTP: {otp}")

    content = f"""
    <p>We received a request to change the password for your account.</p>
    <p>To complete this process, please use the One-Time Password (OTP) provided below:</p>
    <div style="font-size: 24px; font-weight: 700; color: #4f46e5; margin: 20px 0; letter-spacing: 4px;">{otp}</div>
    <p>This OTP is valid for <strong>5 minutes</strong> and can only be used once.</p>
    <p style="margin-top: 25px; font-size: 13px; color: #64748b;">If you did not request a password change, please contact our support team immediately at <a href="mailto:info@ilantechsolutions.com" style="color: #4f46e5;">info@ilantechsolutions.com</a>.</p>
    """
    body = get_email_template(user.name or 'User', "Password Reset OTP", content, "Security Team")
    background_tasks.add_task(send_email_notification, email, f"ITS - Password Reset Mail", body)
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
    print("\n" + "=" * 60)
    print(" GET USER AUTH KEY")
    print("=" * 60)
    p_mail = request.p_mail.strip().lower()
    if not p_mail:
        raise HTTPException(status_code=400, detail="Email is required")
    user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.p_mail)) == p_mail).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.auth_key:
        raise HTTPException(status_code=400, detail="2FA not configured for this user")
    print(f" User found: {user.emp_id}")
    print(f" Auth Timer: {user.auth_timer}")
    return GetAuthKeyResponse(auth_key=user.auth_key, auth_timer=user.auth_timer or 30, p_mail=user.p_mail)


import time


def verify_authenticator_otp_for_user(user, otp_input: str) -> bool:
    try:
        print("\n==============================")
        print(" 2FA VERIFY (DB MODE)")
        print("==============================")
        encrypted_key = user.auth_key
        auth_timer = user.auth_timer or 30
        if not encrypted_key:
            print(" No auth_key found")
            return False
        fernet = Fernet(FERNET_KEY.encode())
        secret = fernet.decrypt(encrypted_key.encode()).decode()
        print(" Secret decrypted")
        totp = pyotp.TOTP(secret, digits=6, interval=auth_timer)
        now = int(time.time())
        print(" Time:", now)
        print(" Prev:", totp.at(now - auth_timer))
        print(" Curr:", totp.now())
        print(" Next:", totp.at(now + auth_timer))
        otp_clean = otp_input.strip()
        if not otp_clean.isdigit() or len(otp_clean) != 6:
            print(" Invalid OTP format")
            return False
        print(" Received:", otp_clean)
        ok = totp.verify(otp_clean, valid_window=1)
        print(" SUCCESS" if ok else " FAILED")
        return ok
    except Exception as e:
        print(" OTP verify error:", str(e))
        return False


@app.post("/verify-2fa")
def verify_2fa(request: schemas.Verify2FARequest, db: Session = Depends(get_db)):
    print("\n" + "=" * 60)
    print(" 2FA VERIFY")
    print("=" * 60)
    emp_id = request.user_id.strip().upper()
    otp_input = request.totp_code.strip()
    user = db.query(models.EmpDet).filter(func.trim(models.EmpDet.emp_id) == emp_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.auth_key:
        raise HTTPException(status_code=400, detail="2FA not configured")
    print(f" User: {user.emp_id}")
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
        func.lower(func.trim(models.EmpDet.manager_id)) == user.emp_id.lower().strip()
    ).first() is not None
    if is_manager and role_type != "Admin":
        role_type = "Admin"
    return {
        "access_token": "REAL_TOKEN_HERE",
        "token_type": "bearer",
        "username": user.p_mail or "",
        "role_type": role_type,
        "is_global_admin": is_global_admin,
        "user_id": user.emp_id or "",
        "name": user.name or "User",
        "requires_2fa": False
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
    user = db.query(models.EmpDet).filter(func.lower(models.EmpDet.p_mail) == email).first()
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


@app.get("/admin/employees")
def get_employees(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.EmpDet).filter(
        (models.EmpDet.end_date == None) | (models.EmpDet.end_date == "")
    )
    if manager_id:
        query = query.filter(
            func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    employees = query.all()
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
            "email": emp.p_mail or emp.mail or "",
            "department": domain_name,
            "designation": emp.role_type or "Employee",
            "doj": emp.date_of_joining or "",
            "manager": emp.reporting_manager or "N/A",
            "location": emp.attribute1 or "Chennai",
            "shift": "General (9:30 AM - 6:30 PM)",
            "address": emp.address or ""
        })
    return results


@app.get("/employee-profile/{emp_id}", response_model=schemas.EmployeeProfileResponse)
def get_employee_profile(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    user = db.query(models.EmpDet).filter(
        func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
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
        "email": user.mail or user.p_mail,
        "p_mail": user.p_mail,
        "mail": user.mail,
        "personal_mail": user.mail,
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
    query = db.query(models.EmpDet).filter(
        (models.EmpDet.end_date == None) | (models.EmpDet.end_date == "")
    )
    if manager_id:
        query = query.filter(
            func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    employees = query.all()
    logs = db.query(models.CheckIn).filter(models.CheckIn.t_date == today).all()
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
            "totalHours": log.Total_hours if log and log.Total_hours else "0h 0m",
            "status": log.status if log and log.status else "Absent"
        })
    return results


@app.post("/check-in")
def check_in(request: schemas.CheckInRequest, db: Session = Depends(get_db)):
    emp_id = request.emp_id.strip()
    now = datetime.now()
    today_date = now.date()
    existing = db.query(models.CheckIn).filter(
        models.CheckIn.emp_id == emp_id,
        models.CheckIn.t_date == today_date
    ).first()
    if existing:
        return {"message": "Already checked in today", "id": existing.check_in_id}
    new_checkin = models.CheckIn(
        emp_id=emp_id,
        in_time=request.in_time,
        t_date=today_date,
        t_day=now.strftime("%A"),
        month=now.strftime("%B"),
        status="Pending",
        created_by=emp_id,
        creation_date=now,
        last_updated_by=emp_id,
        last_update_date=now
    )
    db.add(new_checkin)
    db.commit()
    db.refresh(new_checkin)
    return {"message": "Check-in successful", "id": new_checkin.check_in_id}


@app.post("/check-out")
def check_out(request: schemas.CheckOutRequest, db: Session = Depends(get_db)):
    emp_id = request.emp_id.strip()
    now = datetime.now()
    today_date = now.date()
    checkin_record = db.query(models.CheckIn).filter(
        models.CheckIn.emp_id == emp_id,
        models.CheckIn.t_date == today_date
    ).order_by(models.CheckIn.check_in_id.desc()).first()
    if not checkin_record:
        raise HTTPException(status_code=404, detail="No check-in found for today")
    checkin_record.out_time = request.out_time
    checkin_record.last_update_date = now
    checkin_record.last_updated_by = emp_id
    try:
        fmt = "%H:%M:%S"
        t1 = datetime.strptime(checkin_record.in_time.strip(), fmt)
        t2 = datetime.strptime(request.out_time.strip(), fmt)
        grace_start_time = datetime.strptime("09:30:00", fmt)
        grace_end_time = datetime.strptime("10:00:00", fmt)
        checkout_grace_start = datetime.strptime("18:30:00", fmt)
        checkout_grace_end = datetime.strptime("19:00:00", fmt)

        if grace_start_time <= t1 <= grace_end_time:
            t1 = grace_start_time
            checkin_record.in_time = "09:30:00"
        if checkout_grace_start <= t2 <= checkout_grace_end:
            t2 = checkout_grace_end
            checkin_record.out_time = "19:00:00"

        delta = t2 - t1
        total_seconds = int(delta.total_seconds())
        if total_seconds < 0:
            total_seconds = 0

        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        checkin_record.Total_hours = f"{hours}h {minutes}m"
        total_hours_float = hours + (minutes / 60)

        if total_hours_float < 4:
            checkin_record.status = "LT4"
        elif total_hours_float < 6:
            checkin_record.status = "LT6"
        elif total_hours_float < 8:
            checkin_record.status = "LT8"
        else:
            checkin_record.status = "P"

        db.commit()
    except Exception as e:
        db.rollback()
        print(f" Check-out Error: {str(e)}")
        try:
            checkin_record.out_time = request.out_time
            checkin_record.status = "Error"
            db.commit()
        except:
            db.rollback()

    return {
        "message": "Check-out successful",
        "total_hours": checkin_record.Total_hours or "0h 0m",
        "status": checkin_record.status
    }


@app.get("/check-status/{emp_id}")
def get_check_status(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    today_date = datetime.now().date()
    record = db.query(models.CheckIn).filter(
        models.CheckIn.emp_id == emp_id,
        models.CheckIn.t_date == today_date
    ).order_by(models.CheckIn.check_in_id.desc()).first()
    if record:
        return {
            "checked_in": True,
            "in_time": record.in_time,
            "out_time": record.out_time,
            "total_hours": record.Total_hours
        }
    return {"checked_in": False}


@app.get("/attendance-month/{emp_id}")
def get_attendance_month(emp_id: str, month: int, year: int, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    logs = db.query(models.CheckIn).filter(
        func.lower(func.trim(models.CheckIn.emp_id)) == emp_id.lower(),
        extract('month', models.CheckIn.t_date) == month,
        extract('year', models.CheckIn.t_date) == year
    ).all()
    # Normalize date to YYYY-MM-DD string for frontend consistency
    for log in logs:
        if hasattr(log, 't_date') and log.t_date:
            if not isinstance(log.t_date, str):
                log.t_date = log.t_date.strftime("%Y-%m-%d")
    return logs


@app.get("/leave-stats/{emp_id}")
def get_leave_stats(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    leave_rows = db.query(models.LeaveDet).filter(
        func.lower(func.trim(models.LeaveDet.emp_id)) == emp_id.lower()).all()
    stats: dict = {
        "casualLeave": {"total": 0, "availed": 0},
        "sickLeave": {"total": 0, "availed": 0},
        "maternityPaternity": {"total": 0, "availed": 0},
        "marriageLeave": {"total": 5, "availed": 0},
        "total": 0,
        "availed": 0
    }

    cl_total: float = 0.0
    sl_total: float = 0.0
    mp_total: float = 0.0
    cl_availed: float = 0.0
    sl_availed: float = 0.0
    mp_availed: float = 0.0

    for row in leave_rows:
        l_type = (row.leave_type or "").lower()
        try:
            t_val = float(row.total_leave or 0)
            a_val = float(row.availed_leave or 0)
        except:
            t_val, a_val = 0.0, 0.0

        if 'casual' in l_type or l_type == 'cl':
            cl_total = t_val
            cl_availed = a_val
        elif 'sick' in l_type or l_type == 'sl':
            sl_total = t_val
            sl_availed = a_val
        elif 'maternity' in l_type or 'paternity' in l_type or l_type in ['ml', 'pl']:
            mp_total = t_val
            mp_availed = a_val

    # Cast totals to float to ensure consistency
    stats["casualLeave"] = {"total": cl_total, "availed": cl_availed}
    stats["sickLeave"] = {"total": sl_total, "availed": sl_availed}
    stats["maternityPaternity"] = {"total": mp_total, "availed": mp_availed}
    stats["total"] = cl_total + sl_total + mp_total
    stats["availed"] = cl_availed + sl_availed + mp_availed

    return stats


@app.get("/wfh-history/{emp_id}")
def get_wfh_history(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    history = db.query(models.WFHDet).filter(
        func.lower(func.trim(models.WFHDet.emp_id)) == emp_id.lower()
    ).order_by(models.WFHDet.wfh_id.desc()).all()
    return [
        {
            "wfh_id": row.wfh_id,
            "from_date": row.from_date,
            "to_date": row.to_date,
            "days": row.days,
            "reason": row.reason,
            "status": row.status
        }
        for row in history
    ]


@app.get("/leave-history/{emp_id}")
def get_leave_history(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    history = db.query(models.EmpLeave).filter(
        func.lower(func.trim(models.EmpLeave.emp_id)) == emp_id.lower()
    ).order_by(models.EmpLeave.l_id.desc()).all()
    return [
        {
            "l_id": row.l_id,
            "leaveType": row.leave_type,
            "leave_type": row.leave_type,
            "from_date": row.from_date,
            "to_date": row.to_date,
            "days": row.days,
            "reason": row.reason,
            "status": row.status,
            "remarks": row.remarks,
            "revision": row.revision
        }
        for row in history
    ]


def send_email_notification(to_email: str, subject: str, body_html: str):
    if not to_email:
        print(" Email notification skipped: No recipient email provided")
        return False

    url = "http://devbms.ilantechsolutions.com/attendance/send-mail/"
    api_key = "my_secret_key_123"

    payload = {
        "to_email": to_email,
        "subject": subject,
        "body": body_html,
        "content_type": "text/html", 
    }

    headers = {
        "x-api-key": api_key,
        "Content-Type": "application/json"
    }

    try:
        print(f" Attempting to send email via API to: {to_email}")
        response = requests.post(url, json=payload, headers=headers, timeout=15)

        if response.status_code in [200, 201]:
            print(f" EMAIL SENT successfully via API to {to_email}")
            return True
        else:
            print(f" API FAILED to send email to {to_email}: Status {response.status_code}")
            print(f"   Response Preview: {response.text[:200]}")
            return False

    except Exception as e:
        print(f" ERROR calling email API for {to_email}: {str(e)}")
        return False


def get_email_template(receiver_name, title, content_html, sender_name="Aruvi Team"):
    return f"""
    <html>
    <head>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Segoe+UI:wght@400;600;700&display=swap');
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #334155; margin: 0; padding: 0; background-color: #f8fafc; }}
            .container {{ max-width: 600px; margin: 30px auto; background-color: #ffffff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }}
            .header {{ border-bottom: 2px solid #eef2f6; padding-bottom: 20px; margin-bottom: 30px; }}
            .title {{ color: #1e293b; font-size: 22px; font-weight: 700; margin: 0; }}
            .greeting {{ font-size: 16px; margin-bottom: 20px; color: #1e293b; }}
            .content {{ font-size: 15px; margin-bottom: 30px; }}
            .footer {{ border-top: 1px solid #eef2f6; padding-top: 25px; margin-top: 35px; color: #94a3b8; font-size: 13px; }}
            .company {{ color: #475569; font-weight: 600; font-size: 15px; margin-bottom: 2px; }}
            .signature {{ color: #64748b; font-size: 14px; margin-top: 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="title">{title}</h1>
            </div>
            <p class="greeting">Dear <strong>{receiver_name}</strong>,</p>
            <div class="content">
                {content_html}
            </div>
            <div class="footer">
                <p class="company">{sender_name}</p>
                <p class="signature">Aruvi Team | Ilan Tech Solutions</p>
                <p style="margin-top: 20px; font-size: 11px;">© 2026 Ilan Tech Solutions Private Limited. All rights reserved.</p>
            </div>
        </div>
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
        attachments: Optional[List[UploadFile]] = File(None),
        db: Session = Depends(get_db)
):
    emp_id = emp_id.strip()
    user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
    
    if not user:
        raise HTTPException(status_code=404, detail=f"Employee with ID {emp_id} not found in the system.")
        
    emp_name = user.name if user else 'Unknown'
    normalized_leave_type = (leave_type or "").strip().lower()
    requested_days = float(days or 0)

    # Validation: Sick Leave 2 days or more requires attachment
    if normalized_leave_type == "sick leave" and requested_days >= 2:
        if not attachments or len(attachments) == 0:
            raise HTTPException(status_code=400, detail="Attachment is mandatory for Sick Leave requests lasting 2 days or more.")

    attachment_paths = []
    if attachments:
        print(f" Received {len(attachments)} attachments for leave request.")
        upload_dir = "uploads/leave_attachments"
        os.makedirs(upload_dir, exist_ok=True)

        for i, file in enumerate(attachments):
            if not file.filename:
                continue
            file_extension = file.filename.split('.')[-1]
            file_name = f"{emp_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{i}.{file_extension}"
            file_path = os.path.join(upload_dir, file_name)
            
            # Save file
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            
            # Use forward slashes for DB storage to avoid escaping issues
            db_path = f"uploads/leave_attachments/{file_name}"
            attachment_paths.append(db_path)
            print(f" Saved attachment {i} to {db_path}")

    attr14_paths = ",".join(attachment_paths) if attachment_paths else None
    primary_attachment_path = attachment_paths[0] if attachment_paths else None

    print(f" Processing Leave Request for: {emp_id}, Type: {leave_type}, Days: {days}, Primary File: {primary_attachment_path}")
    
    lop_days_val = 0.0
    cl_days_to_deduct = requested_days

    try:
        req_from = parse_date(from_date)
        req_to = parse_date(to_date)
        if not req_from or not req_to:
            raise HTTPException(status_code=400, detail="Invalid From/To date format")
        assert req_from is not None
        assert req_to is not None
        if req_to < req_from:
            raise HTTPException(status_code=400, detail="To date must be on or after from date")

        if requested_days <= 0:
            raise HTTPException(status_code=400, detail="Invalid leave days")

        # Check for Overlapping Leaves
        existing_leaves = db.query(models.EmpLeave).filter(
            func.lower(func.trim(models.EmpLeave.emp_id)) == emp_id.lower(),
            func.lower(func.trim(models.EmpLeave.status)).in_(["pending", "approved"])
        ).all()
        for row in existing_leaves:
            row_from = parse_date(row.from_date)
            row_to = parse_date(row.to_date) if row.to_date else row_from
            if not row_from or not row_to:
                continue
            # Overlap exists if (req_from <= row_to) AND (req_to >= row_from)
            if row_from and row_to and (req_from <= row_to) and (req_to >= row_from):
                raise HTTPException(
                    status_code=400,
                    detail=f"Leave already applied for overlapping dates ({row.from_date} to {row.to_date})."
                )

        if normalized_leave_type == "casual leave":
            month_usage: dict[str, float] = {}
            for row in existing_leaves:
                if (row.leave_type or "").strip().lower() != "casual leave":
                    continue
                row_from = parse_date(row.from_date)
                row_to = parse_date(row.to_date) if row.to_date else row_from
                if not row_from or not row_to:
                    continue
                if row_from and row_to and row_to < row_from:
                    row_from, row_to = row_to, row_from
                
                if row_from and row_to:
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
                    if excess > max_excess:
                        max_excess = excess
            
            if max_excess > 0:
                # Part of the leave becomes LOP
                lop_days_val = min(requested_days, max_excess)
                cl_days_to_deduct = requested_days - lop_days_val
                print(f" Casual Leave Limit Exceeded. {cl_days_to_deduct} as CL, {lop_days_val} as LOP.")

        # Find balance row and deduct (using robust mapping)
        l_type_lower = leave_type.lower()
        balance_row = None
        
        # Try specific mappings first
        if 'casual' in l_type_lower or 'cl' == l_type_lower:
            search_key = 'casual'
        elif 'sick' in l_type_lower or 'sl' == l_type_lower:
            search_key = 'sick'
        elif 'maternity' in l_type_lower or 'paternity' in l_type_lower or l_type_lower in ['ml', 'pl']:
            # For maternity/paternity, we look for either keyword in the DB
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

        det_id = balance_row.l_det_id if balance_row else None
        
        # Format days to avoid long floating point strings (e.g. 0.999999)
        from decimal import Decimal, ROUND_HALF_UP
        _twodp = Decimal('0.01')
        cl_days_to_deduct = float(Decimal(str(float(cl_days_to_deduct))).quantize(_twodp, rounding=ROUND_HALF_UP))
        lop_days_val = float(Decimal(str(float(lop_days_val))).quantize(_twodp, rounding=ROUND_HALF_UP))
        
        # Utility function to format numbers cleanly for DB string fields
        def fmt_days(d):
            val = float(d)
            if val.is_integer():
                return str(int(val))
            return f"{val:.2f}".rstrip('0').rstrip('.')

        print(f" FINAL: det_id: {det_id}, emp_id: {emp_id}, CL: {cl_days_to_deduct}, LOP: {lop_days_val}")

        # Record 1: The Casual Leave portion (if any)
        if cl_days_to_deduct > 0 and req_from:
            if lop_days_val > 0:
                # Part 1 of splitting
                split_days = int(cl_days_to_deduct)
                future_dt = req_from + timedelta(days=split_days - 1)
                rec1_to = future_dt.strftime('%Y-%m-%d')
            else:
                rec1_to = to_date

            new_leave = models.EmpLeave(
                l_det_id=det_id,
                emp_id=emp_id.strip(),
                leave_type=leave_type,
                from_date=from_date,
                to_date=rec1_to,
                days=fmt_days(cl_days_to_deduct),
                reason=reason + (" (Part 1: CL)" if lop_days_val > 0 else ""),
                status=status,
                file=primary_attachment_path,
                attribute14=attr14_paths,
                applied_date=datetime.now().strftime('%Y-%m-%d'),
                mail_message_id="", hr_action="", hr_approval="", admin_approval="",
                lop_days="0",
                remarks="", approved_by="", reporting_manager="", approver="", revision="0",
                attribute_category="", attribute1=fmt_days(requested_days),
                attribute2="", attribute3="", attribute4="", attribute5="",
                last_update_login="", created_by=emp_id.strip(), creation_date=datetime.now(),
                last_updated_by=emp_id.strip(), last_update_date=datetime.now()
            )
            db.add(new_leave)
            
            if balance_row:
                balance_row.availed_leave = float(balance_row.availed_leave or 0) + cl_days_to_deduct
                if balance_row.available_leave is not None:
                    balance_row.available_leave = float(balance_row.available_leave or 0) - cl_days_to_deduct
                db.add(balance_row)

        # Record 2: The LOP portion (if any)
        if lop_days_val > 0 and req_from:
            if cl_days_to_deduct > 0:
                # Part 2 of a split
                split_offset = int(cl_days_to_deduct)
                future_dt_2 = req_from + timedelta(days=split_offset)
                rec2_from = future_dt_2.strftime('%Y-%m-%d')
                rec2_reason = reason + " (Part 2: LOP)"
            else:
                # Pure LOP
                rec2_from = from_date
                rec2_reason = reason + " (Limit Reached: LOP)"

            lop_leave = models.EmpLeave(
                l_det_id=det_id,
                emp_id=emp_id.strip(),
                leave_type="LOP",
                from_date=rec2_from,
                to_date=to_date,
                days=fmt_days(lop_days_val),
                reason=rec2_reason,
                status=status,
                file=primary_attachment_path,
                attribute14=attr14_paths,
                applied_date=datetime.now().strftime('%Y-%m-%d'),
                mail_message_id="", hr_action="", hr_approval="", admin_approval="",
                lop_days=fmt_days(lop_days_val),
                remarks="", approved_by="", reporting_manager="", approver="", revision="0",
                attribute_category="", attribute1=fmt_days(requested_days),
                attribute2="", attribute3="", attribute4="", attribute5="",
                last_update_login="", created_by=emp_id.strip(), creation_date=datetime.now(),
                last_updated_by=emp_id.strip(), last_update_date=datetime.now()
            )
            db.add(lop_leave)
            
            if cl_days_to_deduct <= 0:
                new_leave = lop_leave
        
        db.commit()
        db.refresh(new_leave)
        print(f" SUCCESS: Leave processing complete for {emp_id}")

        # Email Notification (Safe/Non-blocking)
        try:
            if user and user.manager_id:
                manager = db.query(models.EmpDet).filter(
                    func.lower(func.trim(models.EmpDet.emp_id)) == user.manager_id.strip().lower()
                ).first()
                if manager and manager.p_mail:
                    summary_msg = f"{cl_days_to_deduct} CL / {lop_days_val} LOP" if lop_days_val > 0 else f"{requested_days} days"
                    subject = f"ITS - {emp_name} - {leave_type} Request | {from_date} ({summary_msg})"
                    
                    content = f"""
                    <p>Good Day!</p>
                    <p>I hope this mail finds you well.</p>
                    <p>I am requesting leave from <strong>{from_date}</strong> to <strong>{to_date}</strong>.</p>
                    <p><strong>Breakup:</strong> {summary_msg}</p>
                    <p><strong>Reason:</strong> {reason}</p>
                    """
                    body = get_email_template(manager.name, "Leave Request", content, emp_name)
                    background_tasks.add_task(send_email_notification, manager.p_mail, subject, body)
        except Exception as mail_err:
            print(f" Non-critical error sending mail: {mail_err}")

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        print(f" CRITICAL DATABASE ERROR: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Database Insertion Error: {str(e)}")

    return {"message": "Leave request submitted successfully", "leave_id": new_leave.l_id}


@app.post("/send-leave-notification")
def send_leave_notification(notification: dict, db: Session = Depends(get_db)):
    return {"message": "Notification processed"}


@app.get("/admin/pending-leaves")
def get_pending_leaves(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.EmpLeave, models.EmpDet).join(
        models.EmpDet, models.EmpLeave.emp_id == models.EmpDet.emp_id
    ).filter(models.EmpLeave.status == "Pending")
    if manager_id:
        query = query.filter(
            func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    pending = query.order_by(models.EmpLeave.creation_date.desc()).all()
    results = []
    for leave, emp in pending:
        results.append({
            "l_id": leave.l_id,
            "emp_name": emp.name or "Unknown Employee",
            "emp_id": emp.emp_id.strip() if emp.emp_id else "",
            "leave_type": leave.leave_type,
            "from_date": leave.from_date,
            "to_date": leave.to_date,
            "days": leave.days,
            "reason": leave.reason,
            "remarks": leave.remarks or "",
            "status": leave.status,
            "file": leave.file
        })
    return results


@app.get("/admin/all-leave-history")
def get_all_leave_history(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.EmpLeave, models.EmpDet).join(
        models.EmpDet, models.EmpLeave.emp_id == models.EmpDet.emp_id
    )
    if manager_id:
        query = query.filter(
            func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    all_leaves = query.order_by(models.EmpLeave.creation_date.desc()).all()
    results = []
    for leave, emp in all_leaves:
        results.append({
            "l_id": leave.l_id,
            "emp_name": emp.name or "Unknown Employee",
            "emp_id": emp.emp_id.strip() if emp.emp_id else "",
            "leave_type": leave.leave_type,
            "from_date": leave.from_date,
            "to_date": leave.to_date,
            "days": leave.days,
            "reason": leave.reason,
            "remarks": leave.remarks or "",
            "status": leave.status,
            "file": leave.file,
            "revision": leave.revision
        })
    return results


@app.post("/admin/approve-leave")
def approve_leave(request_item: schemas.LeaveApprovalAction, background_tasks: BackgroundTasks,
                  db: Session = Depends(get_db)):
    leave = db.query(models.EmpLeave).filter(models.EmpLeave.l_id == request_item.l_id).first()
    if not leave:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Leave request not found")
    old_status = leave.status
    leave.status = request_item.action
    leave.remarks = request_item.remarks
    leave.last_update_date = datetime.now()
    if request_item.action == 'Approved':
        leave.admin_approval = 'Approved'
        leave.hr_approval = 'Approved'
    elif request_item.action == 'Rejected':
        leave.admin_approval = 'Rejected'
        leave.hr_approval = 'Rejected'
    admin_user = db.query(models.EmpDet).filter(
        models.EmpDet.emp_id == request_item.admin_id.strip()).first()
    if admin_user:
        leave.approved_by = admin_user.name
        leave.approver = admin_user.name
    
    # Robust revision increment with 3-time limit
    try:
        val = str(leave.revision or "0")
        current_rev = int(''.join(filter(str.isdigit, val))) if any(c.isdigit() for c in val) else 0
    except (ValueError, TypeError):
        current_rev = 0

    if current_rev >= 3:
        raise HTTPException(status_code=400, detail="Maximum 3 revisions allowed for this leave request. No further actions can be taken.")
        
    next_rev = current_rev + 1
    leave.revision = str(next_rev)
    db.add(leave)
    print(f"DEBUG: Leave ID {leave.l_id} revision updated to {next_rev}")
    
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
    db.commit()
    try:
        emp_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == leave.emp_id).first()
        if emp_user and emp_user.p_mail:
            status_msg = request_item.action.upper()
            color = "#10B981" if request_item.action.lower() == "approved" else "#EF4444"
            subject = f"RE: ITS-{emp_user.name}-{leave.leave_type} Request on {leave.from_date}"
            
            # Reconstruction of original request for threading
            original_request_box = f"""
            <div style="margin-top: 30px; padding-top: 20px; border-top: 2px solid #e2e8f0; color: #64748b;">
                <p style="font-size: 12px; font-weight: bold; margin-bottom: 10px;">--- Original Request ---</p>
                <p>Dear {leave.approver or 'Manager'},</p>
                <p>Good Day!</p>
                <p>I hope this mail finds you well.</p>
                <p>I am requesting a <strong>{leave.leave_type}</strong> from {leave.from_date} to {leave.to_date} ({leave.days} days) due to: {leave.reason}</p>
            </div>
            """

            content = f"""
            <p>Your request for <strong>{leave.leave_type}</strong> has been processed.</p>
            <div style="font-size: 20px; font-weight: 700; color: {'#10B981' if request_item.action.lower() == 'approved' else '#EF4444'}; margin: 20px 0;">
                {status_msg}
            </div>
            <p><strong>Dates:</strong> {leave.from_date} to {leave.to_date}</p>
            <p><strong>Remarks:</strong> {request_item.remarks or 'No remarks provided.'}</p>
            <p style="margin-top: 25px; font-size: 13px; color: #64748b;">You can view the full history and status in the Aruvi mobile app.</p>
            """
            
            # Send using the approver name as the sender in the template
            body = get_email_template(emp_user.name, f"Leave Request {status_msg}", content, leave.approved_by or "Manager")
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
    except Exception as e:
        print(f" Email notification failed: {e}")
    return {"message": f"Leave request {request_item.action.lower()} successfully",
            "approved_by": leave.approved_by}


@app.get("/notifications/{user_id}")
def get_notifications(
        user_id: str,
        role: str = "employee",
        manager_id: Optional[str] = None,
        db: Session = Depends(get_db)
):
    user_id = user_id.strip()
    notifications = []

    user = db.query(models.EmpDet).filter(
        func.lower(func.trim(models.EmpDet.emp_id)) == user_id.lower()
    ).first()

    last_clear_date = None
    if user and user.attribute8 and user.attribute8.strip():
        try:
            last_clear_date = datetime.strptime(user.attribute8.strip(), "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            print(f" Could not parse attribute8 '{user.attribute8}': {e}")

    effective_cutoff = last_clear_date if last_clear_date else (datetime.now() - timedelta(days=30))
    print(f" Notifications for {user_id} | role={role} | cutoff={effective_cutoff}")

    def status_type(s: str):
        s = (s or '').lower()
        if s == 'pending': return 'pending'
        if s == 'approved': return 'success'
        if s == 'rejected': return 'error'
        return 'info'

    def status_icon(s: str):
        s = (s or '').lower()
        if s == 'pending': return 'time-outline'
        if s == 'approved': return 'checkmark-circle'
        if s == 'rejected': return 'close-circle'
        return 'notifications-outline'

    def status_label(s: str):
        s = (s or '').lower()
        if s == 'pending': return ' Pending'
        if s == 'approved': return ' Approved'
        if s == 'rejected': return ' Rejected'
        return s or 'Unknown'

    def cutoff_filter(status_col, date_col, creation_col):
        # We now respect the cutoff for EVERYTHING, including pending, 
        # so "Clear All" actually clears them.
        return func.coalesce(date_col, creation_col) > effective_cutoff

    if role.lower() == 'admin':
        print(f" ADMIN notifications for {user_id} (manager_id={manager_id}) - SHOWING ONLY PENDING")

        q_perms = (
            db.query(models.EmpPermission, models.EmpDet)
            .outerjoin(models.EmpDet,
                       func.lower(func.trim(models.EmpPermission.emp_id)) ==
                       func.lower(func.trim(models.EmpDet.emp_id)))
            .filter(func.lower(models.EmpPermission.status) == "pending")
            .filter(cutoff_filter(
                models.EmpPermission.status,
                models.EmpPermission.last_update_date,
                models.EmpPermission.creation_date))
        )
        if manager_id and manager_id.strip().lower() != 'all':
            q_perms = q_perms.filter(
                func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())

        for perm, emp in q_perms.order_by(
                case((func.lower(models.EmpPermission.status) == 'pending', 0), else_=1),
                func.coalesce(models.EmpPermission.last_update_date,
                              models.EmpPermission.creation_date).desc()
        ).limit(30).all():
            try:
                emp_name = emp.name if emp else "Unknown"
                p_date_str = (perm.date.strftime('%d-%b-%Y')
                              if perm.date and hasattr(perm.date, 'strftime')
                              else str(perm.date or ''))
                f_time_str = (perm.f_time.strftime('%I:%M %p')
                              if perm.f_time and hasattr(perm.f_time, 'strftime')
                              else str(perm.f_time or ''))
                t_time_str = (perm.t_time.strftime('%I:%M %p')
                              if perm.t_time and hasattr(perm.t_time, 'strftime')
                              else str(perm.t_time or ''))
                st = perm.status or 'Pending'
                update_time = perm.last_update_date or perm.creation_date
                notifications.append({
                    "id": f"permission_{perm.p_id}",
                    "record_id": perm.p_id,
                    "type": status_type(st),
                    "notification_type": "permission",
                    "title": f"Permission - {emp_name}",
                    "message": f"{status_label(st)} | {p_date_str}: {f_time_str} - {t_time_str}",
                    "time": str(update_time or "Recently"),
                    "icon": status_icon(st),
                    "screen": f"/AdminPermission?tab=myApproval&p_id={perm.p_id}"
                })
            except Exception as e:
                print(f"   Error formatting permission {perm.p_id}: {e}")

        q_leaves = (
            db.query(models.EmpLeave, models.EmpDet)
            .outerjoin(models.EmpDet,
                       func.lower(func.trim(models.EmpLeave.emp_id)) ==
                       func.lower(func.trim(models.EmpDet.emp_id)))
            .filter(func.lower(models.EmpLeave.status) == "pending")
            .filter(cutoff_filter(
                models.EmpLeave.status,
                models.EmpLeave.last_update_date,
                models.EmpLeave.creation_date))
        )
        if manager_id and manager_id.strip().lower() != 'all':
            q_leaves = q_leaves.filter(
                func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())

        for leave, emp in q_leaves.order_by(
                case((func.lower(models.EmpLeave.status) == 'pending', 0), else_=1),
                func.coalesce(models.EmpLeave.last_update_date,
                              models.EmpLeave.creation_date).desc()
        ).limit(30).all():
            try:
                emp_name = emp.name if emp else "Unknown"
                st = leave.status or 'Pending'
                update_time = (leave.last_update_date or leave.creation_date or leave.applied_date)
                notifications.append({
                    "id": f"leave_{leave.l_id}",
                    "record_id": leave.l_id,
                    "type": status_type(st),
                    "notification_type": "leave",
                    "title": f"Leave - {emp_name}",
                    "message": (f"{status_label(st)} | {leave.leave_type}: "
                                f"{leave.from_date} to {leave.to_date} ({leave.days} days)"),
                    "time": str(update_time or "Recently"),
                    "icon": status_icon(st),
                    "screen": f"/AdminLeave?tab=myApproval&l_id={leave.l_id}"
                })
            except Exception as e:
                print(f"   Error formatting leave {leave.l_id}: {e}")

        q_ot = (
            db.query(models.OverTimeDet, models.EmpDet)
            .outerjoin(models.EmpDet,
                       func.lower(func.trim(models.OverTimeDet.emp_id)) ==
                       func.lower(func.trim(models.EmpDet.emp_id)))
            .filter(func.lower(models.OverTimeDet.status) == "pending")
            .filter(cutoff_filter(
                models.OverTimeDet.status,
                models.OverTimeDet.last_update_date,
                models.OverTimeDet.creation_date))
        )
        if manager_id and manager_id.strip().lower() != 'all':
            q_ot = q_ot.filter(
                func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())

        for ot, emp in q_ot.order_by(
                case((func.lower(models.OverTimeDet.status) == 'pending', 0), else_=1),
                func.coalesce(models.OverTimeDet.last_update_date,
                              models.OverTimeDet.creation_date).desc()
        ).limit(30).all():
            try:
                emp_name = emp.name if emp else "Unknown"
                st = ot.status or 'Pending'
                update_time = ot.last_update_date or ot.creation_date
                notifications.append({
                    "id": f"ot_{ot.ot_id}",
                    "record_id": ot.ot_id,
                    "type": status_type(st),
                    "notification_type": "ot",
                    "title": f"OT - {emp_name}",
                    "message": f"{status_label(st)} | {ot.ot_date}: {ot.duration} hrs",
                    "time": str(update_time or "Recently"),
                    "icon": status_icon(st),
                    "screen": f"/AdminOt?tab=myApproval&ot_id={ot.ot_id}"
                })
            except Exception as e:
                print(f"   Error formatting OT {ot.ot_id}: {e}")

        try:
            q_wfh = (
                db.query(models.WFHDet, models.EmpDet)
                .outerjoin(models.EmpDet,
                           func.lower(func.trim(models.WFHDet.emp_id)) ==
                           func.lower(func.trim(models.EmpDet.emp_id)))
                .filter(func.lower(models.WFHDet.status) == "pending")
                .filter(cutoff_filter(
                    models.WFHDet.status,
                    models.WFHDet.last_update_date,
                    models.WFHDet.creation_date))
            )
            if manager_id and manager_id.strip().lower() != 'all':
                q_wfh = q_wfh.filter(
                    func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())

            for wfh, emp in q_wfh.order_by(
                    case((func.lower(models.WFHDet.status) == 'pending', 0), else_=1),
                    func.coalesce(models.WFHDet.last_update_date,
                                  models.WFHDet.creation_date).desc()
            ).limit(30).all():
                try:
                    emp_name = emp.name if emp else "Unknown"
                    st = wfh.status or 'Pending'
                    update_time = wfh.last_update_date or wfh.creation_date
                    notifications.append({
                        "id": f"wfh_{wfh.wfh_id}",
                        "record_id": wfh.wfh_id,
                        "type": status_type(st),
                        "notification_type": "wfh",
                        "title": f"WFH - {emp_name}",
                        "message": f"{status_label(st)} | {wfh.from_date} to {wfh.to_date}",
                        "time": str(update_time or "Recently"),
                        "icon": status_icon(st),
                        "screen": f"/AdminWfh?tab=myApproval&wfh_id={wfh.wfh_id}"
                    })
                except Exception as e:
                    print(f"   Error formatting WFH {wfh.wfh_id}: {e}")
        except Exception as wfh_error:
            print(f" Error fetching WFH notifications (admin): {wfh_error}")
            traceback.print_exc()

        q_timesheets = (
            db.query(models.TimesheetDet, models.EmpDet)
            .outerjoin(models.EmpDet,
                       func.lower(func.trim(models.TimesheetDet.emp_id)) ==
                       func.lower(func.trim(models.EmpDet.emp_id)))
            .filter(func.lower(models.TimesheetDet.status) == "pending")
            .filter(cutoff_filter(
                models.TimesheetDet.status,
                models.TimesheetDet.last_update_date,
                models.TimesheetDet.creation_date))
        )
        if manager_id and manager_id.strip().lower() != 'all':
            q_timesheets = q_timesheets.filter(
                func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())

        for ts, emp in q_timesheets.order_by(
                case((func.lower(models.TimesheetDet.status) == 'pending', 0), else_=1),
                func.coalesce(models.TimesheetDet.last_update_date,
                              models.TimesheetDet.creation_date).desc()
        ).limit(30).all():
            try:
                emp_name = emp.name if emp else "Unknown"
                st = ts.status or 'Pending'
                update_time = ts.last_update_date or ts.creation_date
                notifications.append({
                    "id": f"timesheet_{ts.t_id}",
                    "record_id": ts.t_id,
                    "type": status_type(st),
                    "notification_type": "timesheet",
                    "title": f"Timesheet - {emp_name}",
                    "message": f"{status_label(st)} | {ts.date} - {ts.project or 'N/A'}",
                    "time": str(update_time or "Recently"),
                    "icon": status_icon(st),
                    "screen": "/AdminTimesheet"
                })
            except Exception as e:
                print(f"   Error formatting Timesheet {ts.t_id}: {e}")

    else:
        print(f" EMPLOYEE notifications for {user_id} - SHOWING ONLY APPROVED")

        for leave in (
                db.query(models.EmpLeave)
                .filter(
                    func.lower(func.trim(models.EmpLeave.emp_id)) == user_id.lower(),
                    func.lower(models.EmpLeave.status).in_(["approved", "rejected"]),
                    cutoff_filter(
                        models.EmpLeave.status,
                        models.EmpLeave.last_update_date,
                        models.EmpLeave.creation_date))
                .order_by(func.coalesce(models.EmpLeave.last_update_date,
                                        models.EmpLeave.creation_date).desc())
                .limit(30).all()
        ):
            st = leave.status or 'Pending'
            update_time = leave.last_update_date or leave.creation_date
            notifications.append({
                "id": f"leave_{leave.l_id}",
                "record_id": leave.l_id,
                "type": status_type(st),
                "notification_type": "leave",
                "title": f"Leave {status_label(st)}",
                "message": (f"{leave.leave_type}: {leave.from_date} to "
                            f"{leave.to_date} ({leave.days} days)"),
                "time": str(update_time or "Recently"),
                "icon": status_icon(st),
                "screen": f"/EmployeeLeave?tab=history&id={leave.l_id}"
            })

        for perm in (
                db.query(models.EmpPermission)
                .filter(
                    func.lower(func.trim(models.EmpPermission.emp_id)) == user_id.lower(),
                    func.lower(models.EmpPermission.status).in_(["approved", "rejected"]),
                    cutoff_filter(
                        models.EmpPermission.status,
                        models.EmpPermission.last_update_date,
                        models.EmpPermission.creation_date))
                .order_by(func.coalesce(models.EmpPermission.last_update_date,
                                        models.EmpPermission.creation_date).desc())
                .limit(30).all()
        ):
            st = perm.status or 'Pending'
            p_date_str = (perm.date.strftime('%d-%b-%Y')
                          if perm.date and hasattr(perm.date, 'strftime')
                          else str(perm.date or ''))
            update_time = perm.last_update_date or perm.creation_date
            notifications.append({
                "id": f"permission_{perm.p_id}",
                "record_id": perm.p_id,
                "type": status_type(st),
                "notification_type": "permission",
                "title": f"Permission {status_label(st)}",
                "message": f"Permission on {p_date_str}",
                "time": str(update_time or "Recently"),
                "icon": status_icon(st),
                "screen": f"/EmployeePermission?tab=history&id={perm.p_id}"
            })

        for ot in (
                db.query(models.OverTimeDet)
                .filter(
                    func.lower(func.trim(models.OverTimeDet.emp_id)) == user_id.lower(),
                    func.lower(models.OverTimeDet.status).in_(["pending", "approved", "rejected"]),
                    cutoff_filter(
                        models.OverTimeDet.status,
                        models.OverTimeDet.last_update_date,
                        models.OverTimeDet.creation_date))
                .order_by(func.coalesce(models.OverTimeDet.last_update_date,
                                        models.OverTimeDet.creation_date).desc())
                .limit(30).all()
        ):
            st = ot.status or 'Pending'
            update_time = ot.last_update_date or ot.creation_date
            notifications.append({
                "id": f"ot_{ot.ot_id}",
                "record_id": ot.ot_id,
                "type": status_type(st),
                "notification_type": "ot",
                "title": f"OT {status_label(st)}",
                "message": f"OT on {ot.ot_date}: {ot.duration} hrs",
                "time": str(update_time or "Recently"),
                "icon": status_icon(st),
                "screen": f"/EmployeeOt?tab=history&id={ot.ot_id}"
            })

        try:
            for wfh in (
                    db.query(models.WFHDet)
                    .filter(
                        func.lower(func.trim(models.WFHDet.emp_id)) == user_id.lower(),
                        func.lower(models.WFHDet.status).in_(["pending", "approved", "rejected"]),
                        cutoff_filter(
                            models.WFHDet.status,
                            models.WFHDet.last_update_date,
                            models.WFHDet.creation_date))
                    .order_by(func.coalesce(models.WFHDet.last_update_date,
                                            models.WFHDet.creation_date).desc())
                    .limit(30).all()
            ):
                st = wfh.status or 'Pending'
                update_time = wfh.last_update_date or wfh.creation_date
                notifications.append({
                    "id": f"wfh_{wfh.wfh_id}",
                    "record_id": wfh.wfh_id,
                    "type": status_type(st),
                    "notification_type": "wfh",
                    "title": f"WFH {status_label(st)}",
                    "message": f"WFH: {wfh.from_date} to {wfh.to_date}",
                    "time": str(update_time or "Recently"),
                    "icon": status_icon(st),
                    "screen": f"/EmployeeWfh?tab=history&id={wfh.wfh_id}"
                })
        except Exception as wfh_error:
            print(f" Error fetching WFH notifications: {wfh_error}")

        for ts in (
                db.query(models.TimesheetDet)
                .filter(
                    func.lower(func.trim(models.TimesheetDet.emp_id)) == user_id.lower(),
                    func.lower(models.TimesheetDet.status).in_(["pending", "approved", "rejected"]),
                    cutoff_filter(
                        models.TimesheetDet.status,
                        models.TimesheetDet.last_update_date,
                        models.TimesheetDet.creation_date))
                .order_by(func.coalesce(models.TimesheetDet.last_update_date,
                                        models.TimesheetDet.creation_date).desc())
                .limit(30).all()
        ):
            st = ts.status or 'Pending'
            update_time = ts.last_update_date or ts.creation_date
            notifications.append({
                "id": f"timesheet_{ts.t_id}",
                "record_id": ts.t_id,
                "type": status_type(st),
                "notification_type": "timesheet",
                "title": f"Timesheet {status_label(st)}",
                "message": f"Timesheet: {ts.date} - {ts.project or 'N/A'}",
                "time": str(update_time or "Recently"),
                "icon": status_icon(st),
                "screen": "/EmployeeTimesheet"
            })

    print(f" Returning {len(notifications)} notifications for {user_id}")
    return notifications


@app.post("/notifications/clear-all/{user_id}")
def clear_all_notifications(user_id: str, db: Session = Depends(get_db)):
    user_id = user_id.strip()
    user = db.query(models.EmpDet).filter(
        func.lower(func.trim(models.EmpDet.emp_id)) == user_id.lower()
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.attribute8 = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.commit()
    return {"message": "All notifications cleared"}


@app.post("/apply-ot")
def apply_ot(request: schemas.OverTimeApplyRequest, background_tasks: BackgroundTasks,
             db: Session = Depends(get_db)):
    try:
        user = db.query(models.EmpDet).filter(
            func.trim(models.EmpDet.emp_id) == request.emp_id.strip()).first()
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
            emp_id=target_emp_id,
            ot_date=request.ot_date,
            from_time=request.from_time,
            to_time=request.to_time,
            duration=request.duration,
            reason=request.reason,
            applied_date=datetime.now().strftime("%d-%b-%Y"),
            status=request.status or "Pending",
            created_by=target_emp_id,
            creation_date=datetime.now(),
            last_updated_by=target_emp_id,
            last_update_date=datetime.now(),
            last_update_login=target_emp_id
        )
        db.add(new_ot)
        db.commit()
        db.refresh(new_ot)

        if user and user.manager_id:
            manager = db.query(models.EmpDet).filter(
                func.trim(models.EmpDet.emp_id) == user.manager_id.strip()).first()
            if manager and manager.p_mail:
                subject = f"ITS - {user.name} - OT Request | {ot_date_clean} | {request.from_time} to {request.to_time}"
                content = f"""
                <p>An employee has requested overtime. Details below:</p>
                <div style="font-size: 18px; font-weight: 700; color: #4f46e5; margin: 20px 0;">
                    Overtime Request: {ot_date_clean}<br>
                    <span style="font-size: 14px; font-weight: 500; color: #64748b;">{request.from_time} to {request.to_time} ({request.duration})</span>
                </div>
                <p><strong>Employee:</strong> {user.name}</p>
                <p><strong>Reason:</strong> {request.reason}</p>
                <p style="margin-top: 25px;">Please log in to the portal to take action on this request.</p>
                """
                body = get_email_template(manager.name, "New Overtime Request", content, user.name)
                background_tasks.add_task(send_email_notification, manager.p_mail, subject, body)
        return {"message": "OT request submitted successfully", "ot_id": new_ot.ot_id}
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        print(f" OT INSERT ERROR: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/pending-permissions")
def get_pending_permissions(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.EmpPermission, models.EmpDet).join(
        models.EmpDet, func.lower(func.trim(models.EmpPermission.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
    ).filter(models.EmpPermission.status == "Pending")
    if manager_id:
        query = query.filter(
            func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    pending = query.order_by(models.EmpPermission.creation_date.desc()).all()
    results = []
    for perm, emp in pending:
        results.append({
            "p_id": perm.p_id,
            "emp_name": emp.name or "Unknown",
            "emp_id": emp.emp_id or "N/A",
            "date": perm.date.strftime("%d-%b-%Y") if perm.date else "",
            "time": f"{format_time_safe(perm.f_time)} to {format_time_safe(perm.t_time)}",
            "fromTime": format_time_safe(perm.f_time),
            "toTime": format_time_safe(perm.t_time),
            "f_time": format_time_safe(perm.f_time),
            "t_time": format_time_safe(perm.t_time),
            "total_hours": perm.total_hours or "0.0",
            "dis_total_hours": perm.dis_total_hours or "0.0",
            "reason": perm.reason or "No reason",
            "remarks": perm.remarks or "",
            "status": perm.status or "Pending"
        })
    return results


@app.get("/admin/all-permission-history")
def get_all_permission_history(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    print(f"\n--- FETCH ALL PERMISSION HISTORY: Manager={manager_id} ---")
    query = db.query(models.EmpPermission, models.EmpDet).join(
        models.EmpDet, func.lower(func.trim(models.EmpPermission.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
    )
    if manager_id:
        query = query.filter(
            func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    all_perms = query.order_by(models.EmpPermission.creation_date.desc()).all()
    print(f"   Found {len(all_perms)} records")
    results = []
    for perm, emp in all_perms:
        results.append({
            "p_id": perm.p_id,
            "emp_name": emp.name or "Unknown",
            "emp_id": emp.emp_id or "N/A",
            "date": perm.date.strftime("%d-%b-%Y") if perm.date else "",
            "time": f"{format_time_safe(perm.f_time)} to {format_time_safe(perm.t_time)}",
            "fromTime": format_time_safe(perm.f_time),
            "toTime": format_time_safe(perm.t_time),
            "f_time": format_time_safe(perm.f_time),
            "t_time": format_time_safe(perm.t_time),
            "total_hours": perm.total_hours or "0.0",
            "dis_total_hours": perm.dis_total_hours or "0.0",
            "reason": perm.reason or "No reason",
            "remarks": perm.remarks or "",
            "status": perm.status or "Pending"
        })
    return results


@app.post("/apply-permission")
def apply_permission(request: schemas.PermissionApplyRequest, background_tasks: BackgroundTasks,
                     db: Session = Depends(get_db)):
    print(f"\n--- APPLY PERMISSION ATTEMPT ---")
    print(f" Request Data: {request.dict()}")
    try:
        target_emp_id = (request.emp_id or "").strip().lower()
        user = db.query(models.EmpDet).filter(
            func.lower(func.trim(models.EmpDet.emp_id)) == target_emp_id).first()
        if not user:
            print(f"   Error: Employee {target_emp_id} not found")
            raise HTTPException(status_code=404, detail="Employee not found")

        print(f"   Found User: {user.name} (Manager: {user.manager_id})")
        p_date_dt = parse_date(request.date)
        if not p_date_dt:
            print(f"   Error: Invalid date format {request.date}")
            raise HTTPException(status_code=400, detail="Invalid date format")
        p_date = p_date_dt.date()

        # FIX: Uses the now-defined parse_time_str
        f_time_dt = parse_time_str(request.f_time)
        t_time_dt = parse_time_str(request.t_time)
        if not f_time_dt or not t_time_dt:
            raise HTTPException(status_code=400, detail="Invalid time format")

        assert f_time_dt is not None
        assert t_time_dt is not None

        h1, m1 = f_time_dt.hour, f_time_dt.minute
        h2, m2 = t_time_dt.hour, t_time_dt.minute
        diff_mins = (h2 * 60 + m2) - (h1 * 60 + m1)
        if diff_mins < 0:
            diff_mins += 24 * 60

        if diff_mins <= 0:
            raise HTTPException(status_code=400, detail="To Time must be after From Time")

        # Revised Permission Logic based on user request (Point 4)
        if diff_mins <= 60:
            approved_hrs = 1.0
            lop_hrs = 0.0
        elif diff_mins <= 120:
            approved_hrs = 2.0
            lop_hrs = 0.0
        else:
            approved_hrs = 2.0
            lop_hrs = (diff_mins - 120.0) / 60.0

        # Check for duplicate FIRST before modifying user balance
        duplicate_perm = db.query(models.EmpPermission).filter(
            func.lower(func.trim(models.EmpPermission.emp_id)) == target_emp_id.lower(),
            models.EmpPermission.date == p_date,
            func.lower(func.trim(models.EmpPermission.status)).in_(["pending", "approved"])
        ).first()
        if duplicate_perm:
            raise HTTPException(status_code=400,
                                detail=f"Permission already applied for {request.date}.")

        # Now update remaining_perm
        curr_val = str(user.remaining_perm or "0").strip()
        try:
            curr_perm = float(curr_val) if curr_val else 0.0
        except:
            curr_perm = 0.0

        new_remaining = max(0.0, curr_perm - approved_hrs)
        user.remaining_perm = str(round(new_remaining, 2))

        total_hrs_val = diff_mins / 60.0

        new_perm = models.EmpPermission(
            emp_id=user.emp_id,
            date=p_date,
            f_time=f_time_dt.time(),
            t_time=t_time_dt.time(),
            reason=request.reason,
            total_hours=f"{total_hrs_val:.2f}",
            dis_total_hours=f"{lop_hrs:.2f}",
            available_hours=str(round(new_remaining, 2)),
            status="Pending",
            applied_date=datetime.now().strftime("%d-%b-%Y"),
            permitted_permission=str(round(approved_hrs, 2)),
            lop_hours=str(round(lop_hrs, 2)),
            creation_date=datetime.now(),
            last_update_date=datetime.now()
        )
        db.add(new_perm)
        db.commit()
        db.refresh(new_perm)
        print(f"   Success: Inserted permission {new_perm.p_id}")

        if user and user.manager_id:
            manager = db.query(models.EmpDet).filter(
                func.trim(models.EmpDet.emp_id) == user.manager_id.strip()).first()
            if manager and manager.p_mail:
                subject = f"ITS - {user.name} - Permission Request | {request.date} | {request.f_time} to {request.t_time}"

                # Format time nicely for email display
                try:
                    f_display = f_time_dt.strftime("%I:%M %p").lstrip('0')
                    t_display = t_time_dt.strftime("%I:%M %p").lstrip('0')
                except:
                    f_display = request.f_time
                    t_display = request.t_time

                content = f"""
                <p>Good Day!</p>
                <p>I hope this mail finds you well.</p>
                <p>I would like to request permission on <strong>{request.date}</strong> from <strong>{f_display}</strong> to <strong>{t_display}</strong>.</p>
                <p><strong>Reason:</strong> {request.reason}</p>
                <p>Thank you for considering my request. Looking forward to your approval.</p>
                """
                body = get_email_template(manager.name, "Permission Request", content, user.name)
                background_tasks.add_task(send_email_notification, manager.p_mail, subject, body)

        return {"message": "Permission applied successfully", "p_id": new_perm.p_id}
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database Error: {str(e)}")


@app.post("/admin/approve-permission")
def approve_permission(request: schemas.PermissionApprovalAction, background_tasks: BackgroundTasks,
                       db: Session = Depends(get_db)):
    perm = db.query(models.EmpPermission).filter(
        models.EmpPermission.p_id == request.p_id).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission request not found")
    old_status = perm.status
    perm.status = request.action
    perm.remarks = request.remarks
    perm.last_update_date = datetime.now()
    admin_user = db.query(models.EmpDet).filter(
        models.EmpDet.emp_id == request.admin_id.strip()).first()
    if admin_user:
        perm.remarks = f"{(request.remarks or '')} (Action by: {admin_user.name})".strip()
        perm.approved_by = admin_user.name
    if request.action == 'Rejected' and old_status != 'Rejected':
        user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == perm.emp_id).first()
        if user:
            try:
                if perm.f_time and perm.t_time:
                    h1, m1 = perm.f_time.hour, perm.f_time.minute
                    h2, m2 = perm.t_time.hour, perm.t_time.minute
                    diff = (h2 * 60 + m2) - (h1 * 60 + m1)
                    if diff < 0: diff += 24 * 60
                    approved_to_refund = min(diff / 60.0, 2.0)
                else:
                    approved_to_refund = 0.0
                curr_perm = float(user.remaining_perm or 0)
                user.remaining_perm = str(curr_perm + approved_to_refund)
            except Exception as e:
                print(f"Refund error: {e}")
    db.commit()
    try:
        emp_user = db.query(models.EmpDet).filter(
            func.lower(func.trim(models.EmpDet.emp_id)) == perm.emp_id.strip().lower()
        ).first()
        if emp_user and emp_user.p_mail:
            status_msg = request.action  # 'Approved' or 'Rejected'
            perm_date = perm.date.strftime("%d-%b-%Y") if perm.date else "N/A"
            manager_name = admin_user.name if admin_user else "Manager"
            f_time_str = perm.f_time.strftime("%I:%M %p").lstrip('0') if perm.f_time else "N/A"
            t_time_str = perm.t_time.strftime("%I:%M %p").lstrip('0') if perm.t_time else "N/A"

            subject = f"ITS - Permission Request {status_msg} - {perm_date}"

            if status_msg.lower() == "approved":
                action_line = f"I am pleased to inform you that your permission request on <strong>{perm_date}</strong> from <strong>{f_time_str}</strong> to <strong>{t_time_str}</strong> has been <strong style='color:#10B981;'>Approved</strong>."
            else:
                action_line = f"We regret to inform you that your permission request on <strong>{perm_date}</strong> from <strong>{f_time_str}</strong> to <strong>{t_time_str}</strong> has been <strong style='color:#EF4444;'>Rejected</strong>."

            content = f"""
            <p>Good Day!</p>
            <p>I hope this mail finds you well.</p>
            <p>{action_line}</p>
            {f'<p><strong>Remarks:</strong> {request.remarks}</p>' if request.remarks else ''}
            <p>Please reach out if you have any questions.</p>
            """
            body = get_email_template(emp_user.name, f"Permission Request {status_msg}", content, manager_name)
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
    except Exception as e:
        print(f" Email notification failed: {e}")
    return {"message": f"Permission {request.action.lower()} successfully"}


@app.get("/admin/pending-ot")
def get_pending_ot(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.OverTimeDet, models.EmpDet).outerjoin(
        models.EmpDet,
        func.lower(func.trim(models.OverTimeDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
    ).filter(func.lower(models.OverTimeDet.status) == "pending")
    if manager_id:
        query = query.filter(
            func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    pending = query.order_by(models.OverTimeDet.creation_date.desc()).all()
    results = []
    for ot, emp in pending:
        results.append({
            "ot_id": ot.ot_id,
            "emp_name": emp.name if emp else f"Unknown ({ot.emp_id})",
            "emp_id": ot.emp_id or "N/A",
            "ot_date": ot.ot_date, "date": ot.ot_date,
            "startTime": ot.from_time, "endTime": ot.to_time,
            "start_time": ot.from_time, "end_time": ot.to_time,
            "duration": ot.duration,
            "reason": ot.reason or "No reason",
            "remarks": ot.remarks or "",
            "status": (ot.status or "Pending").strip().capitalize(),
            "submittedDate": ot.applied_date or (
                ot.creation_date.strftime("%d-%b-%Y") if ot.creation_date else "N/A")
        })
    return results


@app.get("/admin/all-ot-history")
def get_all_ot_history(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.OverTimeDet, models.EmpDet).outerjoin(
        models.EmpDet,
        func.lower(func.trim(models.OverTimeDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
    )
    if manager_id:
        query = query.filter(
            func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    all_ot = query.order_by(models.OverTimeDet.creation_date.desc()).all()
    results = []
    for ot, emp in all_ot:
        results.append({
            "ot_id": ot.ot_id, "emp_name": emp.name if emp else f"Unknown ({ot.emp_id})",
            "emp_id": ot.emp_id or "N/A", "ot_date": ot.ot_date, "date": ot.ot_date,
            "startTime": ot.from_time, "endTime": ot.to_time,
            "start_time": ot.from_time, "end_time": ot.to_time,
            "duration": ot.duration, "reason": ot.reason or "No reason",
            "remarks": ot.remarks or "",
            "status": (ot.status or "Pending").strip().capitalize(),
            "submittedDate": ot.applied_date or (
                ot.creation_date.strftime("%d-%b-%Y") if ot.creation_date else "N/A")
        })
    return results


@app.post("/admin/approve-ot")
def approve_ot(request: schemas.OverTimeApprovalAction, background_tasks: BackgroundTasks,
               db: Session = Depends(get_db)):
    ot = db.query(models.OverTimeDet).filter(models.OverTimeDet.ot_id == request.ot_id).first()
    if not ot:
        raise HTTPException(status_code=404, detail="OT request not found")
    ot.status = request.action
    ot.remarks = request.remarks
    ot.last_update_date = datetime.now()
    ot.approved_date = datetime.now().strftime("%d-%b-%Y")
    admin_user = db.query(models.EmpDet).filter(
        models.EmpDet.emp_id == request.admin_id.strip()).first()
    if admin_user:
        ot.approved_by = admin_user.name
        ot.remarks = f"{(request.remarks or '').strip()} (Action by: {admin_user.name})".strip()
    db.commit()
    try:
        emp_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == ot.emp_id).first()
        if emp_user and emp_user.p_mail:
            status_msg = request.action.upper()
            color = "#10B981" if request.action.lower() == "approved" else "#EF4444"
            manager_name = admin_user.name if admin_user else "Manager"
            subject = f"OT Request {status_msg} - {ot.ot_date}"
            content = f"""
            <p>Your Overtime request has been <strong>{status_msg}</strong>.</p>
            <p><strong>Date:</strong> {ot.ot_date}</p>
            <p><strong>Duration:</strong> {ot.duration}</p>
            <p><strong>Remarks:</strong> {request.remarks or 'N/A'}</p>
            """
            body = get_email_template(emp_user.name, "OT Request Update", content, "HR Team")
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
    except Exception as e:
        print(f" Email notification failed: {e}")
    return {"message": f"OT request {request.action.lower()} successfully"}


@app.get("/admin/pending-wfh")
def get_pending_wfh(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.WFHDet, models.EmpDet).join(
        models.EmpDet,
        func.lower(func.trim(models.WFHDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
    ).filter(models.WFHDet.status == "Pending")
    if manager_id:
        query = query.filter(
            func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    pending = query.order_by(models.WFHDet.creation_date.desc()).all()
    results = []
    for wfh, emp in pending:
        results.append({
            "wfh_id": wfh.wfh_id,
            "emp_name": emp.name or "Unknown",
            "emp_id": emp.emp_id or "N/A",
            "date": wfh.from_date,
            "from_date": wfh.from_date,
            "to_date": wfh.to_date,
            "reason": wfh.reason or "No reason",
            "remarks": "",
            "status": wfh.status or "Pending",
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
                func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
        all_wfh = query.order_by(models.WFHDet.creation_date.desc()).all()
        results = []
        for wfh, emp in all_wfh:
            results.append({
                "wfh_id": wfh.wfh_id,
                "emp_name": emp.name if emp else "Unknown",
                "emp_id": wfh.emp_id,
                "date": wfh.from_date,
                "from_date": wfh.from_date,
                "to_date": wfh.to_date,
                "days": wfh.days,
                "reason": wfh.reason or "No reason",
                "remarks": "",
                "status": wfh.status or "Pending",
                "submittedDate": wfh.creation_date.strftime("%d-%b-%Y") if wfh.creation_date else "N/A"
            })
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/approve-wfh")
def approve_wfh(request: schemas.WFHApprovalAction, background_tasks: BackgroundTasks,
                db: Session = Depends(get_db)):
    wfh = db.query(models.WFHDet).filter(models.WFHDet.wfh_id == request.wfh_id).first()
    if not wfh:
        raise HTTPException(status_code=404, detail="WFH request not found")
    wfh.status = request.action
    wfh.last_update_date = datetime.now()
    admin_user = db.query(models.EmpDet).filter(
        models.EmpDet.emp_id == request.admin_id.strip()).first()
    db.commit()
    try:
        emp_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == wfh.emp_id).first()
        if emp_user and emp_user.p_mail:
            status_msg = request.action.upper()
            color = "#10B981" if request.action.lower() == "approved" else "#EF4444"
            manager_name = admin_user.name if admin_user else "Manager"
            subject = f"WFH Request {status_msg} - {wfh.from_date}"
            content = f"""
            <p>Your Work From Home request has been <strong>{status_msg}</strong>.</p>
            <p><strong>Duration:</strong> {wfh.from_date} to {wfh.to_date}</p>
            <p><strong>Remarks:</strong> {request.remarks or 'N/A'}</p>
            """
            body = get_email_template(emp_user.name, "WFH Request Update", content, "HR Team")
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
    except Exception as e:
        print(f" Email notification failed: {e}")
    return {"message": f"WFH request {request.action.lower()} successfully"}


@app.get("/wfh-stats/{emp_id}")
def get_wfh_stats(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    wfh_records = db.query(models.WFHDet).filter(
        func.lower(func.trim(models.WFHDet.emp_id)) == emp_id.lower()).all()
    total_wfh = len(wfh_records)
    approved_wfh = sum(1 for r in wfh_records if r.status and r.status.lower() == 'approved')
    rejected_wfh = sum(1 for r in wfh_records if r.status and r.status.lower() == 'rejected')
    return {"total": total_wfh, "approved": approved_wfh, "rejected": rejected_wfh}


# FIX: Only ONE apply-wfh route (duplicate removed, kept the more complete version)
@app.post("/apply-wfh")
def apply_wfh(request: schemas.WFHApplyRequest, background_tasks: BackgroundTasks,
              db: Session = Depends(get_db)):
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
            if not row_from or not row_to:
                continue
            assert row_from is not None
            assert row_to is not None
            if not (req_to < row_from or req_from > row_to):
                raise HTTPException(
                    status_code=400,
                    detail=f"WFH already applied for overlapping dates ({row.from_date} to {row.to_date})."
                )

        print(f" WFH Apply: emp={clean_emp_id} from={from_date} to={to_date} days={days_val}")

        submitter = db.query(models.EmpDet).filter(
            func.lower(func.trim(models.EmpDet.emp_id)) == clean_emp_id.lower()
        ).first()
        normalized_status = (request.status or "Pending").strip() or "Pending"
        if normalized_status.lower() == "pending":
            normalized_status = "Pending"

        new_wfh = models.WFHDet(
            emp_id=clean_emp_id,
            from_date=from_date,
            to_date=to_date,
            days=days_val,
            reason=request.reason,
            status=normalized_status,
            created_by=clean_emp_id,
            creation_date=datetime.now(),
            last_updated_by=clean_emp_id,
            last_update_date=datetime.now(),
            last_update_login=clean_emp_id
        )
        db.add(new_wfh)
        db.commit()
        db.refresh(new_wfh)
        print(f" WFH inserted: ID={new_wfh.wfh_id}")

        user = submitter
        if user and user.manager_id:
            manager_id_clean = user.manager_id.strip()
            manager = db.query(models.EmpDet).filter(
                func.lower(func.trim(models.EmpDet.emp_id)) == manager_id_clean.lower()).first()
            if manager and manager.p_mail:
                try:
                    from_dt = parse_date(from_date)
                    to_dt = parse_date(to_date)
                    from_str = from_dt.strftime("%d-%b-%Y") if from_dt else from_date
                    to_str = to_dt.strftime("%d-%b-%Y") if to_dt else to_date
                except:
                    from_str = from_date
                    to_str = to_date
                customer_name = user.attribute3 if user.attribute3 else "Internal"
                subject = f"ITS - {user.name}  {customer_name} - WFH | {from_str} to {to_str} ({days_val} Days)"
                content = f"""
                <p>An employee has requested to work from home. Details below:</p>
                <div style="font-size: 18px; font-weight: 700; color: #4f46e5; margin: 20px 0;">
                    WFH Request: {from_str} to {to_str}<br>
                    <span style="font-size: 14px; font-weight: 500; color: #64748b;">Duration: {days_val} Days</span>
                </div>
                <p><strong>Employee:</strong> {user.name}</p>
                <p><strong>Reason:</strong> {request.reason}</p>
                <p style="margin-top: 25px;">Please check the admin portal for more details.</p>
                """
                body = get_email_template(manager.name, "Work From Home Request", content, user.name)
                background_tasks.add_task(send_email_notification, manager.p_mail, subject, body)
        return {"message": "WFH request submitted successfully", "wfh_id": new_wfh.wfh_id}
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        print(f" WFH INSERT ERROR: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# --- CLIENT MODULE ENDPOINTS MOVED TO END ---



@app.get("/wfh-history/{emp_id}")
def get_wfh_history(emp_id: str, db: Session = Depends(get_db)):
    history = db.query(models.WFHDet).filter(
        func.lower(func.trim(models.WFHDet.emp_id)) == emp_id.lower()
    ).order_by(models.WFHDet.wfh_id.desc()).all()
    return [{"id": r.wfh_id,
             "date": r.from_date,
             "to_date": r.to_date,
             "days": r.days,
             "reason": r.reason,
             "status": r.status,
             "submittedDate": r.creation_date.strftime("%Y-%m-%d") if r.creation_date else "N/A"}
            for r in history]


@app.get("/permission-stats/{emp_id}")
def get_permission_stats(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    user = db.query(models.EmpDet).filter(
        func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
    if not user:
        return {"total": 0, "remaining": 0}
    try:
        total = float(user.permission or 0)
        remaining = float(user.remaining_perm or 0)
    except:
        total = 0
        remaining = 0
    return {"total": total, "remaining": remaining}


@app.get("/permission-history/{emp_id}")
def get_permission_history(emp_id: str, db: Session = Depends(get_db)):
    print(f"\n--- FETCH PERMISSION HISTORY: {emp_id} ---")
    emp_id = emp_id.strip().lower()
    history = db.query(models.EmpPermission).filter(
        func.lower(func.trim(models.EmpPermission.emp_id)) == emp_id
    ).order_by(models.EmpPermission.p_id.desc()).all()
    print(f"   Found {len(history)} records")
    return [{
        "p_id": row.p_id, "emp_id": row.emp_id,
        "date": row.date.strftime("%d-%b-%Y") if hasattr(row.date, 'strftime') else (row.date or ""),
        "f_time": format_time_safe(row.f_time),
        "t_time": format_time_safe(row.t_time),
        "total_hours": row.total_hours, "dis_total_hours": row.dis_total_hours,
        "reason": row.reason, "status": row.status, "remarks": row.remarks,
        "creation_date": row.creation_date, "last_update_date": row.last_update_date
    } for row in history]


@app.get("/dashboard/{emp_id}", response_model=schemas.DashboardResponse)
def get_dashboard(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    user = db.query(models.EmpDet).filter(
        func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
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
                if h_date_flat.month == today.month and h_date_flat.year == today.year:
                    show_h = True
                elif 0 <= (h_date_flat - today_flat).days <= 90:
                    show_h = True
                else:
                    show_h = False

                if show_h:
                    upcoming_events.append({
                        "id": f"holiday_{h.holiday_id}",
                        "name": h.Holiday_Name,
                        "type": "holiday",
                        "date": h_date.strftime("%d %b"),
                        "day": h_date.strftime("%A"),
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

                if this_year_bday_flat.month == today.month or (
                        0 <= (this_year_bday_flat - today_flat).days <= 60):
                    upcoming_events.append({
                        "id": f"bday_{emp.emp_id}_{this_year_bday.strftime('%Y%m%d')}",
                        "name": f"{emp.name}'s Birthday", "type": "birthday",
                        "date": this_year_bday.strftime("%d %b"),
                        "day": this_year_bday.strftime("%A"),
                        "raw_date": this_year_bday_flat
                    })

        if emp.date_of_joining:
            join_date = parse_date(emp.date_of_joining)
            if join_date:
                this_anniv = join_date.replace(year=today.year)
                this_anniv_flat = this_anniv.replace(hour=0, minute=0, second=0, microsecond=0)

                if this_anniv_flat.month == today.month or (
                        0 <= (this_anniv_flat - today_flat).days <= 60):
                    upcoming_events.append({
                        "id": f"anniv_{emp.emp_id}_{this_anniv.strftime('%Y%m%d')}",
                        "name": f"{emp.name}'s Anniversary", "type": "anniversary",
                        "date": this_anniv.strftime("%d %b"),
                        "day": this_anniv.strftime("%A"),
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
        func.lower(func.trim(models.EmpDet.manager_id)) == emp_id.lower()
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
                    "time": leave.creation_date.strftime(
                        "%Y-%m-%d %H:%M") if leave.creation_date else "",
                    "type": "alert", "icon": "mail-unread-outline"
                })
            pending_perms = db.query(models.EmpPermission, models.EmpDet.name) \
                .join(models.EmpDet, models.EmpPermission.emp_id == models.EmpDet.emp_id) \
                .filter(models.EmpPermission.status == 'Pending') \
                .order_by(models.EmpPermission.creation_date.desc()).limit(5).all()
            for perm, name in pending_perms:
                notifications.append({
                    "id": f"admin_perm_{perm.p_id}", "title": "New Permission Request",
                    "message": f"{name} requested permission for {perm.total_hours}",
                    "time": perm.creation_date.strftime(
                        "%Y-%m-%d %H:%M") if perm.creation_date else "",
                    "type": "alert", "icon": "time-outline"
                })
        except Exception as e:
            print(f"Error fetching admin notifications: {e}")
    elif is_manager:
        try:
            pending_leaves = db.query(models.EmpLeave, models.EmpDet.name) \
                .join(models.EmpDet, models.EmpLeave.emp_id == models.EmpDet.emp_id) \
                .filter(models.EmpLeave.status == 'Pending') \
                .filter(func.lower(func.trim(models.EmpDet.manager_id)) == emp_id.lower()) \
                .order_by(models.EmpLeave.creation_date.desc()).limit(5).all()
            for leave, name in pending_leaves:
                notifications.append({
                    "id": f"mgr_leave_{leave.l_id}", "title": "New Leave Request (Team)",
                    "message": f"{name} applied for {leave.leave_type} ({leave.days} days)",
                    "time": leave.creation_date.strftime(
                        "%Y-%m-%d %H:%M") if leave.creation_date else "",
                    "type": "alert", "icon": "mail-unread-outline"
                })
            pending_perms = db.query(models.EmpPermission, models.EmpDet.name) \
                .join(models.EmpDet, models.EmpPermission.emp_id == models.EmpDet.emp_id) \
                .filter(models.EmpPermission.status == 'Pending') \
                .filter(func.lower(func.trim(models.EmpDet.manager_id)) == emp_id.lower()) \
                .order_by(models.EmpPermission.creation_date.desc()).limit(5).all()
            for perm, name in pending_perms:
                notifications.append({
                    "id": f"mgr_perm_{perm.p_id}", "title": "New Permission Request (Team)",
                    "message": f"{name} requested permission for {perm.total_hours}",
                    "time": perm.creation_date.strftime(
                        "%Y-%m-%d %H:%M") if perm.creation_date else "",
                    "type": "alert", "icon": "time-outline"
                })

            pending_wfh = db.query(models.WFHDet, models.EmpDet.name) \
                .join(models.EmpDet, models.WFHDet.emp_id == models.EmpDet.emp_id) \
                .filter(models.WFHDet.status == 'Pending') \
                .filter(func.lower(func.trim(models.EmpDet.manager_id)) == emp_id.lower()) \
                .order_by(models.WFHDet.creation_date.desc()).limit(5).all()
            for wfh, name in pending_wfh:
                notifications.append({
                    "id": f"mgr_wfh_{wfh.wfh_id}", "title": "New WFH Request (Team)",
                    "message": f"{name} requested WFH for {wfh.from_date}",
                    "time": wfh.creation_date.strftime(
                        "%Y-%m-%d %H:%M") if wfh.creation_date else "",
                    "type": "alert", "icon": "home-outline"
                })

            pending_ots = db.query(models.OverTimeDet, models.EmpDet.name) \
                .join(models.EmpDet, func.lower(func.trim(models.OverTimeDet.emp_id)) == func.lower(
                func.trim(models.EmpDet.emp_id))) \
                .filter(func.lower(models.OverTimeDet.status) == 'pending') \
                .filter(func.lower(func.trim(models.EmpDet.manager_id)) == emp_id.lower()) \
                .order_by(models.OverTimeDet.creation_date.desc()).limit(5).all()
            for ot, name in pending_ots:
                notifications.append({
                    "id": f"mgr_ot_{ot.ot_id}", "title": "New OT Request (Team)",
                    "message": f"{name} requested OT for {ot.ot_date}",
                    "time": ot.creation_date.strftime(
                        "%Y-%m-%d %H:%M") if ot.creation_date else "",
                    "type": "alert", "icon": "time-outline"
                })
        except Exception as e:
            print(f"Error fetching manager notifications: {e}")

    if is_admin:
        try:
            pending_wfh_admin = db.query(models.WFHDet, models.EmpDet.name) \
                .join(models.EmpDet, models.WFHDet.emp_id == models.EmpDet.emp_id) \
                .filter(models.WFHDet.status == 'Pending') \
                .order_by(models.WFHDet.creation_date.desc()).limit(5).all()
            for wfh, name in pending_wfh_admin:
                if not any(n["id"] == f"mgr_wfh_{wfh.wfh_id}" for n in notifications):
                    notifications.append({
                        "id": f"admin_wfh_{wfh.wfh_id}", "title": "New WFH Request",
                        "message": f"{name} requested WFH for {wfh.from_date}",
                        "time": wfh.creation_date.strftime(
                            "%Y-%m-%d %H:%M") if wfh.creation_date else "",
                        "type": "alert", "icon": "home-outline"
                    })
        except Exception as e:
            print(f"Error fetching admin wfh notifications: {e}")

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
                "time": leave.last_update_date.strftime(
                    "%Y-%m-%d %H:%M") if leave.last_update_date else "",
                "type": "success" if leave.status == 'Approved' else "error",
                "icon": "checkmark-circle-outline" if leave.status == 'Approved' else "close-circle-outline"
            })
        my_perm_updates = db.query(models.EmpPermission) \
            .filter(models.EmpPermission.emp_id == emp_id) \
            .filter(models.EmpPermission.status.in_(['Approved', 'Rejected'])) \
            .filter(models.EmpPermission.last_update_date >= recent_date_limit) \
            .order_by(models.EmpPermission.last_update_date.desc()).limit(5).all()
        for perm in my_perm_updates:
            notifications.append({
                "id": f"perm_{perm.p_id}", "screen": "/AdminPermission?tab=myApproval",
                "title": f"Permission {perm.status}",
                "message": f"Your permission request for {perm.date.strftime('%d-%b-%Y') if perm.date else ''} was {perm.status}",
                "time": perm.last_update_date.strftime(
                    "%Y-%m-%d %H:%M") if perm.last_update_date else "",
                "type": "success" if perm.status == 'Approved' else "error",
                "icon": "time-outline"
            })

        my_wfh_updates = db.query(models.WFHDet) \
            .filter(models.WFHDet.emp_id == emp_id) \
            .filter(models.WFHDet.status.in_(['Approved', 'Rejected'])) \
            .filter(models.WFHDet.last_update_date >= recent_date_limit) \
            .order_by(models.WFHDet.last_update_date.desc()).limit(5).all()
        for wfh in my_wfh_updates:
            notifications.append({
                "id": f"emp_wfh_{wfh.wfh_id}", "title": f"WFH {wfh.status}",
                "message": f"Your WFH request for {wfh.from_date} was {wfh.status}",
                "time": wfh.last_update_date.strftime(
                    "%Y-%m-%d %H:%M") if wfh.last_update_date else "",
                "type": "success" if wfh.status == 'Approved' else "error",
                "icon": "home-outline"
            })

        my_ot_updates = db.query(models.OverTimeDet) \
            .filter(func.lower(func.trim(models.OverTimeDet.emp_id)) == emp_id.lower()) \
            .filter(models.OverTimeDet.status.in_(['Approved', 'Rejected', 'approved', 'rejected'])) \
            .filter(models.OverTimeDet.last_update_date >= recent_date_limit) \
            .order_by(models.OverTimeDet.last_update_date.desc()).limit(5).all()
        for ot in my_ot_updates:
            notifications.append({
                "id": f"emp_ot_{ot.ot_id}", "title": f"OT {ot.status}",
                "message": f"Your OT request for {ot.ot_date} was {ot.status}",
                "time": ot.last_update_date.strftime(
                    "%Y-%m-%d %H:%M") if ot.last_update_date else "",
                "type": "success" if ot.status.lower() == 'approved' else "error",
                "icon": "time-outline"
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

        print(f"Fetching birthdays for month: {current_month}")

        all_emps = db.query(models.EmpDet).all()

        birthdays = []
        for emp in all_emps:
            is_active = False
            if emp.end_date is None or str(emp.end_date).strip() == "" or str(
                    emp.end_date).lower() == "none":
                is_active = True

            if is_active and emp.dob and emp.name:
                dob = parse_date(emp.dob)
                if dob and dob.month == current_month:
                    display_date = f"{dob.day:02d}-{dob.strftime('%b')}-{current_year}"
                    birthdays.append({
                        "emp_id": emp.emp_id,
                        "name": emp.name,
                        "display_dob": display_date,
                        "original_dob": str(emp.dob),
                        "day": dob.day
                    })

        birthdays.sort(key=lambda x: x["day"])
        print(f"Found {len(birthdays)} birthdays this month")
        return birthdays
    except Exception as e:
        print(f"Error in get_birthdays_this_month: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/timesheet-month/{emp_id}", response_model=List[schemas.TimesheetResponse])
def get_timesheet_month(emp_id: str, month: Optional[str] = None, year: Optional[str] = None,
                        db: Session = Depends(get_db)):
    from sqlalchemy import or_, func
    clean_id = emp_id.replace(" ", "")
    query = db.query(models.TimesheetDet).filter(
        or_(
            models.TimesheetDet.emp_id == emp_id,
            func.replace(models.TimesheetDet.emp_id, " ", "") == clean_id
        )
    )
    if month:
        month_map = {
            "January": "01", "February": "02", "March": "03", "April": "04",
            "May": "05", "June": "06", "July": "07", "August": "08",
            "September": "09", "October": "10", "November": "11", "December": "12"
        }
        m_num = month_map.get(month)
        if m_num:
            query = query.filter(or_(
                models.TimesheetDet.month.ilike(f"%{month}%"),
                models.TimesheetDet.month.ilike(f"%{m_num}%"),
                models.TimesheetDet.date.ilike(f"%-{month[:3]}-%")
            ))
        else:
            query = query.filter(models.TimesheetDet.month.ilike(f"%{month}%"))
    if year:
        query = query.filter(models.TimesheetDet.date.ilike(f"%{year}%"))
    return query.all()


@app.get("/admin/timesheet-employees", response_model=List[schemas.AdminTimesheetEmpResponse])
def get_admin_timesheet_employees(month: Optional[str] = None, year: Optional[str] = None,
                                  db: Session = Depends(get_db)):
    ts_query = db.query(models.TimesheetDet.emp_id)
    month_filter = None
    if month:
        month_map = {
            "January": "01", "February": "02", "March": "03", "April": "04",
            "May": "05", "June": "06", "July": "07", "August": "08",
            "September": "09", "October": "10", "November": "11", "December": "12"
        }
        m_num = month_map.get(month)
        if m_num:
            month_filter = or_(
                models.TimesheetDet.month.ilike(f"%{month}%"),
                models.TimesheetDet.month.ilike(f"%{m_num}%"),
                models.TimesheetDet.date.ilike(f"%-{month[:3]}-%")
            )
        else:
            month_filter = models.TimesheetDet.month.ilike(f"%{month}%")
    if month_filter is not None:
        ts_query = ts_query.filter(month_filter)
    if year:
        ts_query = ts_query.filter(models.TimesheetDet.date.ilike(f"%{year}%"))
    ts_results = ts_query.distinct().all()
    emp_ids = [r.emp_id for r in ts_results]
    if not emp_ids:
        return []
    clean_ids = [eid.replace(" ", "") for eid in emp_ids]
    employees = db.query(models.EmpDet).all()
    matched_employees = [e for e in employees if
                         e.emp_id and e.emp_id.replace(" ", "") in clean_ids]
    pending_query = db.query(
        models.TimesheetDet.emp_id,
        func.count(models.TimesheetDet.t_id).label('pending_count')
    ).filter(models.TimesheetDet.status.ilike('Pending'))
    if month_filter is not None:
        pending_query = pending_query.filter(month_filter)
    if year:
        pending_query = pending_query.filter(models.TimesheetDet.date.ilike(f"%{year}%"))
    pending_results = pending_query.group_by(models.TimesheetDet.emp_id).all()
    pending_map = {}
    for r in pending_results:
        cid = r.emp_id.replace(" ", "")
        pending_map[cid] = pending_map.get(cid, 0) + r.pending_count
    results = []
    for emp in matched_employees:
        domain_name = "Employee"
        if emp.dom_id:
            domain = db.query(models.Domain).filter(models.Domain.dom_id == emp.dom_id).first()
            if domain:
                domain_name = domain.domain
        cid = emp.emp_id.replace(" ", "")
        results.append({
            "id": emp.emp_id, "name": emp.name or "Unknown",
            "department": domain_name, "requests": pending_map.get(cid, 0)
        })
    return results


@app.get("/holidays")
def get_holidays(db: Session = Depends(get_db)):
    current_year = datetime.now().year
    holidays = db.query(models.HolidayDet).filter(models.HolidayDet.year == current_year).all()
    results = []
    for h in holidays:
        results.append({
            "id": h.holiday_id,
            "date": h.Office_Holiday_Date,
            "name": h.Holiday_Name,
            "year": h.year,
            "month": h.Month
        })
    return results


@app.post("/admin/timesheet/action")
def timesheet_action(action_req: schemas.TimesheetApprovalAction, background_tasks: BackgroundTasks,
                     db: Session = Depends(get_db)):
    ts = db.query(models.TimesheetDet).filter(
        models.TimesheetDet.t_id == action_req.t_id).first()
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
            status_msg = action_req.action.upper()
            color = "green" if action_req.action.lower() == "approved" else "red"
            admin_user = db.query(models.EmpDet).filter(
                models.EmpDet.emp_id == action_req.admin_id.strip()).first()
            manager_name = admin_user.name if admin_user else "Manager"
            subject = f"Timesheet {status_msg} - {ts.date}"
            body = f"""
            <html><body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                <h3>Timesheet Update</h3>
                <p>Dear {emp_user.name},</p>
                <p>Your Timesheet for <strong>{ts.date}</strong> ({ts.project or 'N/A'}) has been <strong style="color: {color};">{status_msg}</strong>.</p>
                <p><strong>Remarks:</strong> {action_req.remarks or 'N/A'}</p>
                <p><strong>Action By:</strong> {manager_name}</p>
                <br><p>Thanks & Regards,<br>Ilan Tech Solutions</p>
            </body></html>
            """
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
    except Exception as e:
        print(f" Email notification failed: {e}")
    return {"message": f"Timesheet {action_req.action} successfully"}


@app.get("/admin/projects/next-ref")
def get_next_project_ref(db: Session = Depends(get_db)):
    import re
    all_refs = db.query(models.Project.project_ref_no).all()
    max_num = 0
    prefix = "ITS-PRO-"
    
    for (ref_no,) in all_refs:
        if ref_no and ref_no.startswith(prefix):
            try:
                # Extract number using regex to be safe
                match = re.search(r'(\d+)', ref_no[len(prefix):])
                if match:
                    num = int(match.group(1))
                    if num > max_num:
                        max_num = num
            except:
                continue
    
    next_num = max_num + 1
    return {"next_ref": f"{prefix}{next_num:04d}"}


@app.get("/admin/projects", response_model=List[schemas.ProjectResponse])
def get_projects(db: Session = Depends(get_db)):
    return db.query(models.Project).all()


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
        project_ref_no=project_req.project_ref_no,
        project_name=project_req.project_name,
        project_type=project_req.project_type,
        team_size=project_req.team_size,
        budget=project_req.budget,
        start_date=project_req.start_date,
        end_date=project_req.end_date,
        project_manager=project_req.project_manager,
        status=project_req.status,
        duration=project_req.duration,
        description=project_req.description,
        client_ref_no=project_req.client_ref_no,
        attribute1=project_req.attribute1 or "",
        attribute2=project_req.attribute2 or "",
        attribute3=project_req.attribute3 or "",
        attribute4=project_req.attribute4 or "",
        attribute5=project_req.attribute5 or "",
        attribute6=project_req.attribute6 or "",
        attribute7=project_req.attribute7 or "",
        attribute8=project_req.attribute8 or "",
        attribute9=project_req.attribute9 or "",
        attribute10=project_req.attribute10 or "",
        attribute11=project_req.attribute11 or "",
        attribute12=project_req.attribute12 or "",
        attribute13=project_req.attribute13 or "",
        attribute14=project_req.attribute14 or "",
        attribute15=project_req.attribute15 or "",
        creation_date=now,
        dom_id=project_req.dom_id,
        last_update_date=now,
        created_by=project_req.created_by,
        last_updated_by=project_req.created_by or "Admin",
        last_update_login=project_req.created_by or "Admin",
        files=project_req.files,
        project_priority=project_req.project_priority
    )
    db.add(new_project)
    db.commit()
    db.refresh(new_project)
    return new_project


@app.put("/admin/projects/{pro_id}", response_model=schemas.ProjectResponse)
def update_project(pro_id: int, project_req: schemas.ProjectCreateRequest,
                   db: Session = Depends(get_db)):
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
    project.attribute1 = project_req.attribute1
    project.attribute2 = project_req.attribute2
    project.attribute3 = project_req.attribute3
    project.attribute4 = project_req.attribute4
    project.attribute5 = project_req.attribute5
    project.attribute6 = project_req.attribute6
    project.attribute7 = project_req.attribute7
    project.attribute8 = project_req.attribute8
    project.attribute9 = project_req.attribute9
    project.attribute10 = project_req.attribute10
    project.attribute11 = project_req.attribute11
    project.attribute12 = project_req.attribute12
    project.attribute13 = project_req.attribute13
    project.attribute14 = project_req.attribute14
    project.attribute15 = project_req.attribute15
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
    import re
    emp_id = emp_id.strip()
    ot_records = db.query(models.OverTimeDet).filter(
        func.lower(func.trim(models.OverTimeDet.emp_id)) == emp_id.lower()).all()
    total_ot = 0.0
    approved_ot = 0.0

    def parse_duration(duration_str):
        if not duration_str: return 0.0
        duration_str = str(duration_str).strip()
        try:
            return float(duration_str)
        except ValueError:
            pass
        hr_match = re.search(r'(\d+)\s*(h|hr)', duration_str, re.IGNORECASE)
        min_match = re.search(r'(\d+)\s*(m|min)', duration_str, re.IGNORECASE)
        if hr_match or min_match:
            hours = float(hr_match.group(1)) if hr_match else 0.0
            minutes = float(min_match.group(1)) if min_match else 0.0
            return hours + (minutes / 60.0)
        if ':' in duration_str:
            parts = duration_str.split(':')
            if len(parts) == 2:
                try:
                    return float(parts[0]) + float(parts[1]) / 60.0
                except:
                    pass
        return 0.0

    for row in ot_records:
        try:
            d = parse_duration(row.duration or "0")
            total_ot += d
            if row.status and row.status.lower() == 'approved':
                approved_ot += d
        except Exception as e:
            continue
    return {"total": round(total_ot, 2), "approved": round(approved_ot, 2)}


@app.get("/ot-history/{emp_id}")
def get_ot_history(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    return db.query(models.OverTimeDet).filter(
        func.lower(func.trim(models.OverTimeDet.emp_id)) == emp_id.lower()
    ).order_by(models.OverTimeDet.ot_id.desc()).all()


@app.get("/admin/roles", response_model=List[schemas.RoleResponse])
def get_roles(db: Session = Depends(get_db)):
    return db.query(models.Role).all()


@app.get("/admin/departments", response_model=List[schemas.DepartmentResponse])
def get_departments(dpt_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.Department)
    if dpt_id:
        # Cast to int for safety
        ids = [int(i.strip()) for i in dpt_id.split(",") if i.strip().isdigit()]
        query = query.filter(models.Department.dpt_id.in_(ids))
    return query.all()


@app.get("/admin/domains", response_model=List[schemas.DomainResponse])
def get_domains(dom_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.Domain)
    if dom_id:
        # Cast to int for safety
        ids = [int(i.strip()) for i in dom_id.split(",") if i.strip().isdigit()]
        query = query.filter(models.Domain.dom_id.in_(ids))
    return query.all()


@app.get("/admin/employees/brief", response_model=List[schemas.EmployeeBriefResponse])
def get_employees_brief(db: Session = Depends(get_db)):
    # Include role_id, dpt_id, dom_id for frontend filtering
    employees = db.query(models.EmpDet.emp_id, models.EmpDet.name, models.EmpDet.role_id, models.EmpDet.dpt_id, models.EmpDet.dom_id).all()
    return [{"emp_id": e.emp_id, "name": e.name, "role_id": e.role_id, "dpt_id": e.dpt_id, "dom_id": e.dom_id} for e in employees]


@app.get("/admin/projects/{pro_id}/allocations", response_model=List[schemas.ProjectAllocationResponse])
def get_project_allocations(pro_id: int, db: Session = Depends(get_db)):
    allocs = db.query(models.ProjectAllocation).filter(
        models.ProjectAllocation.pro_id == pro_id).all()
    res = []
    for a in allocs:
        # Enrich with names
        emp = db.query(models.EmpDet.name).filter(models.EmpDet.emp_id == a.emp_id).first()
        role = db.query(models.Role.role).filter(models.Role.role_id == a.role_id).first()
        dept = db.query(models.Department.department).filter(
            models.Department.dpt_id == a.dpt_id).first()
        dom = db.query(models.Domain.domain).filter(models.Domain.dom_id == a.dom_id).first()

        res.append(schemas.ProjectAllocationResponse(
            assign_id=a.assign_id,
            emp_id=a.emp_id,
            role_id=a.role_id,
            dom_id=a.dom_id,
            dpt_id=a.dpt_id,
            lead_id=a.lead_id,
            from_date=a.from_date,
            to_date=a.to_date,
            task_description=a.task_description,
            allocation_pct=a.allocation_pct,
            emp_name=emp[0] if emp else "Unknown",
            role_name=role[0] if role else "Unknown",
            dept_name=dept[0] if dept else "Unknown",
            dom_name=dom[0] if dom else "Unknown"
        ))
    return res


@app.post("/admin/projects/{pro_id}/allocations", response_model=schemas.ProjectAllocationResponse)
def create_project_allocation(pro_id: int, alloc_req: schemas.ProjectAllocationCreate, db: Session = Depends(get_db)):
    now = datetime.now()
    new_alloc = models.ProjectAllocation(
        pro_id=pro_id,
        emp_id=alloc_req.emp_id,
        role_id=alloc_req.role_id,
        dom_id=alloc_req.dom_id,
        dpt_id=alloc_req.dpt_id,
        lead_id=alloc_req.lead_id,
        from_date=alloc_req.from_date,
        to_date=alloc_req.to_date,
        task_description=alloc_req.task_description,
        allocation_pct=alloc_req.allocation_pct,
        created_by=alloc_req.created_by,
        creation_date=now,
        last_updated_by=alloc_req.created_by or "Admin",
        last_update_date=now
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
        dept = db.query(models.Department.department).filter(
            models.Department.dpt_id == a.dpt_id).first()
        dom = db.query(models.Domain.domain).filter(models.Domain.dom_id == a.dom_id).first()
        proj = db.query(models.Project.project_name).filter(models.Project.pro_id == a.pro_id).first()

        res.append(schemas.ProjectAllocationResponse(
            assign_id=a.assign_id,
            emp_id=a.emp_id,
            role_id=a.role_id,
            dom_id=a.dom_id,
            dpt_id=a.dpt_id,
            lead_id=a.lead_id,
            from_date=a.from_date,
            to_date=a.to_date,
            task_description=a.task_description,
            allocation_pct=a.allocation_pct,
            emp_name=emp[0] if emp else "Unknown",
            role_name=role[0] if role else "Unknown",
            dept_name=dept[0] if dept else "Unknown",
            dom_name=dom[0] if dom else "Unknown",
            project_name=proj[0] if proj else "Unknown"
        ))
    return res


@app.get("/admin/employees/{emp_id}/allocations", response_model=List[schemas.ProjectAllocationResponse])
def get_employee_allocations(emp_id: str, db: Session = Depends(get_db)):
    allocs = db.query(models.ProjectAllocation).filter(
        models.ProjectAllocation.emp_id == emp_id).all()
    res = []
    for a in allocs:
        emp = db.query(models.EmpDet.name).filter(models.EmpDet.emp_id == a.emp_id).first()
        role = db.query(models.Role.role).filter(models.Role.role_id == a.role_id).first()
        dept = db.query(models.Department.department).filter(
            models.Department.dpt_id == a.dpt_id).first()
        dom = db.query(models.Domain.domain).filter(models.Domain.dom_id == a.dom_id).first()
        proj = db.query(models.Project.project_name).filter(models.Project.pro_id == a.pro_id).first()

        res.append(schemas.ProjectAllocationResponse(
            assign_id=a.assign_id,
            emp_id=a.emp_id,
            role_id=a.role_id,
            dom_id=a.dom_id,
            dpt_id=a.dpt_id,
            lead_id=a.lead_id,
            from_date=a.from_date,
            to_date=a.to_date,
            task_description=a.task_description,
            allocation_pct=a.allocation_pct,
            emp_name=emp[0] if emp else "Unknown",
            role_name=role[0] if role else "Unknown",
            dept_name=dept[0] if dept else "Unknown",
            dom_name=dom[0] if dom else "Unknown",
            project_name=proj[0] if proj else "Unknown"
        ))
    return res

@app.get("/admin/clients/next-ref")
def get_next_client_ref(db: Session = Depends(get_db)):
    clients = db.query(models.CompanyClient).filter(
        models.CompanyClient.client_ref_no.like('ITS-CLI-%')
    ).all()
    
    max_num = 25 # Base number: next will be 26
    import re
    for c in clients:
        if c.client_ref_no:
            match = re.search(r'ITS-CLI-(\d+)$', c.client_ref_no)
            if match:
                num = int(match.group(1))
                if num > max_num:
                    max_num = num
                    
    next_ref = f"ITS-CLI-{max_num + 1:04d}"
    return {"next_ref": next_ref}


@app.get("/admin/clients", response_model=List[schemas.ClientResponse])
def get_clients(db: Session = Depends(get_db)):
    clients = db.query(models.CompanyClient).all()
    res = []
    for c in clients:
        sites = db.query(models.ClientSite).filter(models.ClientSite.client_id == c.cl_id).all()
        sites_list = []
        for s in sites:
            sites_list.append(schemas.ClientSiteSchema(
                site_id=s.site_id,
                client_id=s.client_id,
                gst_pct=s.gst_pct,
                short_code=s.short_code,
                currency=s.currency,
                location=s.location,
                ship_to=s.ship_to,
                status=s.status
            ))

        creation_dt = c.creation_date
        if creation_dt and "0000-00-00" in str(creation_dt):
            creation_dt = None
            
        last_update_dt = c.last_update_date
        if last_update_dt and "0000-00-00" in str(last_update_dt):
            last_update_dt = None

        c_dict = {
            "client_id": c.cl_id,
            "client_ref_no": c.client_ref_no,
            "client_name": c.client_name,
            "mobile_no": c.mobile_no,
            "country_code": c.country_code,
            "email_id": c.email,
            "gst_available": c.gst,
            "gst": c.gst_no,
            "msme_available": c.msme,
            "msme": c.msme_no,
            "pan_no": c.pan,
            "address": c.address,
            "status": c.status or "Active",
            "company_name": c.company_name,
            "website": c.website,
            "short_code": c.short_code,
            "currency": c.currency,
            "gst_value": c.gst_value,
            "attribute_category": c.attribute_category,
            "creation_date": creation_dt,
            "last_update_date": last_update_dt,
            "created_by": c.created_by,
            "last_updated_by": c.last_updated_by,
            "last_update_login": c.last_update_login,
            "attribute1": c.attribute1,
            "attribute2": c.attribute2,
            "attribute3": c.attribute3,
            "attribute4": c.attribute4,
            "attribute5": c.attribute5,
            "attribute6": c.attribute6,
            "attribute7": c.attribute7,
            "attribute8": c.attribute8,
            "attribute9": c.attribute9,
            "attribute10": c.attribute10,
            "attribute11": c.attribute11,
            "attribute12": c.attribute12,
            "attribute13": c.attribute13,
            "attribute14": c.attribute14,
            "sites": sites_list
        }
        res.append(c_dict)
    return res

@app.get("/admin/clients/{client_id}", response_model=schemas.ClientResponse)
def get_client(client_id: int, db: Session = Depends(get_db)):
    client = db.query(models.CompanyClient).filter(models.CompanyClient.cl_id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    sites = db.query(models.ClientSite).filter(models.ClientSite.client_id == client_id).all()
    sites_list = []
    for s in sites:
        sites_list.append(schemas.ClientSiteSchema(
            site_id=s.site_id,
            client_id=s.client_id,
            gst_pct=s.gst_pct,
            short_code=s.short_code,
            currency=s.currency,
            location=s.location,
            ship_to=s.ship_to,
            status=s.status
        ))

    creation_dt = client.creation_date
    if creation_dt and "0000-00-00" in str(creation_dt):
        creation_dt = None
        
    last_update_dt = client.last_update_date
    if last_update_dt and "0000-00-00" in str(last_update_dt):
        last_update_dt = None

    return {
        "client_id": client.cl_id,
        "client_ref_no": client.client_ref_no,
        "client_name": client.client_name,
        "company_name": client.company_name,
        "mobile_no": client.mobile_no,
        "email_id": client.email,
        "gst_available": client.gst,
        "gst": client.gst_no,
        "msme_available": client.msme,
        "msme": client.msme_no,
        "pan_no": client.pan,
        "status": client.status or "Active",
        "website": client.website,
        "short_code": client.short_code,
        "currency": client.currency,
        "address": client.address,
        "sites": sites_list,
        "creation_date": creation_dt,
        "last_update_date": last_update_dt
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
    
    # Sync sites: For simplicity, delete and recreated if provided
    if client_req.sites is not None:
        db.query(models.ClientSite).filter(models.ClientSite.client_id == client_id).delete()
        for s in client_req.sites:
            db.add(models.ClientSite(
                client_id=client_id,
                gst_pct=s.gst_pct,
                short_code=s.short_code,
                currency=s.currency,
                location=s.location,
                ship_to=s.ship_to,
                status=s.status or "Active",
                creation_date=now,
                last_update_date=now,
                created_by="Admin",
                last_updated_by="Admin"
            ))

    db.commit()
    return {"message": "Client updated successfully"}


@app.get("/holiday-dates")
def get_holiday_dates(db: Session = Depends(get_db)):
    holidays = db.query(models.HolidayDet.Office_Holiday_Date).all()
    # Return as a simple list of date strings
    return [h[0] for h in holidays if h[0]]


@app.post("/admin/create-client")
def create_client(client_req: schemas.ClientApplyRequest, db: Session = Depends(get_db)):
    now = datetime.now()
    print(f"DEBUG: Creating new client: {client_req.client_name} (Ref: {client_req.client_ref_no})")
    
    # In case the frontend passes empty client_ref_no despite schema, or we want to overwrite it
    if not client_req.client_ref_no or client_req.client_ref_no.strip() == "":
        last_client = db.query(models.CompanyClient).order_by(models.CompanyClient.cl_id.desc()).first()
        if not last_client or not last_client.client_ref_no:
            client_req.client_ref_no = "CLI-001"
        else:
            ref_no = last_client.client_ref_no
            import re
            match = re.search(r'(\d+)$', ref_no)
            if match:
                num = int(match.group(1)) + 1
                prefix = ref_no[:match.start()]
                client_req.client_ref_no = f"{prefix}{num:03d}"
            else:
                client_req.client_ref_no = f"{ref_no}-1"

    try:
        new_client = models.CompanyClient(
            client_ref_no=client_req.client_ref_no,
            client_name=client_req.client_name,
            company_name=client_req.company_name,
            country_code="",
            mobile_no=client_req.mobile_no or "",
            gst=client_req.gst_available or "No",
            gst_value="",
            gst_no=client_req.gst or "",
            website=client_req.website or "",
            email=client_req.email_id or "",
            msme=client_req.msme_available or "No",
            msme_no=client_req.msme or "",
            pan=client_req.pan_no or "",
            short_code=client_req.short_code or "",
            currency=client_req.currency or "INR",
            address=client_req.address or "",
            status=client_req.status or "Active",
            attribute_category="",
            attribute1="", attribute2="", attribute3="", attribute4="", attribute5="",
            attribute6="", attribute7="", attribute8="", attribute9="", attribute10="",
            attribute11="", attribute12="", attribute13="", attribute14="",
            creation_date=now,
            last_update_date=now,
            created_by="Admin",
            last_updated_by="Admin",
            last_update_login="Admin"
        )
        db.add(new_client)
        db.flush() # Populate the cl_id
        
        print(f"DEBUG: Main client profile added with ID: {new_client.cl_id}")

        if client_req.sites:
            print(f"DEBUG: Adding {len(client_req.sites)} sites for client {new_client.cl_id}")
            for site_req in client_req.sites:
                new_site = models.ClientSite(
                    client_id=new_client.cl_id,
                    client_ref_no=new_client.client_ref_no,
                    gst_pct=site_req.gst_pct,
                    short_code=site_req.short_code,
                    currency=site_req.currency,
                    location=site_req.location,
                    ship_to=site_req.ship_to,
                    status=site_req.status or "Active",
                    creation_date=now,
                    last_update_date=now,
                    created_by="Admin",
                    last_updated_by="Admin",
                    last_update_login="Admin"
                )
                db.add(new_site)
        
        db.commit()
        db.refresh(new_client)
        print(f"SUCCESS: Client and sites created successfully for ID: {new_client.cl_id}")
        return {"message": "Client and sites created successfully", "client_id": new_client.cl_id}
    except Exception as e:
        db.rollback()
        print(f"ERROR: Failed to create client: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=str(e))
