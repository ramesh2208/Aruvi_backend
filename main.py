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

from backend import models, schemas, database
from backend.database import engine

# Create tables if they don't exist
models.Base.metadata.create_all(bind=engine)

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

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

def parse_date(d):
    if not d: return None
    if isinstance(d, datetime): return d
    if isinstance(d, date): return datetime.combine(d, datetime.min.time())
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

@app.post("/login", response_model=schemas.Token)
def login(request: schemas.LoginRequest, db: Session = Depends(get_db)):
    print("\n" + "="*60)
    print("🔐 LOGIN ATTEMPT (DEBUG MODE)")
    print("="*60)

    username_input = request.username.strip().lower()
    input_pwd = request.password.strip()
    print(f"📧 Username input: {username_input}")
    prefix = username_input.split("@")[0] if "@" in username_input else username_input

    user = db.query(models.EmpDet).filter(
        (func.lower(models.EmpDet.p_mail) == username_input) |
        (func.lower(models.EmpDet.mail_id) == username_input) |
        (func.upper(models.EmpDet.emp_id) == prefix.upper()) |
        (func.lower(models.EmpDet.p_mail).like(f"{prefix}%"))
    ).first()

    if not user:
        print(f"❌ User not found for input: {username_input}")
        raise HTTPException(status_code=404, detail="Username Wrong")

    print(f"✅ User FOUND: {user.emp_id} ({user.p_mail})")

    input_md5 = hashlib.md5(input_pwd.encode()).hexdigest()
    print("\n🧪 PASSWORD DEBUG")
    print("Input password:", input_pwd)
    print("Input MD5:", input_md5)
    print("DB attribute15:", user.attribute15)
    print("DB password column:", user.password)

    password_valid = False
    if user.attribute15 and user.attribute15.lower() == input_md5.lower():
        print("✅ Match via attribute15 MD5")
        password_valid = True
    if not password_valid and user.password and user.password.lower() == input_md5.lower():
        print("✅ Match via password column MD5")
        password_valid = True
    if not password_valid and user.password == input_pwd:
        print("✅ Match via PLAINTEXT password")
        password_valid = True
    if not password_valid and user.password and user.attribute15:
        try:
            AES_KEY = b"1234567890abcdef"
            encrypted_bytes = base64.b64decode(user.password)
            iv_bytes = base64.b64decode(user.attribute15)
            if len(iv_bytes) == 16:
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv_bytes)
                decrypted = unpad(cipher.decrypt(encrypted_bytes), 16).decode()
                print("🔓 AES decrypted password:", decrypted)
                if decrypted == input_pwd:
                    print("✅ Match via AES decrypted password")
                    password_valid = True
        except Exception as e:
            print("⚠️ AES decrypt failed:", str(e))

    if not password_valid:
        print("❌ PASSWORD FAILED")
        raise HTTPException(status_code=401, detail="Password Wrong")

    print("✅ PASSWORD VERIFIED")

    is_global_admin = False
    role_type = "Employee"
    if user.dom_id:
        try:
            d_id = int(str(user.dom_id).strip())
            domain_obj = db.query(models.Domain).filter(models.Domain.dom_id == d_id).first()
            if domain_obj and domain_obj.domain:
                if any(x in domain_obj.domain.lower() for x in ["admin","executive","management"]):
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
    print(f"🔐 2FA Enabled: {has_2fa}")
    print(f"🎭 Role: {role_type}, Global Admin: {is_global_admin}, Manager: {is_manager}")
    print("="*60)

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
def forgot_password(request: schemas.ForgotPasswordRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    email = request.email.strip().lower()
    print(f"\n--- 📧 FORGOT PASSWORD ATTEMPT: {email} ---")
    user = db.query(models.EmpDet).filter(func.lower(models.EmpDet.p_mail) == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found in our records")
    print(f" User found: {user.name} (Emp ID: {user.emp_id})")
    otp = ''.join(random.choices(string.digits, k=6))
    otp_store[email] = {"otp": otp, "expires_at": datetime.now() + timedelta(minutes=5)}
    print(f" Generated OTP: {otp}")
    
    body = f"""
    <html>
    <body style="font-family: 'Times New Roman', Times, serif; line-height: 1.6; color: #00008B;">
        <div style="max-width: 600px; margin: auto; padding: 20px;">
            <p>Dear {user.name or 'User'},</p>
            <p>We received a request to change the password for your account.</p>
            <p>To complete this process, please use the One-Time Password (OTP) provided below.</p>
            <p><strong>Your OTP: <span style="font-size: 20px; color: #000;">{otp}</span></strong></p>
            <p>This OTP is valid for 5 minutes and can only be used once.</p>
            <p><strong>Note:</strong></p>
            <ol>
                <li>If you did not request a password change, please contact our support team immediately at <a href="mailto:info@ilantechsolutions.com">info@ilantechsolutions.com</a> or call +91 78459 37740.</li>
                <li>For your security, please do not share this OTP with anyone.</li>
            </ol>
            <p>Thanks & Regards,<br>
            <strong>Ilan Tech Solutions Private Limited</strong><br>
            Website: <a href="http://www.ilantechsolutions.com">www.ilantechsolutions.com</a></p>
        </div>
    </body>
    </html>
    """
    
    background_tasks.add_task(send_email_notification, email, f"ITS - Password Reset Code : {otp} Enclosed", body)
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
        print(f"❌ Fernet decryption error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to decrypt 2FA secret")

class GetAuthKeyRequest(BaseModel):
    p_mail: str

class GetAuthKeyResponse(BaseModel):
    auth_key: str
    auth_timer: int
    p_mail: str

@app.post("/get-user-auth-key", response_model=GetAuthKeyResponse)
def get_user_auth_key(request: GetAuthKeyRequest, db: Session = Depends(get_db)):
    print("\n" + "="*60)
    print("🔐 GET USER AUTH KEY")
    print("="*60)
    p_mail = request.p_mail.strip().lower()
    if not p_mail:
        raise HTTPException(status_code=400, detail="Email is required")
    user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.p_mail)) == p_mail).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.auth_key:
        raise HTTPException(status_code=400, detail="2FA not configured for this user")
    print(f"✅ User found: {user.emp_id}")
    print(f"⏰ Auth Timer: {user.auth_timer}")
    return GetAuthKeyResponse(auth_key=user.auth_key, auth_timer=user.auth_timer or 30, p_mail=user.p_mail)

import time
def verify_authenticator_otp_for_user(user, otp_input: str) -> bool:
    try:
        print("\n==============================")
        print("🔐 2FA VERIFY (DB MODE)")
        print("==============================")
        encrypted_key = user.auth_key
        auth_timer = user.auth_timer or 30
        if not encrypted_key:
            print("❌ No auth_key found")
            return False
        fernet = Fernet(FERNET_KEY.encode())
        secret = fernet.decrypt(encrypted_key.encode()).decode()
        print("✅ Secret decrypted")
        totp = pyotp.TOTP(secret, digits=6, interval=auth_timer)
        now = int(time.time())
        print("⏰ Time:", now)
        print("🔢 Prev:", totp.at(now - auth_timer))
        print("🔢 Curr:", totp.now())
        print("🔢 Next:", totp.at(now + auth_timer))
        otp_clean = otp_input.strip()
        if not otp_clean.isdigit() or len(otp_clean) != 6:
            print("❌ Invalid OTP format")
            return False
        print("📱 Received:", otp_clean)
        ok = totp.verify(otp_clean, valid_window=1)
        print("✅ SUCCESS" if ok else "❌ FAILED")
        return ok
    except Exception as e:
        print("❌ OTP verify error:", str(e))
        return False

@app.post("/verify-2fa")
def verify_2fa(request: schemas.Verify2FARequest, db: Session = Depends(get_db)):
    print("\n" + "="*60)
    print("🔐 2FA VERIFY")
    print("="*60)
    emp_id = request.user_id.strip().upper()
    otp_input = request.totp_code.strip()
    user = db.query(models.EmpDet).filter(func.trim(models.EmpDet.emp_id) == emp_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.auth_key:
        raise HTTPException(status_code=400, detail="2FA not configured")
    print(f"✅ User: {user.emp_id}")
    ok = verify_authenticator_otp_for_user(user, otp_input)
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid Authenticator code")
    print("✅ 2FA SUCCESS")
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
    del otp_store[email]
    return {"message": "Password reset successfully"}

@app.get("/admin/employees")
def get_employees(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.EmpDet).filter(
        (models.EmpDet.end_date == None) | (models.EmpDet.end_date == "")
    )
    if manager_id:
        query = query.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
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
            "email": emp.p_mail or emp.mail_id or "",
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
    user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
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
        "personal_mail": user.p_mail,
        "professional_mail": user.mail_id,
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
        query = query.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
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
            checkin_record.status = "CL"
            try:
                months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
                today_formatted = f"{today_date.day:02d}-{months[today_date.month-1]}-{today_date.year}"
                auto_leave = models.EmpLeave(
                    emp_id=emp_id,
                    leave_type="Casual Leave",
                    from_date=today_formatted,
                    to_date=today_formatted,
                    days="1.0",
                    reason=f"Auto-deducted: Worked only {hours}h {minutes}m (below 4 hours)",
                    status="Approved",
                    created_by=emp_id,
                    creation_date=now,
                    last_updated_by=emp_id,
                    last_update_date=now,
                    # Added missing fields to avoid MySQL NOT NULL errors
                    applied_date=today_formatted,
                    mail_message_id="",
                    hr_action="",
                    hr_approval="",
                    admin_approval="",
                    lop_days="0",
                    remarks="",
                    approved_by="System",
                    reporting_manager="",
                    approver="",
                    revision="1",
                    attribute_category="",
                    last_update_login=emp_id
                )
                db.add(auto_leave)
                print(f"✅ Auto-deducted 1 CL for {emp_id} - worked {total_hours_float:.2f} hours")
            except Exception as e:
                print(f"⚠️ Could not auto-deduct leave: {e}")
        elif total_hours_float < 6:
            checkin_record.status = "0.5P"
        else:
            checkin_record.status = "P"
            
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"❌ Check-out Error: {str(e)}")
        # If it failed during time calc or leave insert, at least try to save out_time
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
    from sqlalchemy import extract
    emp_id = emp_id.strip()
    logs = db.query(models.CheckIn).filter(
        models.CheckIn.emp_id == emp_id,
        extract('month', models.CheckIn.t_date) == month,
        extract('year', models.CheckIn.t_date) == year
    ).all()
    return logs

@app.get("/leave-stats/{emp_id}")
def get_leave_stats(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    leave_rows = db.query(models.LeaveDet).filter(func.lower(func.trim(models.LeaveDet.emp_id)) == emp_id.lower()).all()
    stats = {
        "casualLeave": {"total": 0, "availed": 0},
        "sickLeave": {"total": 0, "availed": 0},
        "maternityPaternity": {"total": 0, "availed": 0},
        "marriageLeave": {"total": 0, "availed": 0},
        "total": 0,
        "availed": 0
    }
    total_allowed = 0
    total_availed = 0
    for row in leave_rows:
        l_type = (row.leave_type or "").lower()
        try:
            t_leave = float(row.total_leave or 0)
            a_leave = float(row.availed_leave or 0)
        except:
            t_leave = 0
            a_leave = 0
        is_counted = False
        if 'casual' in l_type:
            stats["casualLeave"] = {"total": t_leave, "availed": a_leave}
            is_counted = True
        elif 'sick' in l_type:
            stats["sickLeave"] = {"total": t_leave, "availed": a_leave}
            is_counted = True
        elif 'maternity' in l_type or 'paternity' in l_type:
            stats["maternityPaternity"] = {"total": t_leave, "availed": a_leave}
            is_counted = True
        elif 'marriage' in l_type:
            stats["marriageLeave"] = {"total": t_leave, "availed": a_leave}
            is_counted = True
        if is_counted:
            total_allowed += t_leave
            total_availed += a_leave
    stats["total"] = total_allowed
    stats["availed"] = total_availed
    return stats

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
            "remarks": row.remarks
        }
        for row in history
    ]


def send_email_notification(to_email: str, subject: str, body_html: str):
    if not to_email:
        print("⚠️ Email notification skipped: No recipient email provided")
        return False
    
    # NEW: Use the user-provided API to bypass SMTP blocks (e.g. on Render free tier)
    url = "http://devbms.ilantechsolutions.com/attendance/send-mail/"
    api_key = "my_secret_key_123"
    
    payload = {
        "to_email": to_email,
        "subject": subject,
        "body": body_html
    }
    
    headers = {
        "x-api-key": api_key,
        "Content-Type": "application/json"
    }
    
    try:
        print(f"📧 Attempting to send email via API to: {to_email}")
        response = requests.post(url, json=payload, headers=headers, timeout=15)
        
        if response.status_code in [200, 201]:
            print(f"🚀 EMAIL SENT successfully via API to {to_email}")
            return True
        else:
            print(f"❌ API FAILED to send email to {to_email}: Status {response.status_code}")
            print(f"   Response Preview: {response.text[:200]}")
            return False
            
    except Exception as e:
        print(f"❌ ERROR calling email API for {to_email}: {str(e)}")
        return False

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
    attachment: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == emp_id).first()
    emp_name = user.name if user else 'Unknown'
    attachment_path = None
    if attachment:
        upload_dir = "uploads/leave_attachments"
        os.makedirs(upload_dir, exist_ok=True)
        file_extension = attachment.filename.split('.')[-1]
        file_name = f"{emp_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_extension}"
        file_path = os.path.join(upload_dir, file_name)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(attachment.file, buffer)
        attachment_path = file_path
    print(f"📝 Processing Leave Request for: {emp_id}, Type: {leave_type}, Days: {days}")
    try:
        l_type_key = leave_type.strip().lower().split(' ')[0]
        balance_row = db.query(models.LeaveDet).filter(
            func.lower(func.trim(models.LeaveDet.emp_id)) == emp_id.strip().lower(),
            func.lower(func.trim(models.LeaveDet.leave_type)).contains(l_type_key)
        ).first()
        det_id = balance_row.l_det_id if balance_row else None
        new_leave = models.EmpLeave(
            l_det_id=det_id,
            emp_id=emp_id.strip(),
            leave_type=leave_type,
            from_date=from_date,
            to_date=to_date,
            days=str(days),
            reason=reason,
            status=status,
            file=attachment_path,
            applied_date=datetime.now().strftime('%Y-%m-%d'),
            mail_message_id="",
            hr_action="",
            hr_approval="",
            admin_approval="",
            lop_days="0",
            remarks="",
            approved_by="",
            reporting_manager="",
            approver="",
            revision="1",
            attribute_category="",
            attribute1="", attribute2="", attribute3="", attribute4="", attribute5="",
            last_update_login="",
            created_by=emp_id.strip(),
            creation_date=datetime.now(),
            last_updated_by=emp_id.strip(),
            last_update_date=datetime.now()
        )
        db.add(new_leave)
        if balance_row:
            days_count = float(days)
            balance_row.availed_leave = float(balance_row.availed_leave or 0) + days_count
            if balance_row.available_leave is not None:
                balance_row.available_leave = float(balance_row.available_leave or 0) - days_count
        db.commit()
        db.refresh(new_leave)
        print(f"✅ Leave Applied Successfully. ID: {new_leave.l_id} for Emp: {new_leave.emp_id}")
        if user and user.manager_id:
            manager = db.query(models.EmpDet).filter(models.EmpDet.emp_id == user.manager_id).first()
            if manager and manager.p_mail:
                subject = f"Leave Request - {emp_name} ({emp_id})"
                body = f"""
                <html><body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                    <h3>New Leave Request</h3>
                    <p><strong>Employee:</strong> {emp_name} ({emp_id})</p>
                    <p><strong>Leave Type:</strong> {leave_type}</p>
                    <p><strong>Dates:</strong> {from_date} to {to_date} ({days} days)</p>
                    <p><strong>Reason:</strong> {reason}</p>
                    <hr>
                    <p>Please review and approve/reject via the Aruvi Mobile App.</p>
                </body></html>
                """
                background_tasks.add_task(send_email_notification, manager.p_mail, subject, body)
    except Exception as e:
        print(f"❌ DATABASE ERROR: {str(e)}")
        db.rollback()
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
        query = query.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
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
        query = query.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
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
            "file": leave.file
        })
    return results

@app.post("/admin/approve-leave")
def approve_leave(request_item: schemas.LeaveApprovalAction, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
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
    admin_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == request_item.admin_id.strip()).first()
    if admin_user:
        leave.approved_by = admin_user.name
        leave.approver = admin_user.name
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
            color = "green" if request_item.action.lower() == "approved" else "red"
            subject = f"Leave Request {status_msg} - {leave.leave_type}"
            body = f"""
            <html><body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                <h3>Leave Request Update</h3>
                <p>Dear {emp_user.name},</p>
                <p>Your leave request for <strong>{leave.leave_type}</strong> from {leave.from_date} has been <strong style="color: {color};">{status_msg}</strong>.</p>
                <p><strong>Remarks:</strong> {request_item.remarks or 'N/A'}</p>
                <p><strong>Action By:</strong> {leave.approved_by or 'Manager'}</p>
            </body></html>
            """
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
    except Exception as e:
        print(f"⚠️ Email notification failed: {e}")
    return {"message": f"Leave request {request_item.action.lower()} successfully", "approved_by": leave.approved_by}


# ═══════════════════════════════════════════════════════════════════════════
# NOTIFICATIONS — FIXED VERSION
# ═══════════════════════════════════════════════════════════════════════════
#
# KEY FIXES:
#
# 1. STABLE IDs — Admin:
#    ID = f"{type}_{record_id}"  e.g. "leave_42"
#    When admin approves leave_42, the notification ID stays "leave_42".
#    The frontend's knownNotifIds already has "leave_42", so NO spurious toast.
#    The status/icon/color in the notification body will just update.
#
# 2. STABLE IDs — Employee:
#    Old code: f"leave_{l_id}_{status.lower()}"  — changing status = new ID = unwanted toast
#    New code: f"leave_{l_id}"  — ID never changes regardless of status
#
# 3. LAST_UPDATE_DATE for ordering — ensures status-changed items bubble up
#    and the frontend can detect actual status changes if needed.
#
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/notifications/{user_id}")
def get_notifications(
    user_id: str,
    role: str = "employee",
    manager_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Fetch notifications for Leave, Permission, OT, WFH, Timesheet.
    - Admin:    All requests (Pending/Approved/Rejected) from subordinates
    - Employee: All their own requests (Pending/Approved/Rejected)

    NOTIFICATION ID RULES (stable IDs prevent false "new notification" toasts):
    - Admin   : f"{type}_{record_id}"          e.g. "leave_42", "ot_7"
    - Employee: f"{type}_{record_id}"          e.g. "leave_42", "permission_3"
      (status is NOT included in the ID — status changes don't create new IDs)
    """
    user_id = user_id.strip()
    notifications = []

    # ── Cutoff date (for approved/rejected; pending always shown) ───────────
    user = db.query(models.EmpDet).filter(
        func.lower(func.trim(models.EmpDet.emp_id)) == user_id.lower()
    ).first()

    last_clear_date = None
    if user and user.attribute8 and user.attribute8.strip():
        try:
            last_clear_date = datetime.strptime(user.attribute8.strip(), "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            print(f"⚠️ Could not parse attribute8 '{user.attribute8}': {e}")

    effective_cutoff = last_clear_date if last_clear_date else (datetime.now() - timedelta(days=30))
    print(f"📅 Notifications for {user_id} | role={role} | cutoff={effective_cutoff}")

    # ── Helper functions ─────────────────────────────────────────────────────
    def status_type(s: str):
        s = (s or '').lower()
        if s == 'pending':  return 'pending'
        if s == 'approved': return 'success'
        if s == 'rejected': return 'error'
        return 'info'

    def status_icon(s: str):
        s = (s or '').lower()
        if s == 'pending':  return 'time-outline'
        if s == 'approved': return 'checkmark-circle'
        if s == 'rejected': return 'close-circle'
        return 'notifications-outline'

    def status_label(s: str):
        s = (s or '').lower()
        if s == 'pending':  return '🕐 Pending'
        if s == 'approved': return '✅ Approved'
        if s == 'rejected': return '❌ Rejected'
        return s or 'Unknown'

    def cutoff_filter(status_col, date_col, creation_col):
        """Always show pending; show others only if updated after cutoff."""
        return or_(
            func.lower(status_col) == 'pending',
            func.coalesce(date_col, creation_col) > effective_cutoff
        )

    # ════════════════════════════════════════════════════════════════════════
    # ADMIN - SHOW ONLY PENDING REQUESTS
    # ════════════════════════════════════════════════════════════════════════
    if role.lower() == 'admin':
        print(f"🔍 ADMIN notifications for {user_id} (manager_id={manager_id}) - SHOWING ONLY PENDING")

        # ── 1. Permission ────────────────────────────────────────────────────
        q_perms = (
            db.query(models.EmpPermission, models.EmpDet)
            .outerjoin(models.EmpDet,
                func.lower(func.trim(models.EmpPermission.emp_id)) ==
                func.lower(func.trim(models.EmpDet.emp_id)))
            .filter(func.lower(models.EmpPermission.status) == "pending")  # ADMIN: Only pending
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
                    # ✅ STABLE ID — no status suffix
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

        # ── 2. Leave ─────────────────────────────────────────────────────────
        q_leaves = (
            db.query(models.EmpLeave, models.EmpDet)
            .outerjoin(models.EmpDet,
                func.lower(func.trim(models.EmpLeave.emp_id)) ==
                func.lower(func.trim(models.EmpDet.emp_id)))
            .filter(func.lower(models.EmpLeave.status) == "pending")  # ADMIN: Only pending
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
                    # ✅ STABLE ID
                    "id": f"leave_{leave.l_id}",
                    "record_id": leave.l_id,
                    "type": status_type(st),
                    "notification_type": "leave",
                    "title": f"Leave - {emp_name}",
                    "message": (f"{status_label(st)} | {leave.leave_type}: "
                                f"{leave.from_date} to {leave.to_date} ({leave.days} days)"),
                    "time": str(update_time or "Recently"),
                    "icon": status_icon(st),
                    "screen": "/AdminLeave?tab=myApproval"
                })
            except Exception as e:
                print(f"   Error formatting leave {leave.l_id}: {e}")

        # ── 3. OT ────────────────────────────────────────────────────────────
        q_ot = (
            db.query(models.OverTimeDet, models.EmpDet)
            .outerjoin(models.EmpDet,
                func.lower(func.trim(models.OverTimeDet.emp_id)) ==
                func.lower(func.trim(models.EmpDet.emp_id)))
            .filter(func.lower(models.OverTimeDet.status) == "pending")  # ADMIN: Only pending
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
                    # ✅ STABLE ID
                    "id": f"ot_{ot.ot_id}",
                    "record_id": ot.ot_id,
                    "type": status_type(st),
                    "notification_type": "ot",
                    "title": f"OT - {emp_name}",
                    "message": f"{status_label(st)} | {ot.ot_date}: {ot.duration} hrs",
                    "time": str(update_time or "Recently"),
                    "icon": status_icon(st),
                    "screen": "/AdminOt?tab=myApproval"
                })
            except Exception as e:
                print(f"   Error formatting OT {ot.ot_id}: {e}")

        # ── 4. WFH ───────────────────────────────────────────────────────────
        try:
            q_wfh = (
                db.query(models.WFHDet, models.EmpDet)
                .outerjoin(models.EmpDet,
                    func.lower(func.trim(models.WFHDet.emp_id)) ==
                    func.lower(func.trim(models.EmpDet.emp_id)))
                .filter(func.lower(models.WFHDet.status) == "pending")  # ADMIN: Only pending
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
                        # ✅ STABLE ID
                        "id": f"wfh_{wfh.wfh_id}",
                        "record_id": wfh.wfh_id,
                        "type": status_type(st),
                        "notification_type": "wfh",
                        "title": f"WFH - {emp_name}",
                        "message": f"{status_label(st)} | {wfh.from_date} to {wfh.to_date}",
                        "time": str(update_time or "Recently"),
                        "icon": status_icon(st),
                        "screen": "/AdminWfh?tab=myApproval"
                    })
                except Exception as e:
                    print(f"   Error formatting WFH {wfh.wfh_id}: {e}")
        except Exception as wfh_error:
            print(f"⚠️ Error fetching WFH notifications (admin): {wfh_error}")
            import traceback
            traceback.print_exc()
            # Continue with other notifications even if WFH fails

        # ── 5. Timesheet ─────────────────────────────────────────────────────
        q_timesheets = (
            db.query(models.TimesheetDet, models.EmpDet)
            .outerjoin(models.EmpDet,
                func.lower(func.trim(models.TimesheetDet.emp_id)) ==
                func.lower(func.trim(models.EmpDet.emp_id)))
            .filter(func.lower(models.TimesheetDet.status) == "pending")  # ADMIN: Only pending
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
                    # ✅ STABLE ID
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

    # ════════════════════════════════════════════════════════════════════════
    # EMPLOYEE - SHOW ONLY APPROVED REQUESTS
    # ════════════════════════════════════════════════════════════════════════
    else:
        print(f"🔍 EMPLOYEE notifications for {user_id} - SHOWING ONLY APPROVED")

        # ── 1. Leave ─────────────────────────────────────────────────────────
        for leave in (
            db.query(models.EmpLeave)
            .filter(
                func.lower(func.trim(models.EmpLeave.emp_id)) == user_id.lower(),
                func.lower(models.EmpLeave.status) == "approved",  # EMPLOYEE: Only approved
                cutoff_filter(
                    models.EmpLeave.status,
                    models.EmpLeave.last_update_date,
                    models.EmpLeave.creation_date)
            )
            .order_by(func.coalesce(models.EmpLeave.last_update_date,
                                    models.EmpLeave.creation_date).desc())
            .limit(30).all()
        ):
            st = leave.status or 'Pending'
            update_time = leave.last_update_date or leave.creation_date
            notifications.append({
                # ✅ STABLE ID — no status suffix
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

        # ── 2. Permission ────────────────────────────────────────────────────
        for perm in (
            db.query(models.EmpPermission)
            .filter(
                func.lower(func.trim(models.EmpPermission.emp_id)) == user_id.lower(),
                func.lower(models.EmpPermission.status) == "approved",  # EMPLOYEE: Only approved
                cutoff_filter(
                    models.EmpPermission.status,
                    models.EmpPermission.last_update_date,
                    models.EmpPermission.creation_date)
            )
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
                # ✅ STABLE ID
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

        # ── 3. OT ────────────────────────────────────────────────────────────
        for ot in (
            db.query(models.OverTimeDet)
            .filter(
                func.lower(func.trim(models.OverTimeDet.emp_id)) == user_id.lower(),
                func.lower(models.OverTimeDet.status).in_(["pending","approved","rejected"]),
                cutoff_filter(
                    models.OverTimeDet.status,
                    models.OverTimeDet.last_update_date,
                    models.OverTimeDet.creation_date)
            )
            .order_by(func.coalesce(models.OverTimeDet.last_update_date,
                                    models.OverTimeDet.creation_date).desc())
            .limit(30).all()
        ):
            st = ot.status or 'Pending'
            update_time = ot.last_update_date or ot.creation_date
            notifications.append({
                # ✅ STABLE ID
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

        # ── 4. WFH ───────────────────────────────────────────────────────────
        try:
            for wfh in (
                db.query(models.WFHDet)
                .filter(
                    func.lower(func.trim(models.WFHDet.emp_id)) == user_id.lower(),
                    func.lower(models.WFHDet.status).in_(["pending","approved","rejected"]),
                    cutoff_filter(
                        models.WFHDet.status,
                        models.WFHDet.last_update_date,
                        models.WFHDet.creation_date)
                )
                .order_by(func.coalesce(models.WFHDet.last_update_date,
                                        models.WFHDet.creation_date).desc())
                .limit(30).all()
            ):
                st = wfh.status or 'Pending'
                update_time = wfh.last_update_date or wfh.creation_date
                notifications.append({
                    # ✅ STABLE ID
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
            print(f"⚠️ Error fetching WFH notifications: {wfh_error}")
            # Continue with other notifications even if WFH fails

        # ── 5. Timesheet ─────────────────────────────────────────────────────
        for ts in (
            db.query(models.TimesheetDet)
            .filter(
                func.lower(func.trim(models.TimesheetDet.emp_id)) == user_id.lower(),
                func.lower(models.TimesheetDet.status).in_(["pending","approved","rejected"]),
                cutoff_filter(
                    models.TimesheetDet.status,
                    models.TimesheetDet.last_update_date,
                    models.TimesheetDet.creation_date)
            )
            .order_by(func.coalesce(models.TimesheetDet.last_update_date,
                                    models.TimesheetDet.creation_date).desc())
            .limit(30).all()
        ):
            st = ts.status or 'Pending'
            update_time = ts.last_update_date or ts.creation_date
            notifications.append({
                # ✅ STABLE ID
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

    print(f"✅ Returning {len(notifications)} notifications for {user_id}")
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


@app.post("/apply-permission")
def apply_permission(request: schemas.PermissionApplyRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    from datetime import datetime, time
    target_emp_id = request.emp_id.strip()
    user = db.query(models.EmpDet).filter(
        (models.EmpDet.emp_id == target_emp_id) |
        (models.EmpDet.emp_id == request.emp_id)
    ).first()
    if not user:
        user = db.query(models.EmpDet).filter(func.trim(models.EmpDet.emp_id) == target_emp_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"Employee {request.emp_id} not found")
    try:
        def parse_time_str(time_str):
            for fmt in ("%H:%M", "%I:%M %p", "%I:%M:%S %p", "%H:%M:%S"):
                try:
                    return datetime.strptime(time_str, fmt).time()
                except ValueError:
                    continue
            raise ValueError(f"Time format not recognized: {time_str}")
        f_time = parse_time_str(request.f_time)
        t_time = parse_time_str(request.t_time)
        p_date_dt = parse_date(request.date)
        if not p_date_dt:
            raise HTTPException(status_code=400, detail="Invalid date format")
        p_date = p_date_dt.date()
        h1, m1 = f_time.hour, f_time.minute
        h2, m2 = t_time.hour, t_time.minute
        diff_mins = (h2 * 60 + m2) - (h1 * 60 + m1)
        if diff_mins < 0: diff_mins += 24 * 60
        if diff_mins <= 0:
            raise HTTPException(status_code=400, detail="To Time must be after From Time")
        duration_hrs = diff_mins / 60.0
        if duration_hrs > 4:
            raise HTTPException(status_code=400, detail="Permission duration cannot exceed 4 hours")
        approved_hrs = min(duration_hrs, 2.0)
        lop_hrs = max(0.0, duration_hrs - 2.0)
        final_total_hours = request.total_hours if request.total_hours is not None else f"{duration_hrs:.1f}"
        final_dis_total_hours = request.dis_total_hours if request.dis_total_hours is not None else f"{lop_hrs:.1f}"
        final_status = request.status if request.status else "Pending"
        new_remaining = 0.0
        try:
            curr_val = str(user.remaining_perm or "0").strip()
            curr_perm = float(curr_val) if curr_val else 0.0
            new_remaining = max(0.0, curr_perm - approved_hrs)
            user.remaining_perm = str(new_remaining)
        except Exception as bal_err:
            print(f"⚠️ Balance update error: {bal_err}")
        new_perm = models.EmpPermission(
            emp_id=user.emp_id,
            date=p_date,
            f_time=f_time,
            t_time=t_time,
            reason=request.reason,
            total_hours=final_total_hours,
            dis_total_hours=final_dis_total_hours,
            available_hours=str(new_remaining),
            permitted_permission=str(approved_hrs),
            lop_hours=str(lop_hrs),
            applied_date=datetime.now().strftime("%d-%b-%Y"),
            status=final_status,
            creation_date=datetime.now(),
            last_update_date=datetime.now()
        )
        db.add(new_perm)
        db.commit()
        db.refresh(new_perm)
        print(f"✅ PERMISSION CREATED: ID={new_perm.p_id}")
        if user and user.manager_id:
            manager = db.query(models.EmpDet).filter(
                func.lower(func.trim(models.EmpDet.emp_id)) == user.manager_id.strip().lower()
            ).first()
            if manager and manager.p_mail:
                p_date_str = p_date.strftime("%d-%b-%Y")
                f_time_str = f_time.strftime("%I:%M %p")
                t_time_str = t_time.strftime("%I:%M %p")
                customer_name = user.attribute3 if user.attribute3 else "Internal"
                duration_str = f"{duration_hrs:.1f}"
                subject = f"ITS - {user.name} – {customer_name} - Permission | {p_date_str} | {f_time_str} to {t_time_str} ({duration_str} Hours)"
                body = f"""
                <html><body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                    <p>Dear {manager.name},</p>
                    <p>Good Evening! I hope you are doing well.</p>
                    <p>I would like to request permission from <strong>{f_time_str}</strong> to <strong>{t_time_str}</strong> (<strong>{duration_str} hours</strong>) on <strong>{p_date_str}</strong> due to: {request.reason}</p>
                    <p>Kindly approve the same to proceed.</p>
                    <p>Thanks & Regards,<br><strong>{user.name}</strong></p>
                </body></html>
                """
                background_tasks.add_task(send_email_notification, manager.p_mail, subject, body)
        return {"message": "Permission request submitted successfully", "p_id": new_perm.p_id}
    except Exception as e:
        print(f"❌ DB ERROR in apply_permission: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/admin/pending-permissions")
def get_pending_permissions(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.EmpPermission, models.EmpDet).join(
        models.EmpDet, models.EmpPermission.emp_id == models.EmpDet.emp_id
    ).filter(models.EmpPermission.status == "Pending")
    if manager_id:
        query = query.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    pending = query.order_by(models.EmpPermission.creation_date.desc()).all()
    results = []
    for perm, emp in pending:
        results.append({
            "p_id": perm.p_id,
            "emp_name": emp.name or "Unknown",
            "emp_id": emp.emp_id or "N/A",
            "date": perm.date.strftime("%d-%b-%Y") if perm.date else "",
            "time": f"{perm.f_time.strftime('%H:%M')} to {perm.t_time.strftime('%H:%M')}",
            "fromTime": perm.f_time.strftime('%H:%M') if perm.f_time else "",
            "toTime": perm.t_time.strftime('%H:%M') if perm.t_time else "",
            "f_time": perm.f_time.strftime('%H:%M') if perm.f_time else "",
            "t_time": perm.t_time.strftime('%H:%M') if perm.t_time else "",
            "total_hours": perm.total_hours or "0.0",
            "dis_total_hours": perm.dis_total_hours or "0.0",
            "reason": perm.reason or "No reason",
            "remarks": perm.remarks or "",
            "status": perm.status or "Pending"
        })
    return results

@app.get("/admin/all-permission-history")
def get_all_permission_history(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.EmpPermission, models.EmpDet).join(
        models.EmpDet, models.EmpPermission.emp_id == models.EmpDet.emp_id
    )
    if manager_id:
        query = query.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    all_perms = query.order_by(models.EmpPermission.creation_date.desc()).all()
    results = []
    for perm, emp in all_perms:
        results.append({
            "p_id": perm.p_id,
            "emp_name": emp.name or "Unknown",
            "emp_id": emp.emp_id or "N/A",
            "date": perm.date.strftime("%d-%b-%Y") if perm.date else "",
            "time": f"{perm.f_time.strftime('%H:%M')} to {perm.t_time.strftime('%H:%M')}",
            "fromTime": perm.f_time.strftime('%H:%M') if perm.f_time else "",
            "toTime": perm.t_time.strftime('%H:%M') if perm.t_time else "",
            "f_time": perm.f_time.strftime('%H:%M') if perm.f_time else "",
            "t_time": perm.t_time.strftime('%H:%M') if perm.t_time else "",
            "total_hours": perm.total_hours or "0.0",
            "dis_total_hours": perm.dis_total_hours or "0.0",
            "reason": perm.reason or "No reason",
            "remarks": perm.remarks or "",
            "status": perm.status or "Pending"
        })
    return results

@app.post("/admin/approve-permission")
def approve_permission(request: schemas.PermissionApprovalAction, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    perm = db.query(models.EmpPermission).filter(models.EmpPermission.p_id == request.p_id).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission request not found")
    old_status = perm.status
    perm.status = request.action
    perm.remarks = request.remarks
    perm.last_update_date = datetime.now()
    admin_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == request.admin_id.strip()).first()
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
            status_msg = request.action.upper()
            perm_date = perm.date.strftime("%d-%b-%Y") if perm.date else "N/A"
            color = "green" if request.action.lower() == "approved" else "red"
            manager_name = admin_user.name if admin_user else "Manager"
            f_time_str = perm.f_time.strftime("%I:%M %p") if perm.f_time else "N/A"
            t_time_str = perm.t_time.strftime("%I:%M %p") if perm.t_time else "N/A"
            subject = f"Permission Request {status_msg} - {perm_date}"
            body = f"""
            <html><body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                <h3>Permission Request Update</h3>
                <p>Dear {emp_user.name},</p>
                <p>Your permission request for <strong>{perm_date}</strong> (<strong>{f_time_str}</strong> to <strong>{t_time_str}</strong>) has been <strong style="color: {color};">{status_msg}</strong>.</p>
                <p><strong>Remarks:</strong> {request.remarks or 'N/A'}</p>
                <p><strong>Action By:</strong> {manager_name}</p>
                <br>
                <p>Thanks & Regards,<br>Ilan Tech Solutions</p>
            </body></html>
            """
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
    except Exception as e:
        print(f"⚠️ Email notification failed: {e}")
    return {"message": f"Permission {request.action.lower()} successfully"}

@app.get("/admin/pending-ot")
def get_pending_ot(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.OverTimeDet, models.EmpDet).outerjoin(
        models.EmpDet, func.lower(func.trim(models.OverTimeDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
    ).filter(func.lower(models.OverTimeDet.status) == "pending")
    if manager_id:
        query = query.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    pending = query.order_by(models.OverTimeDet.creation_date.desc()).all()
    results = []
    for ot, emp in pending:
        results.append({
            "ot_id": ot.ot_id,
            "emp_name": emp.name if emp else f"Unknown ({ot.emp_id})",
            "emp_id": ot.emp_id or "N/A",
            "ot_date": ot.ot_date,
            "date": ot.ot_date,
            "startTime": ot.from_time,
            "endTime": ot.to_time,
            "start_time": ot.from_time,
            "end_time": ot.to_time,
            "duration": ot.duration,
            "reason": ot.reason or "No reason",
            "remarks": ot.remarks or "",
            "status": (ot.status or "Pending").strip().capitalize(),
            "submittedDate": ot.applied_date or (ot.creation_date.strftime("%d-%b-%Y") if ot.creation_date else "N/A")
        })
    return results

@app.get("/admin/all-ot-history")
def get_all_ot_history(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.OverTimeDet, models.EmpDet).outerjoin(
        models.EmpDet, func.lower(func.trim(models.OverTimeDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
    )
    if manager_id:
        query = query.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    all_ot = query.order_by(models.OverTimeDet.creation_date.desc()).all()
    results = []
    for ot, emp in all_ot:
        results.append({
            "ot_id": ot.ot_id, "emp_name": emp.name if emp else f"Unknown ({ot.emp_id})",
            "emp_id": ot.emp_id or "N/A", "ot_date": ot.ot_date, "date": ot.ot_date,
            "startTime": ot.from_time, "endTime": ot.to_time, "start_time": ot.from_time,
            "end_time": ot.to_time, "duration": ot.duration, "reason": ot.reason or "No reason",
            "remarks": ot.remarks or "", "status": (ot.status or "Pending").strip().capitalize(),
            "submittedDate": ot.applied_date or (ot.creation_date.strftime("%d-%b-%Y") if ot.creation_date else "N/A")
        })
    return results

@app.post("/admin/approve-ot")
def approve_ot(request: schemas.OverTimeApprovalAction, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    ot = db.query(models.OverTimeDet).filter(models.OverTimeDet.ot_id == request.ot_id).first()
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
            status_msg = request.action.upper()
            color = "green" if request.action.lower() == "approved" else "red"
            manager_name = admin_user.name if admin_user else "Manager"
            subject = f"OT Request {status_msg} - {ot.ot_date}"
            body = f"""
            <html><body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                <h3>OT Request Update</h3>
                <p>Dear {emp_user.name},</p>
                <p>Your Overtime request for <strong>{ot.ot_date}</strong> ({ot.duration}) has been <strong style="color: {color};">{status_msg}</strong>.</p>
                <p><strong>Remarks:</strong> {request.remarks or 'N/A'}</p>
                <p><strong>Action By:</strong> {manager_name}</p>
                <br><p>Thanks & Regards,<br>Ilan Tech Solutions</p>
            </body></html>
            """
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
    except Exception as e:
        print(f"⚠️ Email notification failed: {e}")
    return {"message": f"OT request {request.action.lower()} successfully"}

@app.post("/apply-ot")
def apply_ot(request: schemas.OverTimeApplyRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        user = db.query(models.EmpDet).filter(func.trim(models.EmpDet.emp_id) == request.emp_id.strip()).first()
        if not user:
            raise HTTPException(status_code=404, detail="Employee not found")
        target_emp_id = user.emp_id
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
            manager = db.query(models.EmpDet).filter(func.trim(models.EmpDet.emp_id) == user.manager_id.strip()).first()
            if manager and manager.p_mail:
                try:
                    ot_date_dt = parse_date(request.ot_date)
                    ot_date_str = ot_date_dt.strftime("%d-%b-%Y") if ot_date_dt else request.ot_date
                except:
                    ot_date_str = request.ot_date
                customer_name = user.attribute3 if user.attribute3 else "Internal"
                subject = f"ITS - {user.name} – {customer_name} - Overtime | {ot_date_str} | {request.from_time} to {request.to_time} ({request.duration})"
                body = f"""
                <html><body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                    <p>Dear {manager.name} ,</p>
                    <p>Good Evening! I hope you are doing well. </p>
                    <p>I would like to request permission to do overtime work on {ot_date_str} from {request.from_time} to {request.to_time} ({request.duration}) for {request.reason}</p>
                    <p>Kindly, Approve the same to proceed.</p>
                    <p>Thanks & Regards,<br><strong>{user.name}</strong></p>
                </body></html>
                """
                background_tasks.add_task(send_email_notification, manager.p_mail, subject, body)
        return {"message": "OT request submitted successfully", "ot_id": new_ot.ot_id}
    except Exception as e:
        print(f"❌ OT INSERT ERROR: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/ot-stats/{emp_id}")
def get_ot_stats(emp_id: str, db: Session = Depends(get_db)):
    import re
    emp_id = emp_id.strip()
    ot_records = db.query(models.OverTimeDet).filter(func.lower(func.trim(models.OverTimeDet.emp_id)) == emp_id.lower()).all()
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
        except Exception as e:
            continue
    return {"total": round(total_ot, 2), "approved": round(approved_ot, 2)}

@app.get("/ot-history/{emp_id}")
def get_ot_history(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    return db.query(models.OverTimeDet).filter(
        func.lower(func.trim(models.OverTimeDet.emp_id)) == emp_id.lower()
    ).order_by(models.OverTimeDet.ot_id.desc()).all()

@app.get("/admin/pending-wfh")
def get_pending_wfh(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.WFHDet, models.EmpDet).join(
        models.EmpDet, func.lower(func.trim(models.WFHDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
    ).filter(models.WFHDet.status == "Pending")
    if manager_id:
        query = query.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
    pending = query.order_by(models.WFHDet.creation_date.desc()).all()
    results = []
    for wfh, emp in pending:
        results.append({
            "wfh_id": wfh.wfh_id, "emp_name": emp.name or "Unknown", "emp_id": emp.emp_id or "N/A",
            "date": wfh.from_date, "from_date": wfh.from_date, "to_date": wfh.to_date,
            "reason": wfh.reason or "No reason", "remarks": wfh.remarks or "",
            "status": wfh.status or "Pending",
            "submittedDate": wfh.creation_date.strftime("%d-%b-%Y") if wfh.creation_date else "N/A"
        })
    return results

@app.get("/admin/all-wfh-history")
def get_all_wfh_history(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        query = db.query(models.WFHDet, models.EmpDet).outerjoin(
            models.EmpDet, func.lower(func.trim(models.WFHDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
        )
        if manager_id:
            query = query.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
        all_wfh = query.order_by(models.WFHDet.creation_date.desc()).all()
        results = []
        for wfh, emp in all_wfh:
            results.append({
                "wfh_id": wfh.wfh_id, "emp_name": emp.name if emp else "Unknown",
                "emp_id": wfh.emp_id, "date": wfh.from_date, "from_date": wfh.from_date,
                "to_date": wfh.to_date, "days": wfh.days, "reason": wfh.reason or "No reason",
                "remarks": wfh.remarks or "", "status": wfh.status or "Pending",
                "submittedDate": wfh.creation_date.strftime("%d-%b-%Y") if wfh.creation_date else "N/A"
            })
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/approve-wfh")
def approve_wfh(request: schemas.WFHApprovalAction, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    wfh = db.query(models.WFHDet).filter(models.WFHDet.wfh_id == request.wfh_id).first()
    if not wfh:
        raise HTTPException(status_code=404, detail="WFH request not found")
    wfh.status = request.action
    wfh.remarks = request.remarks
    wfh.last_update_date = datetime.now()
    admin_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == request.admin_id.strip()).first()
    if admin_user:
        existing_remarks = wfh.remarks or ""
        wfh.remarks = f"{existing_remarks} (Action by: {admin_user.name})".strip() if existing_remarks else f"Action by: {admin_user.name}"
    db.commit()
    try:
        emp_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == wfh.emp_id).first()
        if emp_user and emp_user.p_mail:
            status_msg = request.action.upper()
            color = "green" if request.action.lower() == "approved" else "red"
            manager_name = admin_user.name if admin_user else "Manager"
            subject = f"WFH Request {status_msg} - {wfh.from_date}"
            body = f"""
            <html><body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                <h3>WFH Request Update</h3>
                <p>Dear {emp_user.name},</p>
                <p>Your Work From Home request for <strong>{wfh.from_date}</strong> has been <strong style="color: {color};">{status_msg}</strong>.</p>
                <p><strong>Remarks:</strong> {request.remarks or 'N/A'}</p>
                <p><strong>Action By:</strong> {manager_name}</p>
                <br><p>Thanks & Regards,<br>Ilan Tech Solutions</p>
            </body></html>
            """
            background_tasks.add_task(send_email_notification, emp_user.p_mail, subject, body)
    except Exception as e:
        print(f"⚠️ Email notification failed: {e}")
    return {"message": f"WFH request {request.action.lower()} successfully"}

@app.get("/wfh-stats/{emp_id}")
def get_wfh_stats(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    wfh_records = db.query(models.WFHDet).filter(func.lower(func.trim(models.WFHDet.emp_id)) == emp_id.lower()).all()
    total_wfh = len(wfh_records)
    approved_wfh = sum(1 for r in wfh_records if r.status and r.status.lower() == 'approved')
    rejected_wfh = sum(1 for r in wfh_records if r.status and r.status.lower() == 'rejected')
    return {"total": total_wfh, "approved": approved_wfh, "rejected": rejected_wfh}

@app.post("/apply-wfh")
def apply_wfh(request: schemas.WFHApplyRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        clean_emp_id = request.emp_id.strip()
        new_wfh = models.WFHDet(
            emp_id=clean_emp_id,
            from_date=request.date,
            to_date=request.date,
            days="1",
            reason=request.reason,
            status=request.status or "Pending",
            created_by=clean_emp_id,
            creation_date=datetime.now(),
            last_updated_by=clean_emp_id,
            last_update_date=datetime.now(),
            last_update_login=clean_emp_id,
            remarks=""
        )
        db.add(new_wfh)
        db.commit()
        db.refresh(new_wfh)
        user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == clean_emp_id.lower()).first()
        if user and user.manager_id:
            manager_id_clean = user.manager_id.strip()
            manager = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == manager_id_clean.lower()).first()
            if manager and manager.p_mail:
                try:
                    wfh_date_dt = parse_date(request.date)
                    wfh_date_str = wfh_date_dt.strftime("%d-%b-%Y") if wfh_date_dt else request.date
                except:
                    wfh_date_str = request.date
                customer_name = user.attribute3 if user.attribute3 else "Internal"
                subject = f"ITS - {user.name} – {customer_name} - WFH | {wfh_date_str}"
                body = f"""
                <html><body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                    <p>Dear {manager.name} ,</p>
                    <p>Good Evening! I hope you are doing well. </p>
                    <p>I would like to request Work From Home for {wfh_date_str} (1 Day) due to {request.reason}</p>
                    <p>Kindly, Approve the same to proceed.</p>
                    <p>Thanks & Regards,<br><strong>{user.name}</strong></p>
                </body></html>
                """
                background_tasks.add_task(send_email_notification, manager.p_mail, subject, body)
        return {"message": "WFH request submitted successfully", "wfh_id": new_wfh.wfh_id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/wfh-history/{emp_id}")
def get_wfh_history(emp_id: str, db: Session = Depends(get_db)):
    history = db.query(models.WFHDet).filter(
        func.lower(func.trim(models.WFHDet.emp_id)) == emp_id.lower()
    ).order_by(models.WFHDet.wfh_id.desc()).all()
    return [{"id": r.wfh_id, "date": r.from_date, "reason": r.reason, "status": r.status,
             "submittedDate": r.creation_date.strftime("%Y-%m-%d") if r.creation_date else "N/A"}
            for r in history]

@app.get("/permission-stats/{emp_id}")
def get_permission_stats(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
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
    history = db.query(models.EmpPermission).filter(
        func.lower(func.trim(models.EmpPermission.emp_id)) == emp_id.lower()
    ).order_by(models.EmpPermission.p_id.desc()).all()
    return [{
        "p_id": row.p_id, "emp_id": row.emp_id,
        "date": row.date.strftime("%d-%b-%Y") if row.date else "",
        "f_time": row.f_time.strftime("%H:%M") if row.f_time else "",
        "t_time": row.t_time.strftime("%H:%M") if row.t_time else "",
        "total_hours": row.total_hours, "dis_total_hours": row.dis_total_hours,
        "reason": row.reason, "status": row.status, "remarks": row.remarks,
        "creation_date": row.creation_date, "last_update_date": row.last_update_date
    } for row in history]

@app.get("/dashboard/{emp_id}", response_model=schemas.DashboardResponse)
def get_dashboard(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
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

    # 1. Fetch Holidays
    try:
        all_holidays = db.query(models.HolidayDet).all()
        for h in all_holidays:
            h_date = parse_date(h.Office_Holiday_Date)
            if h_date:
                h_date_flat = h_date.replace(hour=0, minute=0, second=0, microsecond=0)
                # Show if in current month OR within next 90 days
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
        print(f"⚠️ Error fetching holidays: {e}")

    # 2. Birthdays & Anniversaries
    for emp in all_emps:
        # Birthdays
        if emp.dob:
            bday = parse_date(emp.dob)
            if bday:
                # Convert birth year to current year for display/sorting
                this_year_bday = bday.replace(year=today.year)
                this_year_bday_flat = this_year_bday.replace(hour=0, minute=0, second=0, microsecond=0)
                
                # Show if in current month OR within next 60 days
                if this_year_bday_flat.month == today.month or (0 <= (this_year_bday_flat - today_flat).days <= 60):
                    upcoming_events.append({
                        "id": f"bday_{emp.emp_id}_{this_year_bday.strftime('%Y%m%d')}",
                        "name": f"{emp.name}'s Birthday", "type": "birthday",
                        "date": this_year_bday.strftime("%d %b"), "day": this_year_bday.strftime("%A"),
                        "raw_date": this_year_bday_flat
                    })

        # Anniversaries
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

    # Sort all events month-wise (chronological)
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
            pending_leaves = db.query(models.EmpLeave, models.EmpDet.name)\
                .join(models.EmpDet, models.EmpLeave.emp_id == models.EmpDet.emp_id)\
                .filter(models.EmpLeave.status == 'Pending')\
                .order_by(models.EmpLeave.creation_date.desc()).limit(5).all()
            for leave, name in pending_leaves:
                notifications.append({
                    "id": f"admin_leave_{leave.l_id}", "title": "New Leave Request",
                    "message": f"{name} applied for {leave.leave_type} ({leave.days} days)",
                    "time": leave.creation_date.strftime("%Y-%m-%d %H:%M") if leave.creation_date else "",
                    "type": "alert", "icon": "mail-unread-outline"
                })
            pending_perms = db.query(models.EmpPermission, models.EmpDet.name)\
                .join(models.EmpDet, models.EmpPermission.emp_id == models.EmpDet.emp_id)\
                .filter(models.EmpPermission.status == 'Pending')\
                .order_by(models.EmpPermission.creation_date.desc()).limit(5).all()
            for perm, name in pending_perms:
                notifications.append({
                    "id": f"admin_perm_{perm.p_id}", "title": "New Permission Request",
                    "message": f"{name} requested permission for {perm.total_hours}",
                    "time": perm.creation_date.strftime("%Y-%m-%d %H:%M") if perm.creation_date else "",
                    "type": "alert", "icon": "time-outline"
                })
        except Exception as e:
            print(f"Error fetching admin notifications: {e}")
    elif is_manager:
        try:
            pending_leaves = db.query(models.EmpLeave, models.EmpDet.name)\
                .join(models.EmpDet, models.EmpLeave.emp_id == models.EmpDet.emp_id)\
                .filter(models.EmpLeave.status == 'Pending')\
                .filter(func.lower(func.trim(models.EmpDet.manager_id)) == emp_id.lower())\
                .order_by(models.EmpLeave.creation_date.desc()).limit(5).all()
            for leave, name in pending_leaves:
                notifications.append({
                    "id": f"mgr_leave_{leave.l_id}", "title": "New Leave Request (Team)",
                    "message": f"{name} applied for {leave.leave_type} ({leave.days} days)",
                    "time": leave.creation_date.strftime("%Y-%m-%d %H:%M") if leave.creation_date else "",
                    "type": "alert", "icon": "mail-unread-outline"
                })
            pending_perms = db.query(models.EmpPermission, models.EmpDet.name)\
                .join(models.EmpDet, models.EmpPermission.emp_id == models.EmpDet.emp_id)\
                .filter(models.EmpPermission.status == 'Pending')\
                .filter(func.lower(func.trim(models.EmpDet.manager_id)) == emp_id.lower())\
                .order_by(models.EmpPermission.creation_date.desc()).limit(5).all()
            for perm, name in pending_perms:
                notifications.append({
                    "id": f"mgr_perm_{perm.p_id}", "title": "New Permission Request (Team)",
                    "message": f"{name} requested permission for {perm.total_hours}",
                    "time": perm.creation_date.strftime("%Y-%m-%d %H:%M") if perm.creation_date else "",
                    "type": "alert", "icon": "time-outline"
                })
            
            # WFH Notifications (Manager)
            pending_wfh = db.query(models.WFHDet, models.EmpDet.name)\
                .join(models.EmpDet, models.WFHDet.emp_id == models.EmpDet.emp_id)\
                .filter(models.WFHDet.status == 'Pending')\
                .filter(func.lower(func.trim(models.EmpDet.manager_id)) == emp_id.lower())\
                .order_by(models.WFHDet.creation_date.desc()).limit(5).all()
            for wfh, name in pending_wfh:
                notifications.append({
                    "id": f"mgr_wfh_{wfh.wfh_id}", "title": "New WFH Request (Team)",
                    "message": f"{name} requested WFH for {wfh.from_date}",
                    "time": wfh.creation_date.strftime("%Y-%m-%d %H:%M") if wfh.creation_date else "",
                    "type": "alert", "icon": "home-outline"
                })

            # OT Notifications (Manager)
            pending_ots = db.query(models.OverTimeDet, models.EmpDet.name)\
                .join(models.EmpDet, func.lower(func.trim(models.OverTimeDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id)))\
                .filter(func.lower(models.OverTimeDet.status) == 'pending')\
                .filter(func.lower(func.trim(models.EmpDet.manager_id)) == emp_id.lower())\
                .order_by(models.OverTimeDet.creation_date.desc()).limit(5).all()
            for ot, name in pending_ots:
                notifications.append({
                    "id": f"mgr_ot_{ot.ot_id}", "title": "New OT Request (Team)",
                    "message": f"{name} requested OT for {ot.ot_date}",
                    "time": ot.creation_date.strftime("%Y-%m-%d %H:%M") if ot.creation_date else "",
                    "type": "alert", "icon": "time-outline"
                })
        except Exception as e:
            print(f"Error fetching manager notifications: {e}")
    
    # All Admin view
    if is_admin:
        try:
             # WFH Notifications (Admin)
            pending_wfh_admin = db.query(models.WFHDet, models.EmpDet.name)\
                .join(models.EmpDet, models.WFHDet.emp_id == models.EmpDet.emp_id)\
                .filter(models.WFHDet.status == 'Pending')\
                .order_by(models.WFHDet.creation_date.desc()).limit(5).all()
            for wfh, name in pending_wfh_admin:
                # Avoid duplicates if already added by manager logic
                if not any(n["id"] == f"mgr_wfh_{wfh.wfh_id}" for n in notifications):
                    notifications.append({
                        "id": f"admin_wfh_{wfh.wfh_id}", "title": "New WFH Request",
                        "message": f"{name} requested WFH for {wfh.from_date}",
                        "time": wfh.creation_date.strftime("%Y-%m-%d %H:%M") if wfh.creation_date else "",
                        "type": "alert", "icon": "home-outline"
                    })
        except Exception as e:
            print(f"Error fetching admin wfh notifications: {e}")

    try:
        my_leave_updates = db.query(models.EmpLeave)\
            .filter(models.EmpLeave.emp_id == emp_id)\
            .filter(models.EmpLeave.status.in_(['Approved', 'Rejected']))\
            .filter(models.EmpLeave.last_update_date >= recent_date_limit)\
            .order_by(models.EmpLeave.last_update_date.desc()).limit(5).all()
        for leave in my_leave_updates:
            notifications.append({
                "id": f"emp_leave_{leave.l_id}", "title": f"Leave {leave.status}",
                "message": f"Your {leave.leave_type} request for {leave.from_date} was {leave.status}",
                "time": leave.last_update_date.strftime("%Y-%m-%d %H:%M") if leave.last_update_date else "",
                "type": "success" if leave.status == 'Approved' else "error",
                "icon": "checkmark-circle-outline" if leave.status == 'Approved' else "close-circle-outline"
            })
        my_perm_updates = db.query(models.EmpPermission)\
            .filter(models.EmpPermission.emp_id == emp_id)\
            .filter(models.EmpPermission.status.in_(['Approved', 'Rejected']))\
            .filter(models.EmpPermission.last_update_date >= recent_date_limit)\
            .order_by(models.EmpPermission.last_update_date.desc()).limit(5).all()
        for perm in my_perm_updates:
            notifications.append({
                "id": f"perm_{perm.p_id}", "screen": "/AdminPermission?tab=myApproval",
                "title": f"Permission {perm.status}",
                "message": f"Your permission request for {perm.date.strftime('%d-%b-%Y') if perm.date else ''} was {perm.status}",
                "time": perm.last_update_date.strftime("%Y-%m-%d %H:%M") if perm.last_update_date else "",
                "type": "success" if perm.status == 'Approved' else "error",
                "icon": "time-outline"
            })
        
        # WFH Updates for Employee
        my_wfh_updates = db.query(models.WFHDet)\
            .filter(models.WFHDet.emp_id == emp_id)\
            .filter(models.WFHDet.status.in_(['Approved', 'Rejected']))\
            .filter(models.WFHDet.last_update_date >= recent_date_limit)\
            .order_by(models.WFHDet.last_update_date.desc()).limit(5).all()
        for wfh in my_wfh_updates:
            notifications.append({
                "id": f"emp_wfh_{wfh.wfh_id}", "title": f"WFH {wfh.status}",
                "message": f"Your WFH request for {wfh.from_date} was {wfh.status}",
                "time": wfh.last_update_date.strftime("%Y-%m-%d %H:%M") if wfh.last_update_date else "",
                "type": "success" if wfh.status == 'Approved' else "error",
                "icon": "home-outline"
            })

        # OT Updates for Employee
        my_ot_updates = db.query(models.OverTimeDet)\
            .filter(func.lower(func.trim(models.OverTimeDet.emp_id)) == emp_id.lower())\
            .filter(models.OverTimeDet.status.in_(['Approved', 'Rejected', 'approved', 'rejected']))\
            .filter(models.OverTimeDet.last_update_date >= recent_date_limit)\
            .order_by(models.OverTimeDet.last_update_date.desc()).limit(5).all()
        for ot in my_ot_updates:
            notifications.append({
                "id": f"emp_ot_{ot.ot_id}", "title": f"OT {ot.status}",
                "message": f"Your OT request for {ot.ot_date} was {ot.status}",
                "time": ot.last_update_date.strftime("%Y-%m-%d %H:%M") if ot.last_update_date else "",
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

@app.get("/timesheet-month/{emp_id}", response_model=List[schemas.TimesheetResponse])
def get_timesheet_month(emp_id: str, month: Optional[str] = None, year: Optional[str] = None, db: Session = Depends(get_db)):
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
def get_admin_timesheet_employees(month: Optional[str] = None, year: Optional[str] = None, db: Session = Depends(get_db)):
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
    matched_employees = [e for e in employees if e.emp_id and e.emp_id.replace(" ", "") in clean_ids]
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

@app.post("/admin/timesheet/action")
def timesheet_action(action_req: schemas.TimesheetApprovalAction, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    ts = db.query(models.TimesheetDet).filter(models.TimesheetDet.t_id == action_req.t_id).first()
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
            admin_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == action_req.admin_id.strip()).first()
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
        print(f"⚠️ Email notification failed: {e}")
    return {"message": f"Timesheet {action_req.action} successfully"}
