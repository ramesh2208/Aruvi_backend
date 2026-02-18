from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from datetime import datetime, timedelta, date
from typing import List, Optional
import shutil
import os
import smtplib
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
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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

# Add CORS middleware to allow requests from React Native app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (for development)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, OPTIONS, etc.)
    allow_headers=["*"],  # Allow all headers
)

# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper for date parsing "08-Feb-2001"
# Helper for date parsing
def parse_date(d):
    if not d: return None
    if isinstance(d, datetime):
        return d
    if isinstance(d, date):
        return datetime.combine(d, datetime.min.time())
    
    d_str = str(d).strip()
    
    # Custom parsing for formats like "08-Feb-2001" to handle case-insensitivity
    months_map = {
        'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
        'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
    }
    
    # Try DD-Mon-YYYY with case-insensitive month
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

    # Try common formats
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
    
    # Extract prefix if email, otherwise use full input
    prefix = username_input.split("@")[0] if "@" in username_input else username_input

    # --- USER LOOKUP ---
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

    # --- PASSWORD DEBUG INFO ---
    input_md5 = hashlib.md5(input_pwd.encode()).hexdigest()

    print("\n🧪 PASSWORD DEBUG")
    print("Input password:", input_pwd)
    print("Input MD5:", input_md5)
    print("DB attribute15:", user.attribute15)
    print("DB password column:", user.password)

    # --- PASSWORD VERIFY ---
    password_valid = False

    if user.attribute15 and user.attribute15.lower() == input_md5.lower():
        print("✅ Match via attribute15 MD5")
        password_valid = True

    if not password_valid and user.password and user.password.lower() == input_md5.lower():
        print("✅ Match via password column MD5")
        password_valid = True

    if not password_valid and user.password == input_pwd:
        print("✅ Match via PLAINTEXT password")
        print("📢 Expected password (plaintext):", user.password)
        password_valid = True

    # --- OPTIONAL AES DECRYPT DEBUG ---
    if not password_valid and user.password and user.attribute15:
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            import base64

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

    # --- ROLE ---
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

    # Check if this user is a manager for anyone (subordinates exist)
    is_manager = db.query(models.EmpDet).filter(
        func.lower(func.trim(models.EmpDet.manager_id)) == user.emp_id.lower().strip()
    ).first() is not None

    if is_manager and role_type != "Admin":
        role_type = "Admin"  # Give them admin access as requested

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



# --- FORGOT PASSWORD FLOW ---

@app.post("/forgot-password")
def forgot_password(request: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)):
    email = request.email.strip().lower()
    print(f"\n--- 📧 FORGOT PASSWORD ATTEMPT: {email} ---")
    
    # 1. Check if email exists in p_mail
    user = db.query(models.EmpDet).filter(func.lower(models.EmpDet.p_mail) == email).first()
    if not user:
        print(f" ERROR: Email '{email}' not found in p_mail.")
        raise HTTPException(status_code=404, detail="Email not found in our records")
    
    print(f" User found: {user.name} (Emp ID: {user.emp_id})")
    
    # 2. Generate OTP
    otp = ''.join(random.choices(string.digits, k=6))
    otp_store[email] = {
        "otp": otp,
        "expires_at": datetime.now() + timedelta(minutes=5)
    }
    print(f" Generated OTP: {otp}")
    
    # 3. Send Email via ilantechsolutions.com
    sender_email = "ramesh.p@ilantechsolutions.com"
    sender_password = "s#$ITS@9Hs4^Rma"
    smtp_server = "ilantechsolutions.com"
    smtp_port = 465
    
    msg = MIMEMultipart()
    msg['From'] = f"Ilan Tech Solutions <{sender_email}>"
    msg['To'] = email
    msg['Subject'] = f"ITS - Password Reset Code : {otp} Enclosed"
    
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
    msg.attach(MIMEText(body, 'html'))
    
    try:
        print(f"📡 Connecting to {smtp_server} via SSL on port {smtp_port}...")
        # Port 465 requires SMTP_SSL (Implicit SSL)
        server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        
        print(f"🔑 Attempting login for {sender_email}...")
        server.login(sender_email, sender_password)
        
        print(f"✉️ Sending email to {email}...")
        text = msg.as_string()
        server.sendmail(sender_email, email, text)
        server.quit()
        print(f"🚀 SUCCESS: OTP sent successfully to {email}")
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        print(f"❌ SMTP ERROR: {str(e)}")
        print(f"FULL TRACEBACK:\n{error_detail}")
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")
    
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
    """
    Decrypt the auth_key stored in database using Fernet encryption
    """
    try:
        fernet = Fernet(FERNET_KEY.encode())
        decrypted_secret = fernet.decrypt(encrypted_auth_key.encode()).decode()
        
        # Don't strip - return the exact secret
        return decrypted_secret
    except Exception as e:
        print(f"❌ Fernet decryption error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Failed to decrypt 2FA secret")

class GetAuthKeyRequest(BaseModel):
    p_mail: str

class GetAuthKeyResponse(BaseModel):
    auth_key: str
    auth_timer: int
    p_mail: str

@app.post("/get-user-auth-key", response_model=GetAuthKeyResponse)
def get_user_auth_key(
    request: GetAuthKeyRequest,
    db: Session = Depends(get_db)
):

    print("\n" + "="*60)
    print("🔐 GET USER AUTH KEY")
    print("="*60)

    p_mail = request.p_mail.strip().lower()

    if not p_mail:
        raise HTTPException(status_code=400, detail="Email is required")

    user = db.query(models.EmpDet).filter(
        func.lower(func.trim(models.EmpDet.p_mail)) == p_mail
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.auth_key:
        raise HTTPException(
            status_code=400,
            detail="2FA not configured for this user"
        )

    print(f"✅ User found: {user.emp_id}")
    print(f"⏰ Auth Timer: {user.auth_timer}")

    return GetAuthKeyResponse(
        auth_key=user.auth_key,
        auth_timer=user.auth_timer or 30,
        p_mail=user.p_mail
    )

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

        # --- Decrypt ---
        fernet = Fernet(FERNET_KEY.encode())
        secret = fernet.decrypt(encrypted_key.encode()).decode()

        # ⚠️ remove in production
        print("✅ Secret decrypted")

        # --- TOTP ---
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

    user = db.query(models.EmpDet).filter(
        func.trim(models.EmpDet.emp_id) == emp_id
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.auth_key:
        raise HTTPException(status_code=400, detail="2FA not configured")

    print(f"✅ User: {user.emp_id}")

    # ✅ FIXED CALL
    ok = verify_authenticator_otp_for_user(user, otp_input)

    if not ok:
        raise HTTPException(status_code=401, detail="Invalid Authenticator code")

    print("✅ 2FA SUCCESS")

    # --- Role Logic ---
    is_global_admin = False
    role_type = "Employee"

    if user.dom_id:
        try:
            d_id = int(str(user.dom_id).strip())
            domain_obj = db.query(models.Domain).filter(
                models.Domain.dom_id == d_id
            ).first()

            if domain_obj and domain_obj.domain:
                if any(x in domain_obj.domain.lower()
                       for x in ["admin", "executive", "management"]):
                    role_type = "Admin"
                    is_global_admin = True
        except:
            pass

    # Manager check
    is_manager = db.query(models.EmpDet).filter(
        func.lower(func.trim(models.EmpDet.manager_id))
        == user.emp_id.lower().strip()
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
    
    # 1. Verify OTP and Expiry again
    if email not in otp_store:
        raise HTTPException(status_code=400, detail="OTP not requested")
        
    item = otp_store[email]
    if item["otp"] != otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
        
    if datetime.now() > item["expires_at"]:
        raise HTTPException(status_code=400, detail="OTP expired")
    
    # 2. Find user
    user = db.query(models.EmpDet).filter(func.lower(models.EmpDet.p_mail) == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 3. Encrypt password using AES as requested
    # attribute15: IV (base64)
    # password: encrypted password (base64)
    AES_KEY = b"1234567890abcdef"
    iv = os.urandom(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    padded_data = pad(new_pwd.encode(), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
    iv_b64 = base64.b64encode(iv).decode()
    
    # Also update MD5 for fallback/compatibility if needed
    # But user specifically mentioned attribute15 has decode and use key b"1234567890abcdef"
    # In login, it checks MD5 in attribute15 FIRST. 
    # If we want AES to work, we should ensure MD5 doesn't match or update only AES columns.
    # However, if we put IV in attribute15, it won't match MD5.
    
    user.password = encrypted_b64
    user.attribute15 = iv_b64
    
    # Optional: Also store in attribute14 if MD5 is needed? No, user didn't ask.
    
    db.commit()
    
    # 4. Clear OTP
    del otp_store[email]
    
    return {"message": "Password reset successfully"}

@app.get("/admin/employees")
def get_employees(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    # Exclude inactive employees (those with an end_date)
    query = db.query(models.EmpDet).filter(
        (models.EmpDet.end_date == None) | (models.EmpDet.end_date == "")
    )
    
    if manager_id:
        query = query.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())
        
    employees = query.all()
    results = []
    for emp in employees:
        # Get domain name
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
            "department": domain_name, # Map domain to department for now as requested by UI structure
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
    # Exclude inactive employees (those with an end_date)
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
    
    # Check if already checked in today
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
        # Parse times
        fmt = "%H:%M:%S"
        t1 = datetime.strptime(checkin_record.in_time.strip(), fmt)
        t2 = datetime.strptime(request.out_time.strip(), fmt)
        
        # Grace Period Logic
        # If check-in between 09:30-10:00, apply grace to make it 09:30
        # If check-out between 06:30-07:00, apply grace to make it 07:00
        grace_start_time = datetime.strptime("09:30:00", fmt)
        grace_end_time = datetime.strptime("10:00:00", fmt)
        checkout_grace_start = datetime.strptime("18:30:00", fmt)  # 6:30 PM
        checkout_grace_end = datetime.strptime("19:00:00", fmt)    # 7:00 PM
        
        # Apply check-in grace
        if grace_start_time <= t1 <= grace_end_time:
            t1 = grace_start_time
            checkin_record.in_time = "09:30:00"
        
        # Apply check-out grace
        if checkout_grace_start <= t2 <= checkout_grace_end:
            t2 = checkout_grace_end
            checkin_record.out_time = "19:00:00"
        
        # Calculate total time
        delta = t2 - t1
        total_seconds = int(delta.total_seconds())
        if total_seconds < 0:
            total_seconds = 0
             
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        
        # Store in "6h 4m" format
        checkin_record.Total_hours = f"{hours}h {minutes}m"
        
        # Calculate float hours for status logic
        total_hours_float = hours + (minutes / 60)
        
        # Attendance Status Logic
        if total_hours_float < 4:
            # Below 4 hours - Auto deduct 1 CL
            checkin_record.status = "CL"
            
            # Auto-deduct from leave table
            try:
                # Get today's date in the format used in leave table
                months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
                today_formatted = f"{today_date.day:02d}-{months[today_date.month-1]}-{today_date.year}"
                
                # Create automatic leave entry
                auto_leave = models.EmpLeave(
                    emp_id=emp_id,
                    leave_type="Casual Leave",
                    from_date=today_formatted,
                    to_date=today_formatted,
                    days=1.0,
                    reason=f"Auto-deducted: Worked only {hours}h {minutes}m (below 4 hours)",
                    status="Approved",
                    created_by=emp_id,
                    creation_date=now,
                    last_updated_by=emp_id,
                    last_update_date=now
                )
                db.add(auto_leave)
                print(f"✅ Auto-deducted 1 CL for {emp_id} - worked {total_hours_float:.2f} hours")
            except Exception as e:
                print(f"⚠️ Could not auto-deduct leave: {e}")
                
        elif total_hours_float < 6:
            # 4-6 hours - Half day present
            checkin_record.status = "0.5P"
        else:
            # Above 6 hours - Full day present
            checkin_record.status = "P"

    except Exception as e:
        print(f"Time calc error: {e}")
        checkin_record.Total_hours = "0h 0m"
        checkin_record.status = "Error"

    db.commit()
    return {
        "message": "Check-out successful", 
        "total_hours": checkin_record.Total_hours, 
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
    # Fetches all rows for this employee from xxits_leave_det_t
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
            # We use float() since total_leave is a string in the structure provided
            t_leave = float(row.total_leave or 0)
            a_leave = float(row.availed_leave or 0)
        except:
            t_leave = 0
            a_leave = 0
            
        # Check for matching types
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
    history = db.query(models.EmpLeave).filter(func.lower(func.trim(models.EmpLeave.emp_id)) == emp_id.lower()).order_by(models.EmpLeave.l_id.desc()).all()
    return [
        {
            "l_id": row.l_id,
            "leaveType": row.leave_type, # Frontend expects camelCase
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


# ============================================================
# EMAIL HELPER
# ============================================================
def send_email_notification(to_email: str, subject: str, body_html: str):
    """
    Helper function to send email notifications.
    Reuses SMTP credentials from forgot_password flow.
    """
    if not to_email:
        print("⚠️ Email notification skipped: No recipient email provided")
        return False
        
    sender_email = "ramesh.p@ilantechsolutions.com"
    sender_password = "s#$ITS@9Hs4^Rma"
    smtp_server = "ilantechsolutions.com"
    smtp_port = 465
    
    msg = MIMEMultipart()
    msg['From'] = f"Ilan Tech Solutions <{sender_email}>"
    msg['To'] = to_email
    msg['Subject'] = subject
    
    msg.attach(MIMEText(body_html, 'html'))
    
    try:
        print(f"📡 Connecting to {smtp_server} via SSL to send email to {to_email}...")
        server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()
        print(f"🚀 EMAIL SENT successfully to {to_email}")
        return True
    except Exception as e:
        print(f"❌ FAILED to send email to {to_email}: {str(e)}")
        # Don't raise error to avoid breaking the main flow
        return False

@app.post("/apply-leave")
async def apply_leave(
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
    # Get employee name
    user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == emp_id).first()
    emp_name = user.name if user else 'Unknown'
    
    # Handle attachment
    attachment_path = None
    attachment_type = None
    attachment_name = None
    
    if attachment:
        # Create uploads directory if not exists
        upload_dir = "uploads/leave_attachments"
        os.makedirs(upload_dir, exist_ok=True)
        
        # Save file
        file_extension = attachment.filename.split('.')[-1]
        file_name = f"{emp_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_extension}"
        file_path = os.path.join(upload_dir, file_name)
        
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(attachment.file, buffer)
        
        attachment_path = file_path
        attachment_type = attachment.content_type
        attachment_name = attachment.filename
    
    print(f"📝 Processing Leave Request for: {emp_id}, Type: {leave_type}, Days: {days}")
    print("🔍 DEBUG: HIT NEW APPLY_LEAVE 123456")

    try:
        # Find matching leave balance row FIRST to get l_det_id
        l_type_key = leave_type.strip().lower().split(' ')[0] # e.g. "casual"
        
        balance_row = db.query(models.LeaveDet).filter(
            func.lower(func.trim(models.LeaveDet.emp_id)) == emp_id.strip().lower(),
            func.lower(func.trim(models.LeaveDet.leave_type)).contains(l_type_key)
        ).first()

        det_id = balance_row.l_det_id if balance_row else None

        # Insert leave request
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
            attribute1="",
            attribute2="",
            attribute3="",
            attribute4="",
            attribute5="",
            last_update_login="",
            created_by=emp_id.strip(),
            creation_date=datetime.now(),
            last_updated_by=emp_id.strip(),
            last_update_date=datetime.now()
        )
        
        db.add(new_leave)
        
        # UPDATE BALANCE IMMEDIATELY
        if balance_row:
            days_count = float(days)
            balance_row.availed_leave = float(balance_row.availed_leave or 0) + days_count
            if balance_row.available_leave is not None:
                 balance_row.available_leave = float(balance_row.available_leave or 0) - days_count
        
        db.commit()
        db.refresh(new_leave)
        print(f"✅ Leave Applied Successfully. ID: {new_leave.l_id} for Emp: {new_leave.emp_id}")

        # --- SEND EMAIL TO MANAGER ---
        if user and user.manager_id:
            # Find manager
            manager = db.query(models.EmpDet).filter(models.EmpDet.emp_id == user.manager_id).first()
            if manager and manager.p_mail:
                print(f"📧 Sending Leave Request Email to Manager: {manager.name} ({manager.p_mail})")
                
                subject = f"Leave Request - {emp_name} ({emp_id})"
                body = f"""
                <html>
                <body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                    <h3>New Leave Request</h3>
                    <p><strong>Employee:</strong> {emp_name} ({emp_id})</p>
                    <p><strong>Leave Type:</strong> {leave_type}</p>
                    <p><strong>Dates:</strong> {from_date} to {to_date} ({days} days)</p>
                    <p><strong>Reason:</strong> {reason}</p>
                    <hr>
                    <p>Please review and approve/reject via the Aruvi Mobile App.</p>
                </body>
                </html>
                """
                # Send email
                send_email_notification(manager.p_mail, subject, body)
            else:
                print(f"⚠️ Manager info missing or no email found for ID: {user.manager_id}")
        else:
            print(f"⚠️ No manager assigned for employee: {emp_id}")
        
    except Exception as e:
        print(f"❌ DATABASE ERROR: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database Insertion Error: {str(e)}")
    
    return {
        "message": "Leave request submitted successfully",
        "leave_id": new_leave.l_id
    }

@app.post("/send-leave-notification")
def send_leave_notification(notification: dict, db: Session = Depends(get_db)):
    # Notification logic handled dynamically via status checks in dashboard
    # This endpoint is kept for frontend compatibility
    return {"message": "Notification processed"}

@app.get("/admin/pending-leaves")
def get_pending_leaves(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.EmpLeave, models.EmpDet).join(
        models.EmpDet, models.EmpLeave.emp_id == models.EmpDet.emp_id
    ).filter(models.EmpLeave.status == "Pending")
    
    # If manager_id provided, filter employees reporting to this manager
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
    
    # If manager_id provided, filter employees reporting to this manager
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
def approve_leave(request_item: schemas.LeaveApprovalAction, db: Session = Depends(get_db)):
    leave = db.query(models.EmpLeave).filter(models.EmpLeave.l_id == request_item.l_id).first()
    if not leave:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Leave request not found")
    
    old_status = leave.status
    leave.status = request_item.action
    leave.remarks = request_item.remarks
    leave.last_update_date = datetime.now()
    
    # Update approval columns based on action
    if request_item.action == 'Approved':
        leave.admin_approval = 'Approved'
        leave.hr_approval = 'Approved'
    elif request_item.action == 'Rejected':
        leave.admin_approval = 'Rejected'
        leave.hr_approval = 'Rejected'

    # Fetch admin name to store in approved_by
    admin_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == request_item.admin_id.strip()).first()
    if admin_user:
        leave.approved_by = admin_user.name
        leave.approver = admin_user.name
    
    # REVERT BALANCE IF REJECTED
    # If status becomes Rejected (and wasn't already), refund the days
    if request_item.action == 'Rejected' and old_status != 'Rejected':
        # Normalizing type search to find the correct row in xxits_leave_det_t
        # Use first word to match e.g. "Casual" in "Casual Leave"
        l_type_key = leave.leave_type.strip().lower().split(' ')[0]
        
        balance = db.query(models.LeaveDet).filter(
            func.lower(func.trim(models.LeaveDet.emp_id)) == leave.emp_id.lower(),
            func.lower(func.trim(models.LeaveDet.leave_type)).contains(l_type_key)
        ).first()

        if balance:
            l_days = float(leave.days or 0)
            # Revert availed (decrease usage)
            curr_availed = float(balance.availed_leave or 0)
            # Prevent negative availed just in case
            balance.availed_leave = max(0.0, curr_availed - l_days)
            
            # Revert available (increase remaining)
            if balance.available_leave is not None:
                balance.available_leave = float(balance.available_leave) + l_days
    
    # Note: If Approved, we do nothing to balance because it was already deducted during 'apply_leave'
    
    db.commit()
    
    # --- SEND EMAIL TO EMPLOYEE ---
    try:
        emp_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == leave.emp_id).first()
        if emp_user and emp_user.p_mail:
            status_msg = request_item.action.upper()
            subject = f"Leave Request {status_msg} - {leave.leave_type}"
            
            color = "green" if request_item.action.lower() == "approved" else "red"
            
            body = f"""
            <html>
            <body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                <h3>Leave Request Update</h3>
                <p>Dear {emp_user.name},</p>
                <p>Your leave request for <strong>{leave.leave_type}</strong> from {leave.from_date} has been <strong style="color: {color};">{status_msg}</strong>.</p>
                <p><strong>Remarks:</strong> {request_item.remarks or 'N/A'}</p>
                <p><strong>Action By:</strong> {leave.approved_by or 'Manager'}</p>
            </body>
            </html>
            """
            print(f"📧 Sending Leave Status Email to Employee: {emp_user.name}")
            send_email_notification(emp_user.p_mail, subject, body)
    except Exception as e:
        print(f"⚠️ Email notification failed: {e}")

    return {"message": f"Leave request {request_item.action.lower()} successfully", "approved_by": leave.approved_by}

@app.get("/notifications/{user_id}")
def get_notifications(user_id: str, role: str = "employee", manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    """
    Fetch notifications based on role:
    - Admin: Pending requests from subordinates (filtered by manager_id if provided)
    - Employee: Approved/Rejected requests for this employee (filtered by last clear date)
    """
    user_id = user_id.strip()
    notifications = []
    
    # Get user to check last clear date
    user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == user_id.lower()).first()
    
    last_clear_date = None
    if user and user.attribute8 and user.attribute8.strip():
        try:
            last_clear_date = datetime.strptime(user.attribute8.strip(), "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            print(f"⚠️ Could not parse attribute8 '{user.attribute8}': {e}")
    
    # Default cutoff to 30 days if no clear date exists
    effective_cutoff = last_clear_date if last_clear_date else (datetime.now() - timedelta(days=30))
    print(f"📅 Notifications for {user_id} | role={role} | attribute8='{user.attribute8 if user else 'N/A'}' | cutoff={effective_cutoff}")
    
    if role.lower() == 'admin':
        # ADMIN: Show Pending requests
        print(f"🔍 Discovery: Fetching ADMIN notifications for {user_id} (Mgr Param: '{manager_id}')")
        
        # 1. Pending Permission Requests
        query_pending_perms = db.query(models.EmpPermission, models.EmpDet).outerjoin(
            models.EmpDet, func.lower(func.trim(models.EmpPermission.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
        ).filter(func.lower(models.EmpPermission.status) == "pending")
        
        if manager_id and manager_id.strip().lower() != 'all':
            query_pending_perms = query_pending_perms.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())

        # For Admin Pending: Show if (CreationDate > Cutoff) OR (CreationDate is NULL)
        # This ensures old records with missing dates still show up for action.
        query_pending_perms = query_pending_perms.filter(
            or_(
                models.EmpPermission.creation_date > effective_cutoff,
                models.EmpPermission.creation_date == None
            )
        )
        
        pending_perms = query_pending_perms.order_by(models.EmpPermission.creation_date.desc()).all()
        print(f"   Found {len(pending_perms)} pending permissions matching criteria.")
        
        for perm, emp in pending_perms:
            try:
                emp_name = emp.name if emp else "Unknown"
                p_date_str = perm.date.strftime('%d-%b-%Y') if perm.date and hasattr(perm.date, 'strftime') else str(perm.date)
                f_time_str = perm.f_time.strftime('%I:%M %p') if perm.f_time and hasattr(perm.f_time, 'strftime') else str(perm.f_time)
                t_time_str = perm.t_time.strftime('%I:%M %p') if perm.t_time and hasattr(perm.t_time, 'strftime') else str(perm.t_time)
                
                notifications.append({
                    "id": f"permission_{perm.p_id}",
                    "record_id": perm.p_id,
                    "type": "pending",
                    "notification_type": "permission",
                    "title": f"Permission Request - {emp_name}",
                    "message": f"{p_date_str}: {f_time_str} - {t_time_str}",
                    "time": "Recently",
                    "icon": "time",
                    "screen": "/AdminPermission?tab=myApproval"
                })
            except Exception as e:
                print(f"   Error formatting permission {perm.p_id}: {e}")

        # 2. Pending Leave Requests
        query_pending_leaves = db.query(models.EmpLeave, models.EmpDet).outerjoin(
            models.EmpDet, func.lower(func.trim(models.EmpLeave.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
        ).filter(func.lower(models.EmpLeave.status) == "pending")
        
        if manager_id and manager_id.strip().lower() != 'all':
            query_pending_leaves = query_pending_leaves.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())

        query_pending_leaves = query_pending_leaves.filter(
            or_(
                models.EmpLeave.creation_date > effective_cutoff,
                models.EmpLeave.creation_date == None
            )
        )
        pending_leaves = query_pending_leaves.order_by(models.EmpLeave.creation_date.desc()).all()
        print(f"   Found {len(pending_leaves)} pending leaves matching criteria.")
        
        for leave, emp in pending_leaves:
            notifications.append({
                "id": f"leave_{leave.l_id}",
                "record_id": leave.l_id,
                "type": "pending",
                "notification_type": "leave",
                "title": f"Leave Request - {emp.name if emp else 'Unknown'}",
                "message": f"{leave.leave_type}: {leave.from_date} to {leave.to_date} ({leave.days} days)",
                "time": leave.applied_date or "Recently",
                "icon": "calendar",
                "screen": "/AdminLeave?tab=myApproval"
            })
        
        # 3. Pending OT Requests
        query_pending_ot = db.query(models.OverTimeDet, models.EmpDet).outerjoin(
            models.EmpDet, func.lower(func.trim(models.OverTimeDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
        ).filter(func.lower(models.OverTimeDet.status) == "pending")
        
        if manager_id and manager_id.strip().lower() != 'all':
            query_pending_ot = query_pending_ot.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())

        query_pending_ot = query_pending_ot.filter(
            or_(
                models.OverTimeDet.creation_date > effective_cutoff,
                models.OverTimeDet.creation_date == None
            )
        )
        pending_ot = query_pending_ot.order_by(models.OverTimeDet.creation_date.desc()).all()
        print(f"   Found {len(pending_ot)} pending OT matching criteria.")
        
        for ot, emp in pending_ot:
            notifications.append({
                "id": f"ot_{ot.ot_id}",
                "record_id": ot.ot_id,
                "type": "pending",
                "notification_type": "ot",
                "title": f"OT Request - {emp.name if emp else 'Unknown'}",
                "message": f"{ot.ot_date}: {ot.duration} hours",
                "time": ot.applied_date or "Recently",
                "icon": "briefcase",
                "screen": "/AdminOt?tab=myApproval"
            })

        # 4. Pending WFH Requests
        query_pending_wfh = db.query(models.WFHDet, models.EmpDet).outerjoin(
            models.EmpDet, func.lower(func.trim(models.WFHDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
        ).filter(func.lower(models.WFHDet.status) == "pending")
        
        if manager_id and manager_id.strip().lower() != 'all':
            query_pending_wfh = query_pending_wfh.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())

        query_pending_wfh = query_pending_wfh.filter(
            or_(
                models.WFHDet.creation_date > effective_cutoff,
                models.WFHDet.creation_date == None
            )
        )
        pending_wfh = query_pending_wfh.order_by(models.WFHDet.creation_date.desc()).all()
        print(f"   Found {len(pending_wfh)} pending WFH matching criteria.")
        
        for wfh, emp in pending_wfh:
            notifications.append({
                "id": f"wfh_{wfh.wfh_id}",
                "record_id": wfh.wfh_id,
                "type": "pending",
                "notification_type": "wfh",
                "title": f"WFH Request - {emp.name if emp else 'Unknown'}",
                "message": f"{wfh.from_date} to {wfh.to_date}",
                "time": "Recently",
                "icon": "home",
                "screen": "/AdminWfh?tab=myApproval"
            })
    
    else:
        # EMPLOYEE: Show Approved requests for this employee (Only Approved as requested)
        print(f"🔍 Fetching EMPLOYEE notifications for {user_id} (Only Approved)")
        
        # 1. Approved Leaves
        query_leaves = db.query(models.EmpLeave).filter(
            func.lower(func.trim(models.EmpLeave.emp_id)) == user_id.lower(),
            func.lower(models.EmpLeave.status) == "approved",
            models.EmpLeave.last_update_date > effective_cutoff
        )
        approved_leaves = query_leaves.order_by(models.EmpLeave.last_update_date.desc()).limit(20).all()
        
        for leave in approved_leaves:
            notifications.append({
                "id": f"leave_{leave.l_id}_approved",
                "record_id": leave.l_id,
                "type": "success",
                "notification_type": "leave",
                "title": "Leave Approved ✅",
                "message": f"Your {leave.leave_type} from {leave.from_date} was approved",
                "time": "Recently",
                "icon": "checkmark-circle",
                "screen": f"/EmployeeLeave?tab=history&id={leave.l_id}"
            })
        
        # 2. Approved Permissions
        query_perms = db.query(models.EmpPermission).filter(
            func.lower(func.trim(models.EmpPermission.emp_id)) == user_id.lower(),
            func.lower(models.EmpPermission.status) == "approved",
            models.EmpPermission.last_update_date > effective_cutoff
        )
        approved_perms = query_perms.order_by(models.EmpPermission.last_update_date.desc()).limit(20).all()
        
        for perm in approved_perms:
            p_date_str = perm.date.strftime('%d-%b-%Y') if perm.date and hasattr(perm.date, 'strftime') else str(perm.date)
            notifications.append({
                "id": f"permission_{perm.p_id}_approved",
                "record_id": perm.p_id,
                "type": "success",
                "notification_type": "permission",
                "title": "Permission Approved ✅",
                "message": f"Your permission on {p_date_str} was approved",
                "time": "Recently",
                "icon": "checkmark-circle",
                "screen": f"/EmployeePermission?tab=history&id={perm.p_id}"
            })

        # 3. Approved OT
        query_ot = db.query(models.OverTimeDet).filter(
            func.lower(func.trim(models.OverTimeDet.emp_id)) == user_id.lower(),
            func.lower(models.OverTimeDet.status) == "approved",
            models.OverTimeDet.last_update_date > effective_cutoff
        )
        approved_ot = query_ot.order_by(models.OverTimeDet.last_update_date.desc()).limit(20).all()

        for ot in approved_ot:
            notifications.append({
                "id": f"ot_{ot.ot_id}_approved",
                "record_id": ot.ot_id,
                "type": "success",
                "notification_type": "ot",
                "title": "OT Approved ✅",
                "message": f"Your OT on {ot.ot_date} was approved",
                "time": "Recently",
                "icon": "checkmark-circle",
                "screen": f"/EmployeeOt?tab=history&id={ot.ot_id}"
            })

        # 4. Approved WFH
        query_wfh = db.query(models.WFHDet).filter(
            func.lower(func.trim(models.WFHDet.emp_id)) == user_id.lower(),
            func.lower(models.WFHDet.status) == "approved",
            models.WFHDet.last_update_date > effective_cutoff
        )
        approved_wfh = query_wfh.order_by(models.WFHDet.last_update_date.desc()).limit(20).all()

        for wfh in approved_wfh:
            notifications.append({
                "id": f"wfh_{wfh.wfh_id}_approved",
                "record_id": wfh.wfh_id,
                "type": "success",
                "notification_type": "wfh",
                "title": "WFH Approved ✅",
                "message": f"Your WFH request from {wfh.from_date} was approved",
                "time": "Recently",
                "icon": "home",
                "screen": f"/EmployeeWfh?tab=history&id={wfh.wfh_id}"
            })
    
    print(f"✅ Returning {len(notifications)} notifications for {user_id}")
    return notifications

@app.post("/notifications/clear-all/{user_id}")
def clear_all_notifications(user_id: str, db: Session = Depends(get_db)):
    """
    Clears all notifications for a user by updating attribute8 with the current timestamp.
    """
    user_id = user_id.strip()
    user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == user_id.lower()).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.attribute8 = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.commit()
    return {"message": "All notifications cleared"}


@app.post("/apply-permission")
def apply_permission(request: schemas.PermissionApplyRequest, db: Session = Depends(get_db)):
    from datetime import datetime, time
    
    # Robust emp_id handling
    target_emp_id = request.emp_id.strip()
    
    # Check balance
    user = db.query(models.EmpDet).filter(
        (models.EmpDet.emp_id == target_emp_id) | 
        (models.EmpDet.emp_id == request.emp_id)
    ).first()

    if not user:
        # Try fuzzy match if exact match fails (to handle spaces in DB)
        user = db.query(models.EmpDet).filter(func.trim(models.EmpDet.emp_id) == target_emp_id).first()

    if not user:
        print(f"❌ Employee NOT FOUND: '{request.emp_id}'")
        raise HTTPException(status_code=404, detail=f"Employee {request.emp_id} not found")
        
    try:
        # Robust time parsing
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
        
        p_date = p_date_dt.date() # Convert to date object for SQLAlchemy Date column
        
        # Calculate total duration in minutes
        h1, m1 = f_time.hour, f_time.minute
        h2, m2 = t_time.hour, t_time.minute
        diff_mins = (h2 * 60 + m2) - (h1 * 60 + m1)
        
        # Handle overnight case if needed, though usually permissions are same day
        if diff_mins < 0:
            diff_mins += 24 * 60
            
        if diff_mins <= 0:
            raise HTTPException(status_code=400, detail="To Time must be after From Time")
            
        duration_hrs = diff_mins / 60.0
        
        # MAX 4 HOURS VALIDATION
        if duration_hrs > 4:
            raise HTTPException(status_code=400, detail="Permission duration cannot exceed 4 hours")
            
        # LOP LOGIC (Standard: 2 hours allowed, rest is LOP)
        approved_hrs = min(duration_hrs, 2.0)
        lop_hrs = max(0.0, duration_hrs - 2.0)
        
        # Use frontend values if provided, otherwise defaults
        final_total_hours = request.total_hours if request.total_hours is not None else f"{duration_hrs:.1f}"
        final_dis_total_hours = request.dis_total_hours if request.dis_total_hours is not None else f"{lop_hrs:.1f}"
        final_status = request.status if request.status else "Pending"

        # Immediate deduction logic (Approved hours only)
        new_remaining = 0.0
        try:
            curr_val = str(user.remaining_perm or "0").strip()
            curr_perm = float(curr_val) if curr_val else 0.0
            new_remaining = max(0.0, curr_perm - approved_hrs)
            user.remaining_perm = str(new_remaining)
            print(f"📉 DEDUCTED: {approved_hrs}h from {curr_perm}h. New: {new_remaining}h")
        except Exception as bal_err:
            print(f"⚠️ Balance update error: {bal_err}")
        
        print(f"🚀 ATTEMPTING PERMISSION INSERT: Emp='{user.emp_id}', Date={p_date}, Total={final_total_hours}")
        
        new_perm = models.EmpPermission(
            emp_id=user.emp_id, # Use the official ID from the database
            date=p_date,
            f_time=f_time,
            t_time=t_time,
            reason=request.reason,
            total_hours=final_total_hours,
            dis_total_hours=final_dis_total_hours,
            available_hours=str(new_remaining), # Mandatory field
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

        # --- SEND EMAIL TO MANAGER ---
        if user and user.manager_id:
            # Find manager
            manager = db.query(models.EmpDet).filter(
                func.lower(func.trim(models.EmpDet.emp_id)) == user.manager_id.strip().lower()
            ).first()
            
            if manager and manager.p_mail:
                print(f"📧 Sending Permission Request Email to Manager: {manager.name} ({manager.p_mail})")
                
                # Format date and times
                p_date_str = p_date.strftime("%d-%b-%Y")
                f_time_str = f_time.strftime("%I:%M %p")
                t_time_str = t_time.strftime("%I:%M %p")
                
                customer_name = user.attribute3 if user.attribute3 else "Internal"
                duration_str = f"{duration_hrs:.1f}"
                
                subject = f"ITS - {user.name} – {customer_name} - Permission | {p_date_str} | {f_time_str} to {t_time_str} ({duration_str} Hours)"
                
                body = f"""
                <html>
                <body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                    <p>Dear {manager.name},</p>
                    <p>Good Evening! I hope you are doing well.</p>
                    <p>I would like to request permission to take leave from <strong>{f_time_str}</strong> to <strong>{t_time_str}</strong> (<strong>{duration_str} hours</strong>) on <strong>{p_date_str}</strong> due to: {request.reason}</p>
                    <p>Kindly approve the same to proceed.</p>
                    <p>Thanks & Regards,<br>
                    <strong>{user.name}</strong></p>
                </body>
                </html>
                """
                send_email_notification(manager.p_mail, subject, body)
            else:
                print(f"⚠️ Manager email missing or not found for Manager ID: {user.manager_id}")
        else:
            print(f"⚠️ No manager assigned for employee: {user.emp_id}")

        return {
            "message": "Permission request submitted successfully",
            "p_id": new_perm.p_id
        }
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
def approve_permission(request: schemas.PermissionApprovalAction, db: Session = Depends(get_db)):
    perm = db.query(models.EmpPermission).filter(models.EmpPermission.p_id == request.p_id).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission request not found")
        
    old_status = perm.status
    perm.status = request.action
    perm.remarks = request.remarks
    perm.last_update_date = datetime.now()
    
    print(f"✅ Permission {request.p_id} status updated: {old_status} → {request.action}")
    print(f"   Employee: {perm.emp_id}, Timestamp: {perm.last_update_date}")

    # Fetch admin name to store in remarks or approved_by (using remarks as proxy if approved_by not in perm model, 
    # but let's check models.py - EmpPermission has p_id, emp_id, date, f_time, t_time, reason, remarks, total_hours, status, creation_date, last_update_date)
    # EmpPermission doesn't have approved_by in models.py, so we'll store in remarks or skip.
    admin_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == request.admin_id.strip()).first()
    if admin_user:
        perm.remarks = f"{(request.remarks or '')} (Action by: {admin_user.name})".strip()
        perm.approved_by = admin_user.name
    
    # Revert balance if rejected
    if request.action == 'Rejected' and old_status != 'Rejected':
        user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == perm.emp_id).first()
        if user:
            # Parse total_hours and dis_total_hours to find the "Approved" part to refund
            def parse_duration_to_hours(s):
                if not s: return 0.0
                s = str(s).lower().strip()
                # Handle "1.0" or "1"
                try: return float(s)
                except: pass
                # Handle "1h 30m"
                try:
                    parts = s.split(' ')
                    h = float(parts[0].replace('h', '')) if 'h' in parts[0] else 0.0
                    m = 0.0
                    if len(parts) > 1 and 'm' in parts[1]:
                        m = float(parts[1].replace('m', ''))
                    elif len(parts) > 1: # Maybe it's just a number
                        m = float(parts[1])
                    return h + (m/60.0)
                except:
                    return 0.0

            try:
                # Based on the new apply_permission logic:
                # Approved = total_hours (Total) - dis_total_hours (LOP)
                # But wait, if total_hours ALREADY only contained Approved part, then this is wrong.
                # To be safe, let's recalculate based on the times if they are in the DB.
                if perm.f_time and perm.t_time:
                    h1, m1 = perm.f_time.hour, perm.f_time.minute
                    h2, m2 = perm.t_time.hour, perm.t_time.minute
                    diff = (h2 * 60 + m2) - (h1 * 60 + m1)
                    if diff < 0: diff += 24 * 60
                    approved_to_refund = min(diff / 60.0, 2.0)
                else:
                    # Fallback to parsing strings
                    total = parse_duration_to_hours(perm.total_hours)
                    lop = parse_duration_to_hours(perm.dis_total_hours)
                    # If total is 3.0 and lop is 1.0, then 2.0 was approved.
                    # But if total was 2.0 and lop was 1.0 (old logic), then 2.0 was approved? 
                    # No, old logic: total_hours was approved_hrs.
                    # If we follow the current user's rule: total_hours is Total Duration.
                    approved_to_refund = total - lop
                
                curr_perm = float(user.remaining_perm or 0)
                user.remaining_perm = str(curr_perm + approved_to_refund)
            except Exception as e:
                print(f"Refund error: {e}")
                pass
                
    db.commit()

    # --- SEND EMAIL TO EMPLOYEE ---
    try:
        emp_user = db.query(models.EmpDet).filter(
            func.lower(func.trim(models.EmpDet.emp_id)) == perm.emp_id.strip().lower()
        ).first()

        if emp_user and emp_user.p_mail:
            status_msg = request.action.upper()
            perm_date = perm.date.strftime("%d-%b-%Y") if perm.date else "N/A"
            subject = f"Permission Request {status_msg} - {perm_date}"
            
            color = "green" if request.action.lower() == "approved" else "red"
            manager_name = admin_user.name if admin_user else "Manager"
            f_time_str = perm.f_time.strftime("%I:%M %p") if perm.f_time else "N/A"
            t_time_str = perm.t_time.strftime("%I:%M %p") if perm.t_time else "N/A"
            
            body = f"""
            <html>
            <body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                <h3>Permission Request Update</h3>
                <p>Dear {emp_user.name},</p>
                <p>Your permission request for <strong>{perm_date}</strong> (<strong>{f_time_str}</strong> to <strong>{t_time_str}</strong>) has been <strong style="color: {color};">{status_msg}</strong>.</p>
                <p><strong>Remarks:</strong> {request.remarks or 'N/A'}</p>
                <p><strong>Action By:</strong> {manager_name}</p>
                <br>
                <p>Please check your Aruvi Mobile App for details.</p>
                <p>Thanks & Regards,<br>Ilan Tech Solutions</p>
            </body>
            </html>
            """
            print(f"📧 Sending Permission Status Email to Employee: {emp_user.name} ({emp_user.p_mail})")
            send_email_notification(emp_user.p_mail, subject, body)
    except Exception as e:
        print(f"⚠️ Email notification failed: {e}")

    return {"message": f"Permission {request.action.lower()} successfully"}

@app.get("/admin/pending-ot")
def get_pending_ot(manager_id: Optional[str] = None, db: Session = Depends(get_db)):
    print("\n🔍 Fetching Pending OT for Admin Approval")
    
    query = db.query(models.OverTimeDet, models.EmpDet).outerjoin(
        models.EmpDet, func.lower(func.trim(models.OverTimeDet.emp_id)) == func.lower(func.trim(models.EmpDet.emp_id))
    ).filter(func.lower(models.OverTimeDet.status) == "pending")

    if manager_id:
        query = query.filter(func.lower(func.trim(models.EmpDet.manager_id)) == manager_id.strip().lower())

    pending = query.order_by(models.OverTimeDet.creation_date.desc()).all()
    
    print(f"  ADMIN: Found {len(pending)} pending OT records")
    
    results = []
    for ot, emp in pending:
        results.append({
            "ot_id": ot.ot_id,
            "emp_name": emp.name if emp else (f"Unknown ({ot.emp_id})"),
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
            "ot_id": ot.ot_id,
            "emp_name": emp.name if emp else (f"Unknown ({ot.emp_id})"),
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

@app.post("/admin/approve-ot")
def approve_ot(request: schemas.OverTimeApprovalAction, db: Session = Depends(get_db)):
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

    # --- SEND EMAIL TO EMPLOYEE ---
    try:
        emp_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == ot.emp_id).first()
        if emp_user and emp_user.p_mail:
            status_msg = request.action.upper()
            subject = f"OT Request {status_msg} - {ot.ot_date}"
            
            color = "green" if request.action.lower() == "approved" else "red"
            manager_name = admin_user.name if admin_user else "Manager"
            
            body = f"""
            <html>
            <body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                <h3>OT Request Update</h3>
                <p>Dear {emp_user.name},</p>
                <p>Your Overtime request for <strong>{ot.ot_date}</strong> ({ot.duration}) has been <strong style="color: {color};">{status_msg}</strong>.</p>
                <p><strong>Remarks:</strong> {request.remarks or 'N/A'}</p>
                <p><strong>Approved/Action By:</strong> {manager_name}</p>
                <br>
                <p>Thanks & Regards,<br>Ilan Tech Solutions</p>
            </body>
            </html>
            """
            print(f"📧 Sending OT Status Email to Employee: {emp_user.name}")
            send_email_notification(emp_user.p_mail, subject, body)
    except Exception as e:
        print(f"⚠️ Email notification failed: {e}")

    return {"message": f"OT request {request.action.lower()} successfully"}


@app.post("/apply-ot")
def apply_ot(request: schemas.OverTimeApplyRequest, db: Session = Depends(get_db)):
    from datetime import datetime
    try:
        # Check if employee exists
        user = db.query(models.EmpDet).filter(func.trim(models.EmpDet.emp_id) == request.emp_id.strip()).first()
        if not user:
            raise HTTPException(status_code=404, detail="Employee not found")

        # Official ID from DB
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
        print(f"✅ OT INSERT SUCCESS: ID={new_ot.ot_id} for {target_emp_id}")

        # --- SEND EMAIL TO MANAGER ---
        if user and user.manager_id:
            # Find manager
            manager = db.query(models.EmpDet).filter(
                func.trim(models.EmpDet.emp_id) == user.manager_id.strip()
            ).first()
            
            if manager and manager.p_mail:
                print(f"📧 Sending OT Request Email to Manager: {manager.name} ({manager.p_mail})")
                
                # Format date as DD-Mmm-YYYY
                try:
                    ot_date_dt = parse_date(request.ot_date)
                    ot_date_str = ot_date_dt.strftime("%d-%b-%Y") if ot_date_dt else request.ot_date
                except:
                    ot_date_str = request.ot_date
                
                # Customer Name (Try attribute3 or default to Internal)
                customer_name = user.attribute3 if user.attribute3 else "Internal"
                
                # Subject: ITS - Employee Name – Customer Name/Internal - Overtime | DD-Mmm-YYYY | HH:MM AM to HH:MM PM (Duration)
                subject = f"ITS - {user.name} – {customer_name} - Overtime | {ot_date_str} | {request.from_time} to {request.to_time} ({request.duration})"
                
                body = f"""
                <html>
                <body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                    <p>Dear {manager.name} ,</p>
                    <p>Good Evening! I hope you are doing well. </p>
                    <p>I would like to request permission to do overtime work on {ot_date_str} from {request.from_time} to {request.to_time} ({request.duration}) for {request.reason}</p>
                    <p>Kindly, Approve the same to proceed.</p>
                    <p>Thanks & Regards,<br>
                    <strong>{user.name}</strong></p>
                </body>
                </html>
                """
                # Send email
                send_email_notification(manager.p_mail, subject, body)
            else:
                print(f"⚠️ Manager info missing or no email found for ID: {user.manager_id}")
        else:
            print(f"⚠️ No manager assigned for employee: {target_emp_id}")

        return {"message": "OT request submitted successfully", "ot_id": new_ot.ot_id}
    except Exception as e:
        print(f"❌ OT INSERT ERROR: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/ot-stats/{emp_id}")
def get_ot_stats(emp_id: str, db: Session = Depends(get_db)):
    import re
    
    emp_id = emp_id.strip()
    
    print(f"\n🕒 Fetching OT Stats for emp_id: {emp_id}")
    
    ot_records = db.query(models.OverTimeDet).filter(func.lower(func.trim(models.OverTimeDet.emp_id)) == emp_id.lower()).all()
    
    print(f"📊 Found {len(ot_records)} OT records")
    
    total_ot = 0.0
    approved_ot = 0.0
    
    def parse_duration(duration_str):
        """
        Parse duration string and return hours as float.
        """
        if not duration_str:
            return 0.0
        
        duration_str = str(duration_str).strip()
        
        # Try plain float first
        try:
            return float(duration_str)
        except ValueError:
            pass
        
        # Try "Xh Ym" or "X Hr Y Min" format
        hr_match = re.search(r'(\d+)\s*(h|hr)', duration_str, re.IGNORECASE)
        min_match = re.search(r'(\d+)\s*(m|min)', duration_str, re.IGNORECASE)
        
        if hr_match or min_match:
            hours = float(hr_match.group(1)) if hr_match else 0.0
            minutes = float(min_match.group(1)) if min_match else 0.0
            return hours + (minutes / 60.0)
        
        # Try "H:MM" format
        if ':' in duration_str:
            parts = duration_str.split(':')
            if len(parts) == 2:
                try:
                    hours = float(parts[0])
                    minutes = float(parts[1])
                    return hours + (minutes / 60.0)
                except:
                    pass
        
        print(f"  ⚠️ Could not parse duration: '{duration_str}', using 0")
        return 0.0
    
    for row in ot_records:
        try:
            duration_str = row.duration or "0"
            d = parse_duration(duration_str)
            
            print(f"  OT ID {row.ot_id}: Date={row.ot_date}, Duration={duration_str} -> {d}h, Status={row.status}")
            
            total_ot += d
            if row.status and row.status.lower() == 'approved':
                approved_ot += d
        except Exception as e:
            print(f"  ⚠️ Unexpected error for OT ID {row.ot_id}: {e}")
            continue
    
    print(f"✅ Total OT: {total_ot}h, Approved OT: {approved_ot}h\n")
    
    return {
        "total": round(total_ot, 2),
        "approved": round(approved_ot, 2)
    }

@app.get("/ot-history/{emp_id}")
def get_ot_history(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    history = db.query(models.OverTimeDet).filter(func.lower(func.trim(models.OverTimeDet.emp_id)) == emp_id.lower()).order_by(models.OverTimeDet.ot_id.desc()).all()
    return history

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
            "wfh_id": wfh.wfh_id,
            "emp_name": emp.name or "Unknown",
            "emp_id": emp.emp_id or "N/A",
            "date": wfh.from_date,
            "from_date": wfh.from_date,
            "to_date": wfh.to_date,
            "reason": wfh.reason or "No reason",
            "remarks": wfh.remarks or "",
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
                "wfh_id": wfh.wfh_id,
                "emp_name": emp.name if emp else "Unknown",
                "emp_id": wfh.emp_id,
                "date": wfh.from_date,
                "from_date": wfh.from_date,
                "to_date": wfh.to_date,
                "days": wfh.days,
                "approved_by": wfh.approved_by,
                "reason": wfh.reason or "No reason",
                "remarks": wfh.remarks or "",
                "status": wfh.status or "Pending",
                "submittedDate": wfh.creation_date.strftime("%d-%b-%Y") if wfh.creation_date else "N/A"
            })
        return results
    except Exception as e:
        print(f"❌ ERROR in get_all_wfh_history: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/approve-wfh")
def approve_wfh(request: schemas.WFHApprovalAction, db: Session = Depends(get_db)):
    wfh = db.query(models.WFHDet).filter(models.WFHDet.wfh_id == request.wfh_id).first()
    if not wfh:
        raise HTTPException(status_code=404, detail="WFH request not found")
        
    wfh.status = request.action
    wfh.remarks = request.remarks
    wfh.last_update_date = datetime.now()
    
    admin_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == request.admin_id.strip()).first()
    if admin_user:
        wfh.approved_by = admin_user.name
        wfh.remarks = f"{(request.remarks or '').strip()} (Action by: {admin_user.name})".strip()
        
    db.commit()

    # --- SEND EMAIL TO EMPLOYEE ---
    try:
        emp_user = db.query(models.EmpDet).filter(models.EmpDet.emp_id == wfh.emp_id).first()
        if emp_user and emp_user.p_mail:
            status_msg = request.action.upper()
            subject = f"WFH Request {status_msg} - {wfh.from_date}"
            
            color = "green" if request.action.lower() == "approved" else "red"
            manager_name = admin_user.name if admin_user else "Manager"
            
            body = f"""
            <html>
            <body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                <h3>WFH Request Update</h3>
                <p>Dear {emp_user.name},</p>
                <p>Your Work From Home request for <strong>{wfh.from_date}</strong> has been <strong style="color: {color};">{status_msg}</strong>.</p>
                <p><strong>Remarks:</strong> {request.remarks or 'N/A'}</p>
                <p><strong>Approved/Action By:</strong> {manager_name}</p>
                <br>
                <p>Thanks & Regards,<br>Ilan Tech Solutions</p>
            </body>
            </html>
            """
            print(f"📧 Sending WFH Status Email to Employee: {emp_user.name}")
            send_email_notification(emp_user.p_mail, subject, body)
    except Exception as e:
        print(f"⚠️ Email notification failed: {e}")

    return {"message": f"WFH request {request.action.lower()} successfully"}


@app.get("/wfh-stats/{emp_id}")
def get_wfh_stats(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    
    print(f"\n🏠 Fetching WFH Stats for emp_id: {emp_id}")
    
    wfh_records = db.query(models.WFHDet).filter(func.lower(func.trim(models.WFHDet.emp_id)) == emp_id.lower()).all()
    
    print(f"📊 Found {len(wfh_records)} WFH records")
    
    total_wfh = len(wfh_records)
    approved_wfh = 0
    rejected_wfh = 0
    
    for row in wfh_records:
        if row.status and row.status.lower() == 'approved':
            approved_wfh += 1
        elif row.status and row.status.lower() == 'rejected':
            rejected_wfh += 1
        print(f"  WFH ID {row.wfh_id}: Date={row.from_date}, Status={row.status}")
    
    print(f"✅ Total WFH: {total_wfh}, Approved WFH: {approved_wfh}, Rejected WFH: {rejected_wfh}\n")
    
    return {
        "total": total_wfh,
        "approved": approved_wfh,
        "rejected": rejected_wfh
    }



@app.post("/apply-wfh")
def apply_wfh(request: schemas.WFHApplyRequest, db: Session = Depends(get_db)):
    try:
        from datetime import datetime
        new_wfh = models.WFHDet(
            emp_id=request.emp_id,
            from_date=request.date,
            to_date=request.date, # Single day for now
            days="1",
            reason=request.reason,
            status=request.status or "Pending",
            created_by=request.emp_id,
            creation_date=datetime.now(),
            last_updated_by=request.emp_id,
            last_update_date=datetime.now(),
            last_update_login=request.emp_id,
            approved_by="",
            remarks=""
        )
        db.add(new_wfh)
        db.commit()
        db.refresh(new_wfh)

        # --- SEND EMAIL TO MANAGER ---
        # Get employee details for manager_id and name
        user = db.query(models.EmpDet).filter(func.trim(models.EmpDet.emp_id) == request.emp_id.strip()).first()
        if user and user.manager_id:
            # Find manager
            manager = db.query(models.EmpDet).filter(
                func.trim(models.EmpDet.emp_id) == user.manager_id.strip()
            ).first()
            
            if manager and manager.p_mail:
                print(f"📧 Sending WFH Request Email to Manager: {manager.name} ({manager.p_mail})")
                
                # Format date as DD-Mmm-YYYY
                try:
                    wfh_date_dt = parse_date(request.date)
                    wfh_date_str = wfh_date_dt.strftime("%d-%b-%Y") if wfh_date_dt else request.date
                except:
                    wfh_date_str = request.date
                
                # Customer Name (Try attribute3 or default to Internal)
                customer_name = user.attribute3 if user.attribute3 else "Internal"
                
                # Subject: ITS - Employee Name – Customer Name/Internal - WFH | DD-Mmm-YYYY
                subject = f"ITS - {user.name} – {customer_name} - WFH | {wfh_date_str}"
                
                body = f"""
                <html>
                <body style="font-family: 'Times New Roman', Times, serif; color: #00008B;">
                    <p>Dear {manager.name} ,</p>
                    <p>Good Evening! I hope you are doing well. </p>
                    <p>I would like to request Work From Home for {wfh_date_str} (1 Day) due to {request.reason}</p>
                    <p>Kindly, Approve the same to proceed.</p>
                    <p>Thanks & Regards,<br>
                    <strong>{user.name}</strong></p>
                </body>
                </html>
                """
                # Send email
                send_email_notification(manager.p_mail, subject, body)
            else:
                print(f"⚠️ Manager info missing or no email found for ID: {user.manager_id}")
        else:
            print(f"⚠️ No manager assigned or employee not found: {request.emp_id}")

        return {"message": "WFH request submitted successfully", "wfh_id": new_wfh.wfh_id}
    except Exception as e:
        print(f"❌ WFH INSERT ERROR: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/wfh-history/{emp_id}")
def get_wfh_history(emp_id: str, db: Session = Depends(get_db)):
    history = db.query(models.WFHDet).filter(func.lower(func.trim(models.WFHDet.emp_id)) == emp_id.lower()).order_by(models.WFHDet.wfh_id.desc()).all()
    results = []
    for row in history:
        results.append({
            "id": row.wfh_id,
            "date": row.from_date,
            "reason": row.reason,
            "status": row.status,
            "submittedDate": row.creation_date.strftime("%Y-%m-%d") if row.creation_date else "N/A"
        })
    return results

@app.get("/permission-stats/{emp_id}")
def get_permission_stats(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
    if not user:
        return {"total": 0, "remaining": 0}
    
    try:
        # Based on user request: column 'permission' as Total and 'remaining_perm' as Remaining
        total = float(user.permission or 0)
        remaining = float(user.remaining_perm or 0)
    except:
        total = 0
        remaining = 0
        
    return {"total": total, "remaining": remaining}


@app.get("/permission-history/{emp_id}")
def get_permission_history(emp_id: str, db: Session = Depends(get_db)):
    history = db.query(models.EmpPermission).filter(func.lower(func.trim(models.EmpPermission.emp_id)) == emp_id.lower()).order_by(models.EmpPermission.p_id.desc()).all()
    results = []
    for row in history:
        results.append({
            "p_id": row.p_id,
            "emp_id": row.emp_id,
            "date": row.date.strftime("%d-%b-%Y") if row.date else "",
            "f_time": row.f_time.strftime("%H:%M") if row.f_time else "",
            "t_time": row.t_time.strftime("%H:%M") if row.t_time else "",
            "total_hours": row.total_hours,
            "dis_total_hours": row.dis_total_hours,
            "reason": row.reason,
            "status": row.status,
            "remarks": row.remarks,
            "creation_date": row.creation_date,
            "last_update_date": row.last_update_date
        })
    return results



@app.get("/dashboard/{emp_id}", response_model=schemas.DashboardResponse)
def get_dashboard(emp_id: str, db: Session = Depends(get_db)):
    emp_id = emp_id.strip()
    user = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.emp_id)) == emp_id.lower()).first()
    if not user:
        # Check if any user exists at all for debugging
        all_count = db.query(models.EmpDet).count()
        if all_count == 0:
            raise HTTPException(status_code=404, detail="No employees in database")
        raise HTTPException(status_code=404, detail=f"User {emp_id} not found")

    today = datetime.now()
    
    domain_name = "Employee"
    if user.dom_id:
        try:
            # Handle string vs integer match for dom_id
            d_id = int(str(user.dom_id).strip())
            domain = db.query(models.Domain).filter(models.Domain.dom_id == d_id).first()
            if domain:
                domain_name = domain.domain
        except:
            pass

    # Exclude employees with end_date (inactive)
    all_emps = db.query(models.EmpDet).filter(
        (models.EmpDet.end_date == None) | (models.EmpDet.end_date == "")
    ).all()
    upcoming_events = []
    
    for emp in all_emps:
        # Birthday
        if emp.dob:
            bday = parse_date(emp.dob)
            if bday:
                next_bday = bday.replace(year=today.year)
                if next_bday < today.replace(hour=0, minute=0, second=0, microsecond=0):
                    next_bday = next_bday.replace(year=today.year + 1)
                
                days_until = (next_bday - today).days
                if 0 <= days_until <= 60: # Extended to 60 days
                    upcoming_events.append({
                        "id": f"bday_{emp.emp_id}_{next_bday.strftime('%Y%m%d')}",
                        "name": f"{emp.name}'s Birthday",
                        "type": "birthday",
                        "date": next_bday.strftime("%d %b"),
                        "day": next_bday.strftime("%A"),
                        "raw_date": next_bday
                    })
        
        # Anniversary
        if emp.date_of_joining:
            join_date = parse_date(emp.date_of_joining)
            if join_date:
                next_anniv = join_date.replace(year=today.year)
                if next_anniv < today.replace(hour=0, minute=0, second=0, microsecond=0):
                    next_anniv = next_anniv.replace(year=today.year + 1)
                
                days_until = (next_anniv - today).days
                if 0 <= days_until <= 60:
                    upcoming_events.append({
                        "id": f"anniv_{emp.emp_id}_{next_anniv.strftime('%Y%m%d')}",
                        "name": f"{emp.name}'s Anniversary",
                        "type": "anniversary",
                        "date": next_anniv.strftime("%d %b"),
                        "day": next_anniv.strftime("%A"),
                        "raw_date": next_anniv
                    })
        
    # Sort upcoming events
    upcoming_events.sort(key=lambda x: x["raw_date"])
    for event in upcoming_events:
        del event["raw_date"]


    # Dynamic Notifications
    notifications = []
    
    # Check if user is admin
    is_admin = False
    if user.dom_id:
        try:
            d_id = int(str(user.dom_id).strip())
            user_domain = db.query(models.Domain).filter(models.Domain.dom_id == d_id).first()
            if user_domain:
                domain_name = user_domain.domain.lower()
                if 'admin' in domain_name or 'management' in domain_name:
                    is_admin = True
        except:
            pass
    
    print(f"DEBUG: get_dashboard for {emp_id}, is_admin={is_admin}")
    
    # Filter for notifications: Last 7 days to keep it clean (Avoid old data)
    recent_date_limit = datetime.now() - timedelta(days=7)
    
    # 1. Admin Notifications: Pending Leaves & Permissions
    # Check if user is manager (has subordinates)
    is_manager = db.query(models.EmpDet).filter(func.lower(func.trim(models.EmpDet.manager_id)) == emp_id.lower()).first() is not None

    # 1. Admin/Manager Notifications: Pending Leaves & Permissions
    if is_admin:
        try:
            # Pending Leaves (ALL)
            pending_leaves = db.query(models.EmpLeave, models.EmpDet.name)\
                .join(models.EmpDet, models.EmpLeave.emp_id == models.EmpDet.emp_id)\
                .filter(models.EmpLeave.status == 'Pending')\
                .order_by(models.EmpLeave.creation_date.desc())\
                .limit(5).all()
                
            for leave, name in pending_leaves:
                notifications.append({
                    "id": f"admin_leave_{leave.l_id}",
                    "title": "New Leave Request",
                    "message": f"{name} applied for {leave.leave_type} ({leave.days} days)",
                    "time": leave.creation_date.strftime("%Y-%m-%d %H:%M") if leave.creation_date else "",
                    "type": "alert",
                    "icon": "mail-unread-outline"
                })

            # Pending Permissions (ALL)
            pending_perms = db.query(models.EmpPermission, models.EmpDet.name)\
                .join(models.EmpDet, models.EmpPermission.emp_id == models.EmpDet.emp_id)\
                .filter(models.EmpPermission.status == 'Pending')\
                .order_by(models.EmpPermission.creation_date.desc())\
                .limit(5).all()
                
            for perm, name in pending_perms:
                notifications.append({
                    "id": f"admin_perm_{perm.p_id}",
                    "title": "New Permission Request",
                    "message": f"{name} requested permission for {perm.total_hours}",
                    "time": perm.creation_date.strftime("%Y-%m-%d %H:%M") if perm.creation_date else "",
                    "type": "alert",
                    "icon": "time-outline"
                })
        except Exception as e:
            print(f"Error fetching admin notifications: {e}")
            
    elif is_manager:
        try:
            # Pending Leaves (MANAGER TEAM ONLY)
            pending_leaves = db.query(models.EmpLeave, models.EmpDet.name)\
                .join(models.EmpDet, models.EmpLeave.emp_id == models.EmpDet.emp_id)\
                .filter(models.EmpLeave.status == 'Pending')\
                .filter(func.lower(func.trim(models.EmpDet.manager_id)) == emp_id.lower())\
                .order_by(models.EmpLeave.creation_date.desc())\
                .limit(5).all()
                
            for leave, name in pending_leaves:
                notifications.append({
                    "id": f"mgr_leave_{leave.l_id}",
                    "title": "New Leave Request (Team)",
                    "message": f"{name} applied for {leave.leave_type} ({leave.days} days)",
                    "time": leave.creation_date.strftime("%Y-%m-%d %H:%M") if leave.creation_date else "",
                    "type": "alert",
                    "icon": "mail-unread-outline"
                })

            # Pending Permissions (MANAGER TEAM ONLY)
            pending_perms = db.query(models.EmpPermission, models.EmpDet.name)\
                .join(models.EmpDet, models.EmpPermission.emp_id == models.EmpDet.emp_id)\
                .filter(models.EmpPermission.status == 'Pending')\
                .filter(func.lower(func.trim(models.EmpDet.manager_id)) == emp_id.lower())\
                .order_by(models.EmpPermission.creation_date.desc())\
                .limit(5).all()
                
            for perm, name in pending_perms:
                notifications.append({
                    "id": f"mgr_perm_{perm.p_id}",
                    "title": "New Permission Request (Team)",
                    "message": f"{name} requested permission for {perm.total_hours}",
                    "time": perm.creation_date.strftime("%Y-%m-%d %H:%M") if perm.creation_date else "",
                    "type": "alert",
                    "icon": "time-outline"
                })
        except Exception as e:
            print(f"Error fetching manager notifications: {e}")
            
    # 2. Employee Notifications: Recent Status Updates (Leaves & Permissions)
    try:
        # Leave Updates
        my_leave_updates = db.query(models.EmpLeave)\
            .filter(models.EmpLeave.emp_id == emp_id)\
            .filter(models.EmpLeave.status.in_(['Approved', 'Rejected']))\
            .filter(models.EmpLeave.last_update_date >= recent_date_limit)\
            .order_by(models.EmpLeave.last_update_date.desc())\
            .limit(5).all()
            
        for leave in my_leave_updates:
            notifications.append({
                "id": f"emp_leave_{leave.l_id}",
                "title": f"Leave {leave.status}",
                "message": f"Your {leave.leave_type} request for {leave.from_date} was {leave.status}",
                "time": leave.last_update_date.strftime("%Y-%m-%d %H:%M") if leave.last_update_date else "",
                "type": "success" if leave.status == 'Approved' else "error",
                "icon": "checkmark-circle-outline" if leave.status == 'Approved' else "close-circle-outline"
            })

        # Permission Updates
        my_perm_updates = db.query(models.EmpPermission)\
            .filter(models.EmpPermission.emp_id == emp_id)\
            .filter(models.EmpPermission.status.in_(['Approved', 'Rejected']))\
            .filter(models.EmpPermission.last_update_date >= recent_date_limit)\
            .order_by(models.EmpPermission.last_update_date.desc())\
            .limit(5).all()
            
        for perm in my_perm_updates:
            notifications.append({
                "id": f"perm_{perm.p_id}",
                "screen": f"/AdminPermission?tab=myApproval",
                "title": f"Permission {perm.status}",
                "message": f"Your permission request for {perm.date.strftime('%d-%b-%Y') if perm.date else ''} was {perm.status}",
                "time": perm.last_update_date.strftime("%Y-%m-%d %H:%M") if perm.last_update_date else "",
                "type": "success" if perm.status == 'Approved' else "error",
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
    
    # Flexible emp_id search (handles ITS-0012 and ITS - 0012)
    clean_id = emp_id.replace(" ", "")
    query = db.query(models.TimesheetDet).filter(
        or_(
            models.TimesheetDet.emp_id == emp_id,
            func.replace(models.TimesheetDet.emp_id, " ", "") == clean_id
        )
    )
    
    if month:
        # Check for both month name (July) and numerical month (07)
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
    
    # We want employees who HAVE timesheets in this month/year
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
    
    # Fetch employees - also need flexible match here
    clean_ids = [eid.replace(" ", "") for eid in emp_ids]
    employees = db.query(models.EmpDet).all()
    matched_employees = []
    
    # We'll filter in python since we need to match clean IDs
    for emp in employees:
        if emp.emp_id and emp.emp_id.replace(" ", "") in clean_ids:
            matched_employees.append(emp)

    pending_query = db.query(models.TimesheetDet.emp_id, func.count(models.TimesheetDet.t_id).label('pending_count'))\
                      .filter(models.TimesheetDet.status.ilike('Pending'))
    
    if month_filter is not None:
        pending_query = pending_query.filter(month_filter)
    if year:
        pending_query = pending_query.filter(models.TimesheetDet.date.ilike(f"%{year}%"))
        
    pending_results = pending_query.group_by(models.TimesheetDet.emp_id).all()
    
    # Map pending counts using clean IDs
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
            "id": emp.emp_id,
            "name": emp.name or "Unknown",
            "department": domain_name,
            "requests": pending_map.get(cid, 0)
        })
    return results

@app.post("/admin/timesheet/action")
def timesheet_action(action_req: schemas.TimesheetApprovalAction, db: Session = Depends(get_db)):
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
    return {"message": f"Timesheet {action_req.action} successfully"}
