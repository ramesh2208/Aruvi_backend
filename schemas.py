from pydantic import BaseModel
from typing import Optional, List, Any
from datetime import date, datetime


class LoginRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    username: str
    role_type: str # 'Admin' or 'Employee'
    user_id: str
    name: Optional[str] = None
    gender: Optional[str] = None
    requires_2fa: Optional[bool] = False
    is_global_admin: Optional[bool] = False

class CheckInRequest(BaseModel):
    emp_id: str
    in_time: str # "HH:MM:SS"
    location: Optional[str] = None # 'finger print' implied check, but API input comes from device

class CheckOutRequest(BaseModel):
    emp_id: str
    out_time: str # "HH:MM:SS"

class DashboardResponse(BaseModel):
    emp_name: Optional[str] = "User"
    domain_name: str
    upcoming_events: List[dict] # {id: str, name: str, type: str, date: str, day: str}
    notifications: Optional[List[dict]] = []

class LeaveApplyRequest(BaseModel):
    emp_id: str
    leave_type: str
    from_date: str # DD-Mon-YYYY
    to_date: str   # DD-Mon-YYYY
    days: float
    reason: str

class LeaveApprovalAction(BaseModel):
    l_id: int
    admin_id: str
    action: str # Approved or Rejected
    remarks: Optional[str] = None

class PermissionApplyRequest(BaseModel):
    emp_id: str
    date: str # DD-Mon-YYYY
    f_time: str # HH:mm
    t_time: str # HH:mm
    reason: str
    total_hours: Optional[str] = None
    dis_total_hours: Optional[str] = None
    status: Optional[str] = "Pending"

class PermissionApprovalAction(BaseModel):
    p_id: int
    admin_id: str
    action: str # Approved or Rejected
    remarks: Optional[str] = None

class OverTimeApplyRequest(BaseModel):
    emp_id: str
    ot_date: str # DD-Mon-YYYY
    from_time: str # HH:mm
    to_time: str # HH:mm
    duration: str # e.g. "2h 30m"
    reason: str
    status: Optional[str] = "Pending"

class OverTimeApprovalAction(BaseModel):
    ot_id: int
    admin_id: str
    action: str # Approved or Rejected
    remarks: Optional[str] = None

class WFHApplyRequest(BaseModel):
    emp_id: str
    date: str # DD-Mon-YYYY
    reason: str
    status: Optional[str] = "Pending"

class WFHApprovalAction(BaseModel):
    wfh_id: int
    admin_id: str
    action: str # Approved or Rejected
    remarks: Optional[str] = None

class EmployeeProfileResponse(BaseModel):
    emp_id: str
    name: str
    dob: Optional[str] = None
    doj: Optional[str] = None
    mobile_number: Optional[str] = None
    alternative_phone_number: Optional[str] = None
    age: Optional[int] = None
    father_name: Optional[str] = None
    mother_name: Optional[str] = None
    domain: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None
    personal_mail: Optional[str] = None
    professional_mail: Optional[str] = None
    permanent_address: Optional[str] = None
    password: Optional[str] = None
    aadhaar_no: Optional[str] = None
    pan_no: Optional[str] = None
    passport_no: Optional[str] = None

class TimesheetResponse(BaseModel):
    t_id: int
    date: str
    day: str
    type: str
    project: str
    total_hours: str
    activity: str
    reason: Optional[str] = None
    status: str
    remarks: Optional[str] = None

class AdminTimesheetEmpResponse(BaseModel):
    id: str
    name: str
    department: str
    requests: int

class TimesheetApprovalAction(BaseModel):
    t_id: int
    admin_id: str
    action: str
    remarks: Optional[str] = None

class Verify2FARequest(BaseModel):
    user_id: str
    totp_code: str

class ForgotPasswordRequest(BaseModel):
    email: str

class VerifyOtpRequest(BaseModel):
    email: str
    otp: str

class ResetPasswordRequest(BaseModel):
    email: str
    otp: str
    new_password: str
