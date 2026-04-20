from pydantic import BaseModel
from typing import Optional, List, Any
from datetime import date, datetime


class LoginRequest(BaseModel):
    username: str
    password: str
    device_id: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str
    username: str
    role_type: str # 'Admin' or 'Employee'
    user_id: str
    name: Optional[str] = None
    gender: Optional[str] = None
    requires_2fa: Optional[bool] = Falsefrom pydantic import BaseModel
from typing import Optional, List, Any
from datetime import date, datetime


class LoginRequest(BaseModel):
    username: str
    password: str
    device_id: Optional[str] = None

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
    privileges: Optional[List[dict]] = []

class CheckInRequest(BaseModel):
    emp_id: str
    in_time: str # "HH:MM:SS"
    location: Optional[str] = None # 'finger print' implied check, but API input comes from device

class CheckOutRequest(BaseModel):
    emp_id: str
    out_time: str # "HH:MM:SS"
    total_hours: Optional[str] = None

class AutoCalculateHoursRequest(BaseModel):
    emp_id: str

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
    from_date: Optional[str] = None  # preferred DB column naming
    date: Optional[str] = None       # backward-compatible alias for from_date
    reason: str
    status: Optional[str] = "Pending"
    to_date: Optional[str] = None   # to_date (if not given, defaults to date)
    days: Optional[float] = None    # if not given, auto-calculated on backend

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
    email: Optional[str] = None
    p_mail: Optional[str] = None
    mail: Optional[str] = None
    personal_mail: Optional[str] = None
    professional_mail: Optional[str] = None
    permanent_address: Optional[str] = None
    password: Optional[str] = None
    aadhaar_no: Optional[str] = None
    pan_no: Optional[str] = None
    passport_no: Optional[str] = None
    device_id: Optional[str] = None

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

class SubClientSchema(BaseModel):
    sub_cl_id: Optional[int] = None
    sub_client_name: str
    client_ref_no: str
    sub_gst_no: Optional[str] = None
    sub_msme_no: Optional[str] = None
    sub_pan: Optional[str] = None
    sub_tds_p: Optional[int] = 0
    sub_gst_p: Optional[str] = None
    sub_short_code: Optional[str] = None
    sub_location: Optional[str] = None
    ship_to: Optional[str] = None
    currency: Optional[str] = None
    status: Optional[str] = "Active"

class ClientApplyRequest(BaseModel):
    client_ref_no: str
    client_name: str
    company_name: str
    mobile_no: Optional[str] = None
    country_code: Optional[str] = "+91"
    gst_available: Optional[str] = "No"
    gst: Optional[str] = None
    website: Optional[str] = None
    email_id: Optional[str] = None
    msme_available: Optional[str] = "No"
    msme: Optional[str] = None
    pan_no: Optional[str] = None
    short_code: Optional[str] = None
    currency: Optional[str] = None
    tds: Optional[str] = None
    gst_p: Optional[str] = None
    address: Optional[str] = None
    status: Optional[str] = "Active"
    sites: Optional[List[SubClientSchema]] = []

class ClientResponse(BaseModel):
    client_id: int
    client_ref_no: str
    client_name: str
    company_name: str
    country_code: Optional[str] = "+91"
    mobile_no: Optional[str] = None
    email_id: Optional[str] = None
    gst_available: Optional[str] = None
    gst: Optional[str] = None
    msme_available: Optional[str] = None
    msme: Optional[str] = None
    pan_no: Optional[str] = None
    address: Optional[str] = None
    status: Optional[str] = "Active"
    website: Optional[str] = None
    short_code: Optional[str] = None
    currency: Optional[str] = None
    tds: Optional[str] = None
    gst_p: Optional[str] = None
    sites: Optional[List[SubClientSchema]] = []
    creation_date: Optional[Any] = None
    last_update_date: Optional[Any] = None

class ProjectCreateRequest(BaseModel):
    project_ref_no: str
    project_name: str
    project_type: Optional[str] = None
    team_size: int
    budget: str
    start_date: str
    end_date: str
    project_manager: str
    status: str
    duration: str
    description: Optional[str] = None
    client_ref_no: str
    attribute1: Optional[str] = ""
    attribute2: Optional[str] = ""
    attribute3: Optional[str] = ""
    attribute4: Optional[str] = ""
    attribute5: Optional[str] = ""
    attribute6: Optional[str] = ""
    attribute7: Optional[str] = ""
    attribute8: Optional[str] = ""
    attribute9: Optional[str] = ""
    attribute10: Optional[str] = ""
    attribute11: Optional[str] = ""
    attribute12: Optional[str] = ""
    attribute13: Optional[str] = ""
    attribute14: Optional[str] = ""
    attribute15: Optional[str] = ""
    dom_id: str
    created_by: Optional[str] = None
    project_priority: Optional[str] = None
    files: Optional[str] = None

class ProjectResponse(BaseModel):
    model_config = {"from_attributes": True}

    pro_id: int
    project_ref_no: str
    project_name: Optional[str] = None
    project_type: Optional[str] = None
    team_size: Optional[int] = None
    budget: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    project_manager: Optional[str] = None
    status: Optional[str] = None
    duration: Optional[str] = None
    description: Optional[str] = None
    client_ref_no: Optional[str] = None
    project_priority: Optional[str] = None
    dom_id: Optional[str] = None
    files: Optional[str] = None
    attribute1: Optional[str] = None
    attribute2: Optional[str] = None
    attribute3: Optional[str] = None
    attribute4: Optional[str] = None
    attribute5: Optional[str] = None
    attribute6: Optional[str] = None
    attribute7: Optional[str] = None
    attribute8: Optional[str] = None
    attribute9: Optional[str] = None
    attribute10: Optional[str] = None
    attribute11: Optional[str] = None
    attribute12: Optional[str] = None
    attribute13: Optional[str] = None
    attribute14: Optional[str] = None
    attribute15: Optional[str] = None
    created_by: Optional[str] = None
    last_updated_by: Optional[str] = None
    creation_date: Optional[Any] = None
    last_update_date: Optional[Any] = None


class RoleResponse(BaseModel):
    model_config = {"from_attributes": True}
    role_id: int
    role: str
    dpt_id: Optional[str] = None
    dom_id: Optional[str] = None

class DepartmentResponse(BaseModel):
    model_config = {"from_attributes": True}
    dpt_id: int
    department: str

class DomainResponse(BaseModel):
    model_config = {"from_attributes": True}
    dom_id: int
    domain: str

class EmployeeBriefResponse(BaseModel):
    emp_id: str
    name: str
    role_id: Optional[str] = None
    dpt_id: Optional[str] = None
    dom_id: Optional[str] = None

class ProjectAllocationCreate(BaseModel):
    pro_id: int
    emp_id: str
    role_id: int
    dom_id: int
    dpt_id: int
    lead_id: str
    from_date: str
    to_date: str
    task_description: Optional[str] = None
    allocation_pct: str
    created_by: Optional[str] = None

class ProjectAllocationResponse(BaseModel):
    model_config = {"from_attributes": True}
    assign_id: int
    emp_id: str
    role_id: int
    dom_id: int
    dpt_id: int
    lead_id: str
    from_date: str
    to_date: str
    task_description: Optional[str] = None
    allocation_pct: str
    emp_name: Optional[str] = None
    role_name: Optional[str] = None
    dept_name: Optional[str] = None
    dom_name: Optional[str] = None
    project_name: Optional[str] = None
    lead_name: Optional[str] = None
    client_name: Optional[str] = None
    project_type: Optional[str] = None
    project_status: Optional[str] = None
    project_priority: Optional[str] = None

class PushTokenRegisterRequest(BaseModel):
    user_id: str
    push_token: str

class RolePrivilegeResponse(BaseModel):
    model_config = {"from_attributes": True}

    rpd_id: int
    mod_id: Optional[str] = None
    role_prv_ref_no: Optional[str] = None
    role_prv_name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    admin_prv: Optional[str] = None
    hr_prv: Optional[str] = None
    last_update_login: Optional[str] = None
    view_global: Optional[str] = None
    mod_array: Optional[str] = None
    create_prv: Optional[str] = None
    read_prv: Optional[str] = None
    view_prv: Optional[str] = None
    update_prv: Optional[str] = None
    delete_prv: Optional[str] = None
    permissions: Optional[str] = None
    created_by: Optional[str] = None
    creation_date: Optional[Any] = None
    last_updated_by: Optional[str] = None
    last_update_date: Optional[Any] = None
    last_update_login: Optional[str] = None

class ModuleResponse(BaseModel):
    model_config = {"from_attributes": True}

    mod_id: int
    module_ref_no: Optional[str] = None
    module: Optional[str] = None
    description: Optional[str] = None
    crud: Optional[str] = None
    status: Optional[str] = None
    attribute: Optional[str] = None
    attribute1: Optional[str] = None
    attribute2: Optional[str] = None
    attribute3: Optional[str] = None
    attribute4: Optional[str] = None
    attribute5: Optional[str] = None
    attribute6: Optional[str] = None
    attribute7: Optional[str] = None
    attribute8: Optional[str] = None
    attribute9: Optional[str] = None
    attribute10: Optional[str] = None
    attribute11: Optional[str] = None
    attribute12: Optional[str] = None
    attribute13: Optional[str] = None
    attribute14: Optional[str] = None
    attribute15: Optional[str] = None
    created_by: Optional[str] = None
    creation_date: Optional[Any] = None
    last_updated_by: Optional[str] = None
    last_update_date: Optional[Any] = None
    last_update_login: Optional[str] = None
    is_global_admin: Optional[bool] = False
    privileges: Optional[List[dict]] = []

class CheckInRequest(BaseModel):
    emp_id: str
    in_time: str # "HH:MM:SS"
    location: Optional[str] = None # 'finger print' implied check, but API input comes from device

class CheckOutRequest(BaseModel):
    emp_id: str
    out_time: str # "HH:MM:SS"
    total_hours: Optional[str] = None

class AutoCalculateHoursRequest(BaseModel):
    emp_id: str

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
    from_date: Optional[str] = None  # preferred DB column naming
    date: Optional[str] = None       # backward-compatible alias for from_date
    reason: str
    status: Optional[str] = "Pending"
    to_date: Optional[str] = None   # to_date (if not given, defaults to date)
    days: Optional[float] = None    # if not given, auto-calculated on backend

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
    email: Optional[str] = None
    p_mail: Optional[str] = None
    mail: Optional[str] = None
    personal_mail: Optional[str] = None
    professional_mail: Optional[str] = None
    permanent_address: Optional[str] = None
    password: Optional[str] = None
    aadhaar_no: Optional[str] = None
    pan_no: Optional[str] = None
    passport_no: Optional[str] = None
    device_id: Optional[str] = None

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

class SubClientSchema(BaseModel):
    sub_cl_id: Optional[int] = None
    sub_client_name: str
    client_ref_no: str
    sub_gst_no: Optional[str] = None
    sub_msme_no: Optional[str] = None
    sub_pan: Optional[str] = None
    sub_tds_p: Optional[int] = 0
    sub_gst_p: Optional[str] = None
    sub_short_code: Optional[str] = None
    sub_location: Optional[str] = None
    ship_to: Optional[str] = None
    currency: Optional[str] = None
    status: Optional[str] = "Active"

class ClientApplyRequest(BaseModel):
    client_ref_no: str
    client_name: str
    company_name: str
    mobile_no: Optional[str] = None
    country_code: Optional[str] = "+91"
    gst_available: Optional[str] = "No"
    gst: Optional[str] = None
    website: Optional[str] = None
    email_id: Optional[str] = None
    msme_available: Optional[str] = "No"
    msme: Optional[str] = None
    pan_no: Optional[str] = None
    short_code: Optional[str] = None
    currency: Optional[str] = None
    tds: Optional[str] = None
    gst_p: Optional[str] = None
    address: Optional[str] = None
    status: Optional[str] = "Active"
    sites: Optional[List[SubClientSchema]] = []

class ClientResponse(BaseModel):
    client_id: int
    client_ref_no: str
    client_name: str
    company_name: str
    country_code: Optional[str] = "+91"
    mobile_no: Optional[str] = None
    email_id: Optional[str] = None
    gst_available: Optional[str] = None
    gst: Optional[str] = None
    msme_available: Optional[str] = None
    msme: Optional[str] = None
    pan_no: Optional[str] = None
    address: Optional[str] = None
    status: Optional[str] = "Active"
    website: Optional[str] = None
    short_code: Optional[str] = None
    currency: Optional[str] = None
    tds: Optional[str] = None
    gst_p: Optional[str] = None
    sites: Optional[List[SubClientSchema]] = []
    creation_date: Optional[Any] = None
    last_update_date: Optional[Any] = None

class ProjectCreateRequest(BaseModel):
    project_ref_no: str
    project_name: str
    project_type: Optional[str] = None
    team_size: int
    budget: str
    start_date: str
    end_date: str
    project_manager: str
    status: str
    duration: str
    description: Optional[str] = None
    client_ref_no: str
    attribute1: Optional[str] = ""
    attribute2: Optional[str] = ""
    attribute3: Optional[str] = ""
    attribute4: Optional[str] = ""
    attribute5: Optional[str] = ""
    attribute6: Optional[str] = ""
    attribute7: Optional[str] = ""
    attribute8: Optional[str] = ""
    attribute9: Optional[str] = ""
    attribute10: Optional[str] = ""
    attribute11: Optional[str] = ""
    attribute12: Optional[str] = ""
    attribute13: Optional[str] = ""
    attribute14: Optional[str] = ""
    attribute15: Optional[str] = ""
    dom_id: str
    created_by: Optional[str] = None
    project_priority: Optional[str] = None
    files: Optional[str] = None

class ProjectResponse(BaseModel):
    model_config = {"from_attributes": True}

    pro_id: int
    project_ref_no: str
    project_name: Optional[str] = None
    project_type: Optional[str] = None
    team_size: Optional[int] = None
    budget: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    project_manager: Optional[str] = None
    status: Optional[str] = None
    duration: Optional[str] = None
    description: Optional[str] = None
    client_ref_no: Optional[str] = None
    project_priority: Optional[str] = None
    dom_id: Optional[str] = None
    files: Optional[str] = None
    attribute1: Optional[str] = None
    attribute2: Optional[str] = None
    attribute3: Optional[str] = None
    attribute4: Optional[str] = None
    attribute5: Optional[str] = None
    attribute6: Optional[str] = None
    attribute7: Optional[str] = None
    attribute8: Optional[str] = None
    attribute9: Optional[str] = None
    attribute10: Optional[str] = None
    attribute11: Optional[str] = None
    attribute12: Optional[str] = None
    attribute13: Optional[str] = None
    attribute14: Optional[str] = None
    attribute15: Optional[str] = None
    created_by: Optional[str] = None
    last_updated_by: Optional[str] = None
    creation_date: Optional[Any] = None
    last_update_date: Optional[Any] = None


class RoleResponse(BaseModel):
    model_config = {"from_attributes": True}
    role_id: int
    role: str
    dpt_id: Optional[str] = None
    dom_id: Optional[str] = None

class DepartmentResponse(BaseModel):
    model_config = {"from_attributes": True}
    dpt_id: int
    department: str

class DomainResponse(BaseModel):
    model_config = {"from_attributes": True}
    dom_id: int
    domain: str

class EmployeeBriefResponse(BaseModel):
    emp_id: str
    name: str
    role_id: Optional[str] = None
    dpt_id: Optional[str] = None
    dom_id: Optional[str] = None

class ProjectAllocationCreate(BaseModel):
    pro_id: int
    emp_id: str
    role_id: int
    dom_id: int
    dpt_id: int
    lead_id: str
    from_date: str
    to_date: str
    task_description: Optional[str] = None
    allocation_pct: str
    created_by: Optional[str] = None

class ProjectAllocationResponse(BaseModel):
    model_config = {"from_attributes": True}
    assign_id: int
    emp_id: str
    role_id: int
    dom_id: int
    dpt_id: int
    lead_id: str
    from_date: str
    to_date: str
    task_description: Optional[str] = None
    allocation_pct: str
    emp_name: Optional[str] = None
    role_name: Optional[str] = None
    dept_name: Optional[str] = None
    dom_name: Optional[str] = None
    project_name: Optional[str] = None
    lead_name: Optional[str] = None
    client_name: Optional[str] = None
    project_type: Optional[str] = None
    project_status: Optional[str] = None
    project_priority: Optional[str] = None

class PushTokenRegisterRequest(BaseModel):
    user_id: str
    push_token: str

class RolePrivilegeResponse(BaseModel):
    model_config = {"from_attributes": True}

    rpd_id: int
    mod_id: Optional[str] = None
    role_prv_ref_no: Optional[str] = None
    role_prv_name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    admin_prv: Optional[str] = None
    hr_prv: Optional[str] = None
    last_update_login: Optional[str] = None
    view_global: Optional[str] = None
    mod_array: Optional[str] = None
    create_prv: Optional[str] = None
    read_prv: Optional[str] = None
    view_prv: Optional[str] = None
    update_prv: Optional[str] = None
    delete_prv: Optional[str] = None
    permissions: Optional[str] = None
    created_by: Optional[str] = None
    creation_date: Optional[Any] = None
    last_updated_by: Optional[str] = None
    last_update_date: Optional[Any] = None
    last_update_login: Optional[str] = None

class ModuleResponse(BaseModel):
    model_config = {"from_attributes": True}

    mod_id: int
    module_ref_no: Optional[str] = None
    module: Optional[str] = None
    description: Optional[str] = None
    crud: Optional[str] = None
    status: Optional[str] = None
    attribute: Optional[str] = None
    attribute1: Optional[str] = None
    attribute2: Optional[str] = None
    attribute3: Optional[str] = None
    attribute4: Optional[str] = None
    attribute5: Optional[str] = None
    attribute6: Optional[str] = None
    attribute7: Optional[str] = None
    attribute8: Optional[str] = None
    attribute9: Optional[str] = None
    attribute10: Optional[str] = None
    attribute11: Optional[str] = None
    attribute12: Optional[str] = None
    attribute13: Optional[str] = None
    attribute14: Optional[str] = None
    attribute15: Optional[str] = None
    created_by: Optional[str] = None
    creation_date: Optional[Any] = None
    last_updated_by: Optional[str] = None
    last_update_date: Optional[Any] = None
    last_update_login: Optional[str] = None
