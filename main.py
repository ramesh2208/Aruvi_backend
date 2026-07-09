import React, { useEffect, useState, useRef } from 'react';
import {
  SafeAreaView,
  View,
  Text,
  StyleSheet,
  StatusBar,
  TouchableOpacity,
  ScrollView,
  Dimensions,
  Animated,
  ActivityIndicator,
  Platform,
  Share,
  Alert,
  TextInput,
  Modal,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useRouter, useLocalSearchParams } from 'expo-router';
import { LinearGradient } from 'expo-linear-gradient';
import { useAuth } from '@/contexts/AuthContext';
import { API_URL } from '@/constants/Config';
import MailSendingOverlay, { MailSendingStage } from '@/components/MailSendingOverlay';
import { sanitizeReasonText, REASON_VALIDATION_MESSAGE } from '@/utils/textValidation';

const { width } = Dimensions.get('window');

const MONTHS = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December'
];

const MONTH_COLORS = [
  ['#60A5FA', '#2563EB'], // Jan
  ['#F472B6', '#DB2777'], // Feb
  ['#34D399', '#059669'], // Mar
  ['#FBBF24', '#D97706'], // Apr
  ['#A78BFA', '#7C3AED'], // May
  ['#22D3EE', '#0891B2'], // Jun
  ['#F87171', '#DC2626'], // Jul
  ['#FB923C', '#EA580C'], // Aug
  ['#2DD4BF', '#0D9488'], // Sep
  ['#F59E0B', '#B45309'], // Oct
  ['#818CF8', '#4F46E5'], // Nov
  ['#38BDF8', '#0284C7'], // Dec
];

type SummaryTypeBreakdown = {
  type: string;
  hours: number;
  color: string;
};

type RequestStatus = 'approved' | 'pending' | 'rejected';

type ProjectEntry = {
  id: string;
  projectType: string;
  projectName: string;
  activity: string;
  hours: string;
  remarks: string;
};

type DayRequest = {
  date: number;
  status: RequestStatus;
  hours: string;
  type: string;
  checkIn?: string;
  checkOut?: string;
  projects: ProjectEntry[];
};

type ExportEntry = {
  date: string;
  type: string;
  hours: number;
  status: string;
  project: string;
  activity: string;
  remarks: string;
};

type ProjectDayEntry = {
  date: string;
  taskName: string;      // activity
  description: string;   // projectName – activity combined
  hours: number;
  project: string;
  remarks: string;
  status: string;
};

type LeaveDetailEntry = {
  leaveType: string;
  date: string;
  reason: string;
  status: string;
  appliedDate: string;
  activity: string;
};

// A multi-project entry stores its projects as a comma-separated string
// (e.g. "Test, AMC Support"). The same set of projects can be saved in a
// different order on another day ("AMC Support, Test"), which would
// otherwise create two separate rows for what is really one project group.
// Sorting the names before joining gives a stable key so they merge.
const normalizeProjectKey = (value: string): string => {
  const names = (value || '').split(',').map(s => s.trim()).filter(Boolean);
  if (names.length === 0) return 'General';
  return [...names].sort((a, b) => a.localeCompare(b)).join(', ');
};

const normalizeAllocationType = (value: string): 'Internal' | 'External' | null => {
  const normalized = (value || '').toLowerCase().trim();

  if (!normalized) return null;
  if (normalized.includes('internal') || normalized === 'int') return 'Internal';
  if (normalized.includes('external') || normalized === 'ext') return 'External';

  return null;
};

const ExpandableText = ({ text, maxLength = 60 }: { text: string; maxLength?: number }) => {
  const [expanded, setExpanded] = useState(false);

  if (!text) return null;
  if (text.length <= maxLength) {
    return <Text style={styles.modalEntryValue}>{text}</Text>;
  }

  return (
    <View style={{ flex: 1 }}>
      <Text style={styles.modalEntryValue}>
        {expanded ? text : `${text.substring(0, maxLength)}...`}
      </Text>
      <TouchableOpacity onPress={() => setExpanded(!expanded)} style={{ marginTop: 4 }}>
        <Text style={{ color: '#2563EB', fontSize: 12, fontWeight: '700' }}>
          {expanded ? 'View Less' : 'View More'}
        </Text>
      </TouchableOpacity>
    </View>
  );
};

export default function TimesheetSummaryScreen() {
  const router = useRouter();
  const { userData, checkPermission } = useAuth();
  const params = useLocalSearchParams();
  const [sendingMail, setSendingMail] = useState(false);

  const monthIndex = params.month ? parseInt(params.month as string) : 0;
  const year = params.year ? parseInt(params.year as string) : 2026;
  const monthName = MONTHS[monthIndex];
  const gradient = MONTH_COLORS[monthIndex] || ['#3B82F6', '#1D4ED8'];

  // Manager approval context passed from EmployeeTimesheet
  const empId = (params.empId as string) || userData?.user_id || '';
  const empName = (params.empName as string) || '';
  // canApprove reflects true Admin status only — Assign Manager, Project
  // Manager and HR SPOC can view an employee's timesheet but never get the
  // Send Mail (approve/reject) action, which stays Admin-only.
  const canApprove = params.canApprove === '1';
  // Approve/Reject section is restricted to approvers in Domain ID 1, 2 or 9
  const canApproveByDomain = [1, 2, 9].includes(Number((userData as any)?.dom_id));
  const monthStr = (params.monthStr as string) || `${year}-${String(monthIndex + 1).padStart(2, '0')}`;
  // Whether we're looking at someone else's timesheet — independent of admin
  // rights, so the self-notify header button stays hidden for any viewer
  // (manager or admin) looking at an employee's record.
  const isViewingEmployee = !!params.empId && params.empId !== userData?.user_id;


  const [loading, setLoading] = useState(false);
  const [totalHours, setTotalHours] = useState(0);
  const [approvedHours, setApprovedHours] = useState(0);
  const [pendingHours, setPendingHours] = useState(0);
  const [typeBreakdown, setTypeBreakdown] = useState<SummaryTypeBreakdown[]>([]);
  const [projectsList, setProjectsList] = useState<{ name: string; hours: number; activity: string }[]>([]);
  const [rawEntries, setRawEntries] = useState<ExportEntry[]>([]);
  // Project detail map: projectName → day-wise entries
  const [projectDetailMap, setProjectDetailMap] = useState<Record<string, ProjectDayEntry[]>>({});
  // Leave entries list
  const [leaveEntries, setLeaveEntries] = useState<LeaveDetailEntry[]>([]);
  // Modal state
  const [selectedProject, setSelectedProject] = useState<string | null>(null);
  const [selectedLeave, setSelectedLeave] = useState<LeaveDetailEntry | null>(null);

  // Approval section state
  const [approvalStatus, setApprovalStatus] = useState<'Pending' | 'Approved' | 'Rejected'>('Pending');
  const [approvalRemarks, setApprovalRemarks] = useState('');
  const [approvalRemarksWarning, setApprovalRemarksWarning] = useState(false);
  const [approvalDropdownOpen, setApprovalDropdownOpen] = useState(false);
  const [mailSent, setMailSent] = useState(false);
  const [managerMailSendCount, setManagerMailSendCount] = useState(0);
  const MAX_MANAGER_MAIL_SENDS = 3;
  const [mailOverlayVisible, setMailOverlayVisible] = useState(false);
  const [mailOverlayStage, setMailOverlayStage] = useState<MailSendingStage>('loading');
  const [mailOverlayCaption, setMailOverlayCaption] = useState('Sending your timesheet...');

  // Animation values
  const fadeAnim = useRef(new Animated.Value(0)).current;
  const slideAnim = useRef(new Animated.Value(40)).current;
  const progressAnims = useRef<Record<string, Animated.Value>>({}).current;

  const fetchData = async () => {
    if (!userData?.user_id) return;
    setLoading(true);
    try {
      // 1. Check if local data was passed and use it directly if it contains records
      let localRequests: DayRequest[] = [];
      if (params.data) {
        try {
          localRequests = JSON.parse(params.data as string);
        } catch (err) {
          console.error('Error parsing local requests:', err);
        }
      }

      if (localRequests && localRequests.length > 0) {
        let total = 0;
        let approved = 0;
        let pending = 0;
        const typeMap: Record<string, number> = {};
        const projectMap: Record<string, { hours: number; activities: Set<string> }> = {};
        const entries: ExportEntry[] = [];

        const localProjDetailMap: Record<string, ProjectDayEntry[]> = {};
        const localLeaveEntries: LeaveDetailEntry[] = [];

        const LEAVE_TYPES_SET = new Set(['leave', 'casual leave', 'sick leave', 'annual leave',
          'earned leave', 'maternity leave', 'paternity leave', 'cl', 'sl', 'el',
          'week-off', 'holiday', 'public holiday', 'comp-off', 'comp off', 'compoff']);

        localRequests.forEach((dayReq) => {
          const dd = String(dayReq.date).padStart(2, '0');
          const mmm = MONTHS[monthIndex].substring(0, 3);
          const yy = String(year).substring(2, 4);
          const formattedDate = `${dd}-${mmm}-${yy}`;
          const typeLC = (dayReq.type || '').toLowerCase();
          const isLeaveType = LEAVE_TYPES_SET.has(typeLC);

          if (!dayReq.projects || dayReq.projects.length === 0) {
            const hrs = parseFloat(dayReq.hours || '0');
            total += hrs;
            if (dayReq.status?.toLowerCase() === 'approved') {
              approved += hrs;
            } else {
              pending += hrs;
            }
            const t = dayReq.type || 'General';
            const normalizedType = normalizeAllocationType(t);
            if (normalizedType) {
              typeMap[normalizedType] = (typeMap[normalizedType] || 0) + hrs;
            }

            // "Worked on Leave" only applies when an Activity was actually logged
            // against the Comp-Off/Week-off/Leave/Holiday entry — otherwise there's
            // nothing worked on, so it stays out of this list.

            entries.push({
              date: formattedDate,
              type: t,
              hours: hrs,
              status: dayReq.status,
              project: 'General',
              activity: '',
              remarks: ''
            });
          } else if (isLeaveType) {
            // Leave / Comp-Off / Holiday / Week-off entries carry a placeholder
            // project value (e.g. "Not applicable") — group them as a leave
            // record keyed by the actual selected type instead of by project.
            let dayHrs = 0;
            let dayReason = '';
            let dayRemarks = '';
            let dayActivity = '';
            dayReq.projects.forEach((proj) => {
              const hrs = parseFloat(proj.hours || '0');
              dayHrs += hrs;
              total += hrs;
              if (dayReq.status?.toLowerCase() === 'approved') {
                approved += hrs;
              } else {
                pending += hrs;
              }
              if (!dayReason && proj.reason) dayReason = proj.reason;
              if (!dayRemarks && proj.remarks) dayRemarks = proj.remarks;
              if (!dayActivity && proj.activity) dayActivity = proj.activity;
            });
            const normalizedType = normalizeAllocationType(dayReq.type || 'General');
            if (normalizedType) {
              typeMap[normalizedType] = (typeMap[normalizedType] || 0) + dayHrs;
            }

            // "Worked on Leave" only applies when both an Activity and Total Hours
            // were actually logged against the Comp-Off/Week-off/Leave/Holiday
            // entry — otherwise there's nothing worked on, so it stays out of this list.
            if (dayActivity.trim() && dayHrs > 0) {
              localLeaveEntries.push({
                leaveType: dayReq.type || 'Leave',
                date: formattedDate,
                reason: dayReason || dayRemarks,
                status: dayReq.status || 'Pending',
                appliedDate: '',
                activity: dayActivity,
              });
            }

            entries.push({
              date: formattedDate,
              type: dayReq.type || 'General',
              hours: dayHrs,
              status: dayReq.status,
              project: dayReq.type || 'Not applicable',
              activity: dayReq.projects[0]?.activity || '',
              remarks: dayRemarks
            });
          } else {
            dayReq.projects.forEach((proj) => {
              const hrs = parseFloat(proj.hours || '0');
              total += hrs;
              if (dayReq.status?.toLowerCase() === 'approved') {
                approved += hrs;
              } else {
                pending += hrs;
              }
              const t = proj.projectType || dayReq.type || 'General';
              const normalizedType = normalizeAllocationType(t);
              if (normalizedType) {
                typeMap[normalizedType] = (typeMap[normalizedType] || 0) + hrs;
              }

              const projName = normalizeProjectKey(proj.projectName);
              if (!projectMap[projName]) {
                projectMap[projName] = { hours: 0, activities: new Set<string>() };
              }
              projectMap[projName].hours += hrs;
              if (proj.activity) {
                projectMap[projName].activities.add(proj.activity);
              }

              // Build project detail map
              if (!localProjDetailMap[projName]) localProjDetailMap[projName] = [];
              localProjDetailMap[projName].push({
                date: formattedDate,
                taskName: proj.activity || '',
                description: proj.activity || '',
                hours: hrs,
                project: projName,
                remarks: proj.remarks || '',
                status: dayReq.status || 'Pending',
              });

              entries.push({
                date: formattedDate,
                type: t,
                hours: hrs,
                status: dayReq.status,
                project: projName,
                activity: proj.activity || '',
                remarks: proj.remarks || ''
              });
            });
          }
        });

        setTotalHours(total);
        setApprovedHours(approved);
        setPendingHours(pending);
        setRawEntries(entries);
        setProjectDetailMap(localProjDetailMap);
        setLeaveEntries(localLeaveEntries);

        const colors = ['#2563EB', '#10B981'];
        const breakdown = ['Internal', 'External'].map((key, i) => ({
          type: key,
          hours: typeMap[key] || 0,
          color: colors[i % colors.length],
        }));
        setTypeBreakdown(breakdown);

        const projects = Object.keys(projectMap).map(key => ({
          name: key,
          hours: projectMap[key].hours,
          activity: Array.from(projectMap[key].activities).join(', ') || 'No activities listed',
        }));
        setProjectsList(projects);

        triggerAnimations(breakdown);
        setLoading(false);
        return;
      }

      // 2. Fallback: Fetch from API if no local data
      const targetEmpId = empId || userData.user_id;
      const expectedMonthStr = `${year}-${String(monthIndex + 1).padStart(2, '0')}`;
      const resp = await fetch(
        `${API_URL}/timesheet-month/${encodeURIComponent(targetEmpId)}?year=${year}&month=${encodeURIComponent(monthName)}&requester_id=${encodeURIComponent(userData.user_id)}`
      );
      const data = await resp.json();

      const currentMonthData = Array.isArray(data) ? data.filter((item: any) => {
        // Strict employee filter
        if (item.emp_id && item.emp_id.trim().toLowerCase() !== targetEmpId.trim().toLowerCase()) {
          return false;
        }
        // Strict month filter using YYYY-MM
        if (item.month) {
          return item.month.trim() === expectedMonthStr;
        }
        // Fallback: parse month from date field
        if (item.date) {
          const parts = item.date.split('-');
          if (parts.length >= 2) {
            const monthShort = parts[1].toLowerCase();
            const idx = MONTHS.findIndex(m => m.toLowerCase().startsWith(monthShort));
            return idx === monthIndex;
          }
        }
        return false;
      }) : [];

      let total = 0;
      let approved = 0;
      let pending = 0;
      const typeMap: Record<string, number> = {};
      const projectMap: Record<string, { hours: number; activities: Set<string> }> = {};
      const entries: ExportEntry[] = [];
      const apiProjDetailMap: Record<string, ProjectDayEntry[]> = {};
      const apiLeaveEntries: LeaveDetailEntry[] = [];

      const LEAVE_TYPES_SET = new Set(['leave', 'casual leave', 'sick leave', 'annual leave',
        'earned leave', 'maternity leave', 'paternity leave', 'cl', 'sl', 'el',
        'week-off', 'holiday', 'public holiday', 'comp-off', 'comp off', 'compoff']);

      currentMonthData.forEach((item: any) => {
        const hrs = parseFloat(item.total_hours || '0');
        total += hrs;
        if (item.status?.toLowerCase() === 'approved') {
          approved += hrs;
        } else {
          pending += hrs;
        }

        const t = item.type || 'General';
        const normalizedType = normalizeAllocationType(t);
        if (normalizedType) {
          typeMap[normalizedType] = (typeMap[normalizedType] || 0) + hrs;
        }

        const projName = item.project || 'General';

        let formattedDate = item.date || '';
        if (formattedDate.includes('-')) {
          const parts = formattedDate.split('-');
          if (parts.length === 3) {
            const dd = parts[0].padStart(2, '0');
            const mmm = parts[1].substring(0, 3);
            let yy = parts[2];
            if (yy.length === 4) yy = yy.substring(2, 4);
            formattedDate = `${dd}-${mmm}-${yy}`;
          }
        }

        const typeLC = t.toLowerCase();
        if (LEAVE_TYPES_SET.has(typeLC)) {
          // Leave / Comp-Off / Holiday / Week-off entries carry a placeholder
          // project value (e.g. "Not applicable") — group them by the actual
          // selected type instead of polluting the Projects Logged list.
          // "Worked on Leave" only applies when both an Activity and Total Hours
          // were actually logged; without either, there's nothing worked on, so
          // it's left out entirely.
          if ((item.activity || '').trim() && hrs > 0) {
            apiLeaveEntries.push({
              leaveType: t,
              date: formattedDate,
              reason: item.reason || item.remarks || '',
              status: item.status || 'Pending',
              appliedDate: item.applied_date || '',
              activity: item.activity || '',
            });
          }
        } else {
          if (!projectMap[projName]) {
            projectMap[projName] = { hours: 0, activities: new Set<string>() };
          }
          projectMap[projName].hours += hrs;
          if (item.activity) {
            projectMap[projName].activities.add(item.activity);
          }

          // Build project detail map for non-leave entries
          if (!apiProjDetailMap[projName]) apiProjDetailMap[projName] = [];
          apiProjDetailMap[projName].push({
            date: formattedDate,
            taskName: item.activity || '',
            description: item.activity || '',
            hours: hrs,
            project: projName,
            remarks: item.remarks || '',
            status: item.status || 'Pending',
          });
        }

        entries.push({
          date: formattedDate,
          type: t,
          hours: hrs,
          status: item.status || 'pending',
          project: projName,
          activity: item.activity || '',
          remarks: item.remarks || ''
        });
      });

      setTotalHours(total);
      setApprovedHours(approved);
      setPendingHours(pending);
      setRawEntries(entries);
      setProjectDetailMap(apiProjDetailMap);
      setLeaveEntries(apiLeaveEntries);

      const colors = ['#2563EB', '#10B981'];
      const breakdown = ['Internal', 'External'].map((key, i) => ({
        type: key,
        hours: typeMap[key] || 0,
        color: colors[i % colors.length],
      }));
      setTypeBreakdown(breakdown);

      const projects = Object.keys(projectMap)
        .filter(key => !LEAVE_TYPES_SET.has(key.toLowerCase()))
        .map(key => ({
          name: key,
          hours: projectMap[key].hours,
          activity: Array.from(projectMap[key].activities).join(', ') || 'No activities listed',
        }));
      setProjectsList(projects);

      triggerAnimations(breakdown);
    } catch (e) {
      console.error('Fetch summary error:', e);
      // On error, show empty state — no dummy data
      setTotalHours(0);
      setApprovedHours(0);
      setPendingHours(0);
      setTypeBreakdown([]);
      setProjectsList([]);
      setRawEntries([]);
    } finally {
      setLoading(false);
    }
  };

  const reloadAfterMailRef = useRef(false);

  const handleMailOverlayDismiss = () => {
    setMailOverlayVisible(false);
    if (reloadAfterMailRef.current) {
      reloadAfterMailRef.current = false;
      fetchData();
    }
  };

  const sendMail = async () => {
    if (!userData?.user_id) return;
    if (mailSent) {
      Alert.alert('Already Sent', 'Email has already been sent. Modify the timesheet to send again.');
      return;
    }
    setSendingMail(true);
    setMailOverlayCaption('Sending your timesheet...');
    setMailOverlayStage('loading');
    setMailOverlayVisible(true);
    try {
      const resp = await fetch(`${API_URL}/timesheet/send-mail`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          emp_id: empId || userData.user_id,
          month: monthStr,
          requester_id: userData.user_id,
          sender_type: 'employee',
        }),
      });
      const data = await resp.json();
      if (resp.ok && data.success) {
        setMailSent(true);
        setMailOverlayStage('sending');
      } else {
        setMailOverlayVisible(false);
        Alert.alert('Failed', data.detail || 'Could not send email. Please try again.');
      }
    } catch (e) {
      setMailOverlayVisible(false);
      Alert.alert('Error', 'Network error. Please try again.');
    } finally {
      setSendingMail(false);
    }
  };

  const handleManagerSendMail = async () => {
    if (!userData?.user_id || !empId) return;

    if (approvalStatus === 'Pending') {
      Alert.alert('Required', 'Please select Approved or Rejected before sending email.');
      return;
    }
    if (!approvalRemarks.trim()) {
      Alert.alert('Required', 'Please enter remarks before sending email.');
      return;
    }
    if (managerMailSendCount >= MAX_MANAGER_MAIL_SENDS) {
      Alert.alert('Send Limit Reached', `Email can only be sent a maximum of ${MAX_MANAGER_MAIL_SENDS} times for this timesheet.`);
      return;
    }

    setSendingMail(true);
    setMailOverlayCaption('Sending Reply Mail...');
    setMailOverlayStage('loading');
    setMailOverlayVisible(true);
    try {
      // Step 1: Send email first
      const mailResp = await fetch(`${API_URL}/timesheet/send-mail`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          emp_id: empId,
          month: monthStr,
          requester_id: userData.user_id,
          sender_type: 'manager',
          action: approvalStatus,
          remarks: approvalRemarks,
        }),
      });
      const mailData = await mailResp.json();

      if (!mailResp.ok || !mailData.success) {
        setMailOverlayVisible(false);
        Alert.alert('Email Failed', mailData.detail || 'Could not send email. Status was NOT updated.');
        return;
      }

      // Step 2: Update ALL entries for the selected month
      const fetchResp = await fetch(`${API_URL}/timesheet-month/${encodeURIComponent(empId)}?month=${encodeURIComponent(monthName)}&year=${year}&requester_id=${encodeURIComponent(userData.user_id)}`);
      const entries = await fetchResp.json();
      if (Array.isArray(entries)) {
        for (const entry of entries) {
          await fetch(`${API_URL}/admin/timesheet/action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              t_id: entry.t_id,
              admin_id: userData.user_id,
              action: approvalStatus,
              remarks: approvalRemarks,
            }),
          });
        }
      }

      // Step 3: Increment the send counter and play the send animation
      const newCount = managerMailSendCount + 1;
      setManagerMailSendCount(newCount);
      // Status was just updated on the server — reload once the overlay is dismissed
      // so the Approve/Reject panel reflects the new status instead of staying stale.
      reloadAfterMailRef.current = true;
      setMailOverlayStage('sending');
    } catch (e) {
      console.error('handleManagerSendMail error:', e);
      setMailOverlayVisible(false);
      Alert.alert('Error', 'Failed to process request. Please try again.');
    } finally {
      setSendingMail(false);
    }
  };

  const escapeCSV = (val: any) => {
    if (val === undefined || val === null) return '';
    let str = String(val);
    if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const exportToCSV = async () => {
    if (rawEntries.length === 0) {
      Alert.alert('No Data', 'There is no timesheet data to export.');
      return;
    }

    const headers = ['Date', 'Type', 'Hours', 'Status', 'Project', 'Activity', 'Remarks'];
    const rows = rawEntries.map(e => [
      escapeCSV(e.date),
      escapeCSV(e.type),
      escapeCSV(e.hours),
      escapeCSV(e.status),
      escapeCSV(e.project),
      escapeCSV(e.activity),
      escapeCSV(e.remarks)
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map(r => r.join(','))
    ].join('\n');

    try {
      await Share.share({
        message: csvContent,
        title: `Timesheet Export - ${monthName} ${year}`,
      });
    } catch (error) {
      console.error('Error sharing CSV:', error);
    }
  };

  const triggerAnimations = (breakdown: SummaryTypeBreakdown[]) => {
    breakdown.forEach(item => {
      progressAnims[item.type] = new Animated.Value(0);
    });

    Animated.parallel([
      Animated.timing(fadeAnim, {
        toValue: 1,
        duration: 800,
        useNativeDriver: true,
      }),
      Animated.timing(slideAnim, {
        toValue: 0,
        duration: 800,
        useNativeDriver: true,
      }),
    ]).start();

    const progressTimings = breakdown.map(item => {
      return Animated.timing(progressAnims[item.type], {
        toValue: 1,
        duration: 1000,
        useNativeDriver: false,
      });
    });
    Animated.stagger(200, progressTimings).start();
  };

  useEffect(() => {
    fetchData();
  }, [userData?.user_id]);

  const hasPending = rawEntries.some(e => e.status?.toLowerCase() === 'pending');
  const hasRejected = rawEntries.some(e => e.status?.toLowerCase() === 'rejected');
  const hasApproved = rawEntries.some(e => e.status?.toLowerCase() === 'approved');

  let overallStatus = 'Pending';
  if (rawEntries.length > 0) {
    if (hasPending) {
      overallStatus = 'Pending';
    } else if (hasRejected) {
      overallStatus = 'Rejected';
    } else if (hasApproved) {
      overallStatus = 'Approved';
    }
  }

  const adminRemarks = rawEntries.find(e => e.remarks && e.remarks.trim())?.remarks || '';

  return (
    <SafeAreaView style={styles.container}>

      <StatusBar barStyle="light-content" backgroundColor={gradient[0]} />

      <LinearGradient
        colors={gradient as any}
        style={styles.header}
        start={{ x: 0, y: 0 }}
        end={{ x: 1, y: 1 }}
      >
        <View style={styles.headerNav}>
          <TouchableOpacity onPress={() => router.back()} style={styles.backBtn}>
            <Ionicons name="chevron-back" size={24} color="#FFFFFF" />
          </TouchableOpacity>
          <Text style={styles.headerTitle}>Timesheet Analysis</Text>
          <View style={{ flexDirection: 'row', gap: 8 }}>
            {!isViewingEmployee && (
              <TouchableOpacity
                onPress={sendMail}
                style={[styles.exportBtn, (sendingMail || mailSent || overallStatus === 'Approved') && { opacity: 0.7 }]}
                disabled={sendingMail || mailSent || overallStatus === 'Approved'}
              >
                <Ionicons
                  name={mailSent ? 'checkmark-circle' : 'mail-outline'}
                  size={22}
                  color="#FFFFFF"
                />
              </TouchableOpacity>
            )}
            <TouchableOpacity onPress={exportToCSV} style={styles.exportBtn}>
              <Ionicons name="download-outline" size={22} color="#FFFFFF" />
            </TouchableOpacity>
          </View>
        </View>

        <View style={styles.headerContent}>
          <Text style={styles.headerMonth}>{monthName} {year}</Text>
          <Text style={styles.headerSubtitle}>Effort Breakdown & Insights</Text>
        </View>
      </LinearGradient>

      {loading ? (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color={gradient[0]} />
          <Text style={styles.loadingText}>Analyzing timesheet entries...</Text>
        </View>
      ) : (
        <Animated.View
          style={[
            styles.content,
            { opacity: fadeAnim, transform: [{ translateY: slideAnim }] },
          ]}
        >
          <ScrollView contentContainerStyle={styles.scrollContent} showsVerticalScrollIndicator={false}>
            {/* Status Banner */}
            {(overallStatus === 'Approved' || overallStatus === 'Rejected') && (
              <View style={[
                styles.statusDisplayCard,
                {
                  backgroundColor: overallStatus === 'Approved' ? '#ECFDF5' : '#FEF2F2',
                  borderColor: overallStatus === 'Approved' ? '#A7F3D0' : '#FCA5A5',
                  flexDirection: 'row',
                  alignItems: 'center',
                  padding: 14,
                  borderRadius: 16,
                  marginBottom: 16,
                  borderWidth: 1,
                  gap: 8,
                }
              ]}>
                <Ionicons
                  name={overallStatus === 'Approved' ? "checkmark-circle" : "close-circle"}
                  size={20}
                  color={overallStatus === 'Approved' ? '#059669' : '#DC2626'}
                />
                <Text style={{
                  fontSize: 14,
                  fontWeight: '600',
                  color: overallStatus === 'Approved' ? '#065F46' : '#991B1B',
                }}>
                  Timesheet Status: <Text style={{ fontWeight: '800' }}>{overallStatus}</Text>
                </Text>
              </View>
            )}

            {/* Admin remarks for the approval/rejection decision */}
            {(overallStatus === 'Approved' || overallStatus === 'Rejected') && !!adminRemarks && (
              <View style={[
                styles.statusDisplayCard,
                {
                  backgroundColor: overallStatus === 'Approved' ? '#ECFDF5' : '#FEF2F2',
                  borderColor: overallStatus === 'Approved' ? '#A7F3D0' : '#FCA5A5',
                  padding: 14,
                  borderRadius: 16,
                  marginBottom: 16,
                  borderWidth: 1,
                  gap: 4,
                }
              ]}>
                <Text style={{
                  fontSize: 12,
                  fontWeight: '700',
                  color: overallStatus === 'Approved' ? '#065F46' : '#991B1B',
                }}>
                  Admin Remarks
                </Text>
                <Text style={{
                  fontSize: 14,
                  color: overallStatus === 'Approved' ? '#065F46' : '#991B1B',
                }}>
                  {adminRemarks}
                </Text>
              </View>
            )}

            {/* Stats Dashboard */}
            <View style={styles.statsGrid}>
              <View style={styles.statCard}>
                <View style={[styles.statIconBg, { backgroundColor: '#EFF6FF' }]}>
                  <Ionicons name="time" size={20} color="#2563EB" />
                </View>
                <Text style={styles.statValue}>{totalHours}Hrs</Text>
                <Text style={styles.statLabel}>Total Logs</Text>
              </View>

              <View style={styles.statCard}>
                <View style={[styles.statIconBg, { backgroundColor: '#ECFDF5' }]}>
                  <Ionicons name="checkmark-circle" size={20} color="#059669" />
                </View>
                <Text style={styles.statValue}>{approvedHours}Hrs</Text>
                <Text style={styles.statLabel}>Approved</Text>
              </View>

              <View style={styles.statCard}>
                <View style={[styles.statIconBg, { backgroundColor: '#FFFBEB' }]}>
                  <Ionicons name="hourglass" size={20} color="#D97706" />
                </View>
                <Text style={styles.statValue}>{pendingHours}Hrs</Text>
                <Text style={styles.statLabel}>Pending</Text>
              </View>
            </View>

            {/* Type Breakdown Chart */}
            <View style={styles.chartCard}>
              <Text style={styles.cardTitle}>Hours by Allocation Type</Text>
              
              {typeBreakdown.length === 0 ? (
                <Text style={styles.noData}>No Internal or External records logged this month</Text>
              ) : (
                (() => {
                  const summaryTotalHours = typeBreakdown.reduce((sum, item) => sum + item.hours, 0);

                  return typeBreakdown.map((item, index) => {
                    const percentage = summaryTotalHours > 0 ? (item.hours / summaryTotalHours) * 100 : 0;
                    const barWidth = progressAnims[item.type] ? progressAnims[item.type].interpolate({
                      inputRange: [0, 1],
                      outputRange: ['0%', `${percentage}%`]
                    }) : '0%';

                    return (
                      <View key={index} style={styles.chartRow}>
                        <View style={styles.chartLabelRow}>
                          <View style={styles.typeNameContainer}>
                            <View style={[styles.colorDot, { backgroundColor: item.color }]} />
                            <Text style={styles.typeName}>{item.type}</Text>
                          </View>
                          <Text style={styles.typeValue}>{item.hours}h ({Math.round(percentage)}%)</Text>
                        </View>
                        <View style={styles.progressBarBg}>
                          <Animated.View
                            style={[
                              styles.progressBarFill,
                              {
                                backgroundColor: item.color,
                                width: barWidth
                              }
                            ]}
                          />
                        </View>
                      </View>
                    );
                  });
                })()
              )}
            </View>

            {/* Projects Overview */}
            <View style={styles.projectsCard}>
              <Text style={styles.cardTitle}>Projects Logged</Text>
              {projectsList.length === 0 ? (
                <Text style={styles.noData}>No projects recorded</Text>
              ) : (
                projectsList.map((proj, idx) => (
                  <TouchableOpacity
                    key={idx}
                    style={styles.projectItem}
                    onPress={() => setSelectedProject(proj.name)}
                    activeOpacity={0.7}
                  >
                    <View style={styles.projectHeader}>
                      <View style={{ flexDirection: 'row', alignItems: 'center', flex: 1 }}>
                        <View style={styles.projectIconBg}>
                          <Ionicons name="folder-open" size={14} color="#2563EB" />
                        </View>
                        <Text style={styles.projectName}>{proj.name}</Text>
                      </View>
                      <View style={styles.projectHoursBadge}>
                        <Text style={styles.projectHours}>{proj.hours}h</Text>
                      </View>
                    </View>
                    <Text style={styles.projectActivity} numberOfLines={2}>{proj.activity}</Text>
                    <View style={styles.projectTapHint}>
                      <Ionicons name="eye-outline" size={12} color="#9CA3AF" />
                      <Text style={styles.projectTapHintText}>Tap to view day-wise details</Text>
                    </View>
                  </TouchableOpacity>
                ))
              )}
            </View>

            {/* Leave Entries */}
            {leaveEntries.length > 0 && (
              <View style={styles.leavesCard}>
                <Text style={styles.cardTitle}>Worked on Leave</Text>
                {leaveEntries.map((leave, idx) => {
                  const statusColor = leave.status.toLowerCase() === 'approved' ? '#059669'
                    : leave.status.toLowerCase() === 'rejected' ? '#DC2626' : '#D97706';
                  const statusBg = leave.status.toLowerCase() === 'approved' ? '#ECFDF5'
                    : leave.status.toLowerCase() === 'rejected' ? '#FEF2F2' : '#FFFBEB';
                  return (
                    <TouchableOpacity
                      key={idx}
                      style={styles.leaveItem}
                      onPress={() => setSelectedLeave(leave)}
                      activeOpacity={0.7}
                    >
                      <View style={styles.leaveRow}>
                        <View style={styles.leaveLeft}>
                          <View style={styles.leaveIconBg}>
                            <Ionicons name="calendar-outline" size={16} color="#7C3AED" />
                          </View>
                          <View style={{ flex: 1 }}>
                            <Text style={styles.leaveType}>{leave.leaveType}</Text>
                            <Text style={styles.leaveDate}>{leave.date}</Text>
                          </View>
                        </View>
                        <View style={[styles.leaveStatusBadge, { backgroundColor: statusBg }]}>
                          <Text style={[styles.leaveStatusText, { color: statusColor }]}>
                            {leave.status}
                          </Text>
                        </View>
                      </View>
                      {leave.reason ? (
                        <Text style={styles.leaveReason} numberOfLines={1}>{leave.reason}</Text>
                      ) : null}
                      <View style={styles.projectTapHint}>
                        <Ionicons name="eye-outline" size={12} color="#9CA3AF" />
                        <Text style={styles.projectTapHintText}>Tap to view full details</Text>
                      </View>
                    </TouchableOpacity>
                  );
                })}
              </View>
            )}

            {/* Approve / Reject + Send Mail — Admin only */}
            {isViewingEmployee && canApprove && canApproveByDomain && overallStatus === 'Pending' && (
              <View style={styles.approvalCard}>
                    <Text style={styles.approvalCardTitle}>Timesheet Review & Approval</Text>

                    {managerMailSendCount > 0 && (
                      <Text style={{ fontSize: 12, fontWeight: '600', color: '#4B5563', marginBottom: 12 }}>
                        Email sent {managerMailSendCount}/{MAX_MANAGER_MAIL_SENDS} times
                      </Text>
                    )}

                    <View style={{ marginBottom: 16 }}>
                      <Text style={styles.approvalLabel}>Status</Text>
                      <TouchableOpacity
                        style={styles.approvalDropdown}
                        onPress={() => setApprovalDropdownOpen(!approvalDropdownOpen)}
                      >
                        <Text style={[
                          styles.approvalDropdownText,
                          approvalStatus === 'Approved' && { color: '#15803D' },
                          approvalStatus === 'Rejected' && { color: '#B91C1C' },
                        ]}>{approvalStatus}</Text>
                        <Ionicons name={approvalDropdownOpen ? "chevron-up" : "chevron-down"} size={16} color="#4B5563" />
                      </TouchableOpacity>

                      {approvalDropdownOpen && (
                        <View style={styles.approvalDropdownMenu}>
                          {(['Approved', 'Rejected'] as const).map((status) => (
                            <TouchableOpacity
                              key={status}
                              style={[styles.approvalDropdownOption, approvalStatus === status && styles.approvalDropdownOptionSelected]}
                              onPress={() => { setApprovalStatus(status); setApprovalDropdownOpen(false); }}
                            >
                              <Text style={[
                                styles.approvalDropdownOptionText,
                                approvalStatus === status && { color: '#2563EB' }
                              ]}>{status}</Text>
                            </TouchableOpacity>
                          ))}
                        </View>
                      )}
                    </View>

                    <View style={{ marginBottom: 4 }}>
                      <Text style={styles.approvalLabel}>Remarks</Text>
                      <TextInput
                        style={styles.approvalRemarksInput}
                        placeholder="Enter approval/rejection remarks..."
                        placeholderTextColor="#9CA3AF"
                        multiline
                        numberOfLines={3}
                        value={approvalRemarks}
                        onChangeText={(text) => {
                          const { value, hadInvalidStart } = sanitizeReasonText(text);
                          setApprovalRemarks(value);
                          setApprovalRemarksWarning(hadInvalidStart);
                        }}
                      />
                      {approvalRemarksWarning && <Text style={styles.errorText}>{REASON_VALIDATION_MESSAGE}</Text>}
                    </View>

                    <TouchableOpacity
                      style={[styles.approvalSendBtn, (sendingMail || approvalStatus === 'Pending' || managerMailSendCount >= MAX_MANAGER_MAIL_SENDS) && { opacity: 0.6 }]}
                      onPress={handleManagerSendMail}
                      disabled={sendingMail || approvalStatus === 'Pending' || managerMailSendCount >= MAX_MANAGER_MAIL_SENDS}
                    >
                      <Ionicons name="mail-outline" size={18} color="#FFFFFF" style={{ marginRight: 8 }} />
                      <Text style={styles.approvalSendBtnText}>
                        {managerMailSendCount >= MAX_MANAGER_MAIL_SENDS
                          ? 'Send Limit Reached'
                          : approvalStatus === 'Approved' ? 'Approve & Send Mail'
                          : approvalStatus === 'Rejected' ? 'Reject & Send Mail'
                          : 'Send Mail'}
                      </Text>
                    </TouchableOpacity>
              </View>
            )}

          </ScrollView>
        </Animated.View>
      )}

      {/* Mail sending animation overlay */}
      <MailSendingOverlay
        visible={mailOverlayVisible}
        stage={mailOverlayStage}
        onDismiss={handleMailOverlayDismiss}
        caption={mailOverlayCaption}
      />

      {/* ── PROJECT DETAIL MODAL ──────────────────────────────────── */}
      <Modal
        visible={!!selectedProject}
        animationType="slide"
        transparent
        onRequestClose={() => setSelectedProject(null)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalSheet}>
            {/* Handle */}
            <View style={styles.modalHandle} />

            {/* Header */}
            <View style={styles.modalHeader}>
              <View style={{ flex: 1 }}>
                <Text style={styles.modalTitle}>{selectedProject}</Text>
                <Text style={styles.modalSubtitle}>Day-wise work entries</Text>
              </View>
              <TouchableOpacity
                style={styles.modalCloseBtn}
                onPress={() => setSelectedProject(null)}
              >
                <Ionicons name="close" size={20} color="#374151" />
              </TouchableOpacity>
            </View>

            <ScrollView
              style={{ flex: 1 }}
              showsVerticalScrollIndicator={false}
              contentContainerStyle={{ paddingBottom: 24 }}
            >
              {selectedProject && (projectDetailMap[selectedProject] || []).length === 0 ? (
                <Text style={styles.noData}>No detailed records available</Text>
              ) : (
                (selectedProject ? projectDetailMap[selectedProject] || [] : []).map((entry, i) => {
                  const statusColor = entry.status.toLowerCase() === 'approved' ? '#059669'
                    : entry.status.toLowerCase() === 'rejected' ? '#DC2626' : '#D97706';
                  return (
                    <View key={i} style={styles.modalEntryCard}>
                      {/* Date badge */}
                      <View style={styles.modalEntryHeader}>
                        <View style={styles.modalDateBadge}>
                          <Ionicons name="calendar" size={12} color="#2563EB" />
                          <Text style={styles.modalDateText}>{entry.date}</Text>
                        </View>
                        <View style={[styles.modalStatusBadge, {
                          backgroundColor: entry.status.toLowerCase() === 'approved' ? '#ECFDF5'
                            : entry.status.toLowerCase() === 'rejected' ? '#FEF2F2' : '#FFFBEB'
                        }]}>
                          <Text style={[styles.modalStatusText, { color: statusColor }]}>
                            {entry.status}
                          </Text>
                        </View>
                      </View>

                      {/* Project */}
                      <View style={styles.modalEntryRow}>
                        <Ionicons name="folder-open-outline" size={14} color="#6B7280" />
                        <Text style={styles.modalEntryLabel}>Project</Text>
                        <Text style={styles.modalEntryValue}>{entry.project}</Text>
                      </View>

                      {/* Task Name */}
                      {!!entry.taskName && (
                        <View style={styles.modalEntryRow}>
                          <Ionicons name="checkmark-done-outline" size={14} color="#6B7280" />
                          <Text style={styles.modalEntryLabel}>Task</Text>
                          <Text style={styles.modalEntryValue}>{entry.taskName}</Text>
                        </View>
                      )}

                      {/* Description */}
                      {!!entry.description && entry.description !== entry.taskName && (
                        <View style={styles.modalEntryRow}>
                          <Ionicons name="document-text-outline" size={14} color="#6B7280" />
                          <Text style={styles.modalEntryLabel}>Description</Text>
                          <ExpandableText text={entry.description} />
                        </View>
                      )}

                      {/* Hours */}
                      <View style={styles.modalEntryRow}>
                        <Ionicons name="time-outline" size={14} color="#6B7280" />
                        <Text style={styles.modalEntryLabel}>Hours</Text>
                        <Text style={[styles.modalEntryValue, { color: '#2563EB', fontWeight: '700' }]}>
                          {entry.hours}h
                        </Text>
                      </View>

                      {/* Remarks */}
                      {!!entry.remarks && (
                        <View style={styles.modalEntryRow}>
                          <Ionicons name="chatbubble-ellipses-outline" size={14} color="#6B7280" />
                          <Text style={styles.modalEntryLabel}>Remarks</Text>
                          <ExpandableText text={entry.remarks} />
                        </View>
                      )}
                    </View>
                  );
                })
              )}
            </ScrollView>
          </View>
        </View>
      </Modal>

      {/* ── LEAVE DETAIL MODAL ───────────────────────────────────── */}
      <Modal
        visible={!!selectedLeave}
        animationType="slide"
        transparent
        onRequestClose={() => setSelectedLeave(null)}
      >
        <View style={styles.modalOverlay}>
          <View style={[styles.modalSheet, { maxHeight: '65%' }]}>
            {/* Handle */}
            <View style={styles.modalHandle} />

            {/* Header */}
            <View style={styles.modalHeader}>
              <View style={{ flex: 1 }}>
                <Text style={styles.modalTitle}>{selectedLeave?.leaveType || 'Leave'}</Text>
                <Text style={styles.modalSubtitle}>Leave Details</Text>
              </View>
              <TouchableOpacity
                style={styles.modalCloseBtn}
                onPress={() => setSelectedLeave(null)}
              >
                <Ionicons name="close" size={20} color="#374151" />
              </TouchableOpacity>
            </View>

            {selectedLeave && (
              <ScrollView
                showsVerticalScrollIndicator={false}
                contentContainerStyle={{ paddingBottom: 24 }}
              >
                <View style={styles.modalEntryCard}>
                  {/* Leave Type */}
                  <View style={styles.modalEntryRow}>
                    <Ionicons name="calendar-outline" size={14} color="#6B7280" />
                    <Text style={styles.modalEntryLabel}>Leave Type</Text>
                    <Text style={styles.modalEntryValue}>{selectedLeave.leaveType}</Text>
                  </View>

                  {/* Date */}
                  <View style={styles.modalEntryRow}>
                    <Ionicons name="today-outline" size={14} color="#6B7280" />
                    <Text style={styles.modalEntryLabel}>Date</Text>
                    <Text style={styles.modalEntryValue}>{selectedLeave.date}</Text>
                  </View>

                  {/* Status */}
                  <View style={styles.modalEntryRow}>
                    <Ionicons name="checkmark-circle-outline" size={14} color="#6B7280" />
                    <Text style={styles.modalEntryLabel}>Status</Text>
                    <Text style={[
                      styles.modalEntryValue,
                      { fontWeight: '700',
                        color: selectedLeave.status.toLowerCase() === 'approved' ? '#059669'
                          : selectedLeave.status.toLowerCase() === 'rejected' ? '#DC2626' : '#D97706' }
                    ]}>
                      {selectedLeave.status}
                    </Text>
                  </View>

                  {/* Activity */}
                  {!!selectedLeave.activity && (
                    <View style={styles.modalEntryRow}>
                      <Ionicons name="checkmark-done-outline" size={14} color="#6B7280" />
                      <Text style={styles.modalEntryLabel}>Activity</Text>
                      <ExpandableText text={selectedLeave.activity} />
                    </View>
                  )}

                  {/* Reason */}
                  {!!selectedLeave.reason && (
                    <View style={styles.modalEntryRow}>
                      <Ionicons name="help-circle-outline" size={14} color="#6B7280" />
                      <Text style={styles.modalEntryLabel}>Reason</Text>
                      <ExpandableText text={selectedLeave.reason} />
                    </View>
                  )}

                  {/* Applied Date */}
                  {!!selectedLeave.appliedDate && (
                    <View style={styles.modalEntryRow}>
                      <Ionicons name="send-outline" size={14} color="#6B7280" />
                      <Text style={styles.modalEntryLabel}>Applied On</Text>
                      <Text style={styles.modalEntryValue}>{selectedLeave.appliedDate}</Text>
                    </View>
                  )}

                </View>
              </ScrollView>
            )}
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#F3F4F6',
  },
  header: {
    paddingTop: Platform.OS === 'android' ? (StatusBar.currentHeight || 0) + 10 : 10,
    paddingBottom: 30,
    borderBottomLeftRadius: 32,
    borderBottomRightRadius: 32,
  },
  headerNav: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
  },
  backBtn: {
    padding: 6,
    borderRadius: 12,
    backgroundColor: 'rgba(255, 255, 255, 0.2)',
  },
  exportBtn: {
    padding: 6,
    borderRadius: 12,
    backgroundColor: 'rgba(255, 255, 255, 0.2)',
  },
  headerTitle: {
    color: '#FFFFFF',
    fontSize: 18,
    fontWeight: '700',
  },
  headerContent: {
    marginTop: 24,
    alignItems: 'center',
  },
  headerMonth: {
    color: '#FFFFFF',
    fontSize: 26,
    fontWeight: '800',
  },
  headerSubtitle: {
    color: 'rgba(255, 255, 255, 0.8)',
    fontSize: 14,
    marginTop: 4,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 20,
  },
  loadingText: {
    marginTop: 12,
    color: '#4B5563',
    fontSize: 14,
    fontWeight: '500',
  },
  content: {
    flex: 1,
    marginTop: -20,
  },
  scrollContent: {
    paddingHorizontal: 16,
    paddingBottom: 40,
  },
  statsGrid: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 16,
  },
  statCard: {
    flex: 1,
    backgroundColor: '#FFFFFF',
    borderRadius: 20,
    padding: 16,
    alignItems: 'center',
    marginHorizontal: 4,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.05,
    shadowRadius: 8,
    elevation: 2,
  },
  statIconBg: {
    width: 38,
    height: 38,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 10,
  },
  statValue: {
    fontSize: 18,
    fontWeight: '800',
    color: '#111827',
  },
  statLabel: {
    fontSize: 11,
    color: '#6B7280',
    marginTop: 2,
    fontWeight: '500',
  },
  chartCard: {
    backgroundColor: '#FFFFFF',
    borderRadius: 24,
    padding: 20,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.05,
    shadowRadius: 8,
    elevation: 2,
  },
  cardTitle: {
    fontSize: 16,
    fontWeight: '700',
    color: '#111827',
    marginBottom: 16,
  },
  noData: {
    fontSize: 13,
    color: '#9CA3AF',
    fontStyle: 'italic',
    textAlign: 'center',
    paddingVertical: 10,
  },
  chartRow: {
    marginBottom: 16,
  },
  chartLabelRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 6,
  },
  typeNameContainer: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  colorDot: {
    width: 10,
    height: 10,
    borderRadius: 5,
    marginRight: 8,
  },
  typeName: {
    fontSize: 13,
    fontWeight: '600',
    color: '#374151',
  },
  typeValue: {
    fontSize: 13,
    fontWeight: '700',
    color: '#111827',
  },
  progressBarBg: {
    height: 8,
    backgroundColor: '#F3F4F6',
    borderRadius: 4,
    overflow: 'hidden',
  },
  progressBarFill: {
    height: '100%',
    borderRadius: 4,
  },
  projectsCard: {
    backgroundColor: '#FFFFFF',
    borderRadius: 24,
    padding: 20,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.05,
    shadowRadius: 8,
    elevation: 2,
  },
  projectItem: {
    borderBottomWidth: 1,
    borderBottomColor: '#F3F4F6',
    paddingVertical: 12,
  },
  projectHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 4,
  },
  projectIconBg: {
    width: 26,
    height: 26,
    borderRadius: 8,
    backgroundColor: '#EFF6FF',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 8,
  },
  projectName: {
    fontSize: 14,
    fontWeight: '700',
    color: '#111827',
    flex: 1,
  },
  projectHoursBadge: {
    backgroundColor: '#EFF6FF',
    borderRadius: 10,
    paddingHorizontal: 10,
    paddingVertical: 3,
  },
  projectHours: {
    fontSize: 13,
    fontWeight: '700',
    color: '#2563EB',
  },
  projectActivity: {
    fontSize: 12,
    color: '#6B7280',
    marginTop: 2,
    marginLeft: 34,
  },
  projectTapHint: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: 6,
    marginLeft: 34,
    gap: 4,
  },
  projectTapHintText: {
    fontSize: 11,
    color: '#9CA3AF',
  },
  // Leave card styles
  leavesCard: {
    backgroundColor: '#FFFFFF',
    borderRadius: 24,
    padding: 20,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.05,
    shadowRadius: 8,
    elevation: 2,
  },
  leaveItem: {
    borderBottomWidth: 1,
    borderBottomColor: '#F3F4F6',
    paddingVertical: 12,
  },
  leaveRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  leaveLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
  },
  leaveIconBg: {
    width: 34,
    height: 34,
    borderRadius: 10,
    backgroundColor: '#F5F3FF',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 10,
  },
  leaveType: {
    fontSize: 14,
    fontWeight: '700',
    color: '#111827',
  },
  leaveDate: {
    fontSize: 12,
    color: '#6B7280',
    marginTop: 2,
  },
  leaveStatusBadge: {
    borderRadius: 10,
    paddingHorizontal: 10,
    paddingVertical: 4,
  },
  leaveStatusText: {
    fontSize: 12,
    fontWeight: '700',
  },
  leaveReason: {
    fontSize: 12,
    color: '#6B7280',
    marginTop: 4,
    marginLeft: 44,
    fontStyle: 'italic',
  },
  // Modal styles
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.45)',
    justifyContent: 'flex-end',
  },
  modalSheet: {
    backgroundColor: '#FFFFFF',
    borderTopLeftRadius: 28,
    borderTopRightRadius: 28,
    paddingHorizontal: 20,
    paddingBottom: 0,
    maxHeight: '85%',
    minHeight: '40%',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: -4 },
    shadowOpacity: 0.15,
    shadowRadius: 12,
    elevation: 10,
  },
  modalHandle: {
    width: 40,
    height: 4,
    backgroundColor: '#D1D5DB',
    borderRadius: 2,
    alignSelf: 'center',
    marginTop: 12,
    marginBottom: 4,
  },
  modalHeader: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    paddingTop: 12,
    paddingBottom: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#F3F4F6',
    marginBottom: 12,
  },
  modalTitle: {
    fontSize: 17,
    fontWeight: '800',
    color: '#111827',
  },
  modalSubtitle: {
    fontSize: 12,
    color: '#6B7280',
    marginTop: 2,
  },
  modalCloseBtn: {
    width: 32,
    height: 32,
    borderRadius: 16,
    backgroundColor: '#F3F4F6',
    alignItems: 'center',
    justifyContent: 'center',
    marginLeft: 12,
  },
  modalEntryCard: {
    backgroundColor: '#F9FAFB',
    borderRadius: 16,
    padding: 14,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: '#E5E7EB',
  },
  modalEntryHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  modalDateBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#EFF6FF',
    borderRadius: 8,
    paddingHorizontal: 8,
    paddingVertical: 4,
    gap: 4,
  },
  modalDateText: {
    fontSize: 12,
    fontWeight: '700',
    color: '#1D4ED8',
  },
  modalStatusBadge: {
    borderRadius: 8,
    paddingHorizontal: 8,
    paddingVertical: 3,
  },
  modalStatusText: {
    fontSize: 11,
    fontWeight: '700',
  },
  modalEntryRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    marginTop: 8,
    gap: 6,
  },
  modalEntryLabel: {
    fontSize: 12,
    color: '#6B7280',
    fontWeight: '600',
    width: 80,
    flexShrink: 0,
  },
  modalEntryValue: {
    fontSize: 13,
    color: '#111827',
    fontWeight: '500',
    flexShrink: 1,
  },
  statusDisplayCard: {
    borderRadius: 16,
    marginBottom: 16,
    borderWidth: 1,
    padding: 14,
  },
  noteCard: {
    backgroundColor: '#FFFBEB',
    borderRadius: 20,
    padding: 16,
    flexDirection: 'row',
    alignItems: 'flex-start',
    borderWidth: 1,
    borderColor: '#FEF3C7',
  },
  noteIcon: {
    marginRight: 12,
    marginTop: 2,
  },
  noteTextContainer: {
    flex: 1,
  },
  noteTitle: {
    fontSize: 14,
    fontWeight: '700',
    color: '#D97706',
    marginBottom: 4,
  },
  noteText: {
    fontSize: 12,
    color: '#B45309',
    lineHeight: 18,
    fontWeight: '500',
  },
  approvalCard: {
    backgroundColor: '#FFFFFF',
    borderRadius: 24,
    padding: 20,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.05,
    shadowRadius: 8,
    elevation: 2,
    borderWidth: 1,
    borderColor: '#E0E7FF',
  },
  approvalCardTitle: {
    fontSize: 16,
    fontWeight: '700',
    color: '#111827',
    marginBottom: 16,
  },
  approvalLabel: {
    fontSize: 13,
    fontWeight: '600',
    color: '#374151',
    marginBottom: 6,
  },
  errorText: {
    color: '#EF4444',
    fontSize: 12,
    marginTop: 4,
  },
  approvalDropdown: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    borderWidth: 1,
    borderColor: '#D1D5DB',
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 12,
    backgroundColor: '#F9FAFB',
  },
  approvalDropdownText: {
    fontSize: 15,
    fontWeight: '600',
    color: '#374151',
  },
  approvalDropdownMenu: {
    borderWidth: 1,
    borderColor: '#D1D5DB',
    borderRadius: 12,
    marginTop: 4,
    backgroundColor: '#FFFFFF',
    overflow: 'hidden',
  },
  approvalDropdownOption: {
    paddingHorizontal: 14,
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#F3F4F6',
  },
  approvalDropdownOptionSelected: {
    backgroundColor: '#F0FDF4',
  },
  approvalDropdownOptionText: {
    fontSize: 14,
    fontWeight: '600',
  },
  approvalRemarksInput: {
    borderWidth: 1,
    borderColor: '#D1D5DB',
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 10,
    fontSize: 14,
    color: '#111827',
    backgroundColor: '#F9FAFB',
    textAlignVertical: 'top',
    minHeight: 80,
  },
  approvalSendBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#2563EB',
    borderRadius: 14,
    paddingVertical: 14,
    marginTop: 16,
  },
  approvalSendBtnText: {
    color: '#FFFFFF',
    fontSize: 15,
    fontWeight: '700',
  },
  mailSentCard: {
    alignItems: 'center',
    paddingVertical: 20,
  },
  mailSentTitle: {
    fontSize: 16,
    fontWeight: '700',
    color: '#059669',
    marginTop: 10,
  },
  mailSentSubtitle: {
    fontSize: 13,
    color: '#6B7280',
    marginTop: 4,
    textAlign: 'center',
  },
  mailSentResetBtn: {
    marginTop: 14,
    paddingHorizontal: 20,
    paddingVertical: 8,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: '#2563EB',
  },
  mailSentResetBtnText: {
    color: '#2563EB',
    fontSize: 13,
    fontWeight: '600',
  },
});
