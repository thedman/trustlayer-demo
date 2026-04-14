// tools.js — Govagentic Third-Party Risk Management
// Controlled tool layer for AI-assisted vendor risk assessment.
// Agent never accesses vendors.json directly.
// Every call is logged to an immutable audit trail.

const TOOL_VERSION = "1.0.0";

// ── AUDIT LOG ─────────────────────────────────────────
const auditLog = [];

function logToolCall(toolName, vendorId, inputSummary, outputSummary) {
  const entry = {
    timestamp: new Date().toISOString(),
    session_id: window._sessionId || "unknown",
    tool: toolName,
    tool_version: TOOL_VERSION,
    vendor_id: vendorId,
    input_summary: inputSummary,
    output_summary: outputSummary,
    status: "success"
  };
  auditLog.push(entry);
  if (typeof window._onAuditLog === "function") window._onAuditLog(entry);
  return entry;
}

function logToolError(toolName, vendorId, inputSummary, errorMsg) {
  const entry = {
    timestamp: new Date().toISOString(),
    session_id: window._sessionId || "unknown",
    tool: toolName,
    tool_version: TOOL_VERSION,
    vendor_id: vendorId,
    input_summary: inputSummary,
    output_summary: null,
    status: "error",
    error: errorMsg
  };
  auditLog.push(entry);
  if (typeof window._onAuditLog === "function") window._onAuditLog(entry);
  return entry;
}

export function getAuditLog() { return [...auditLog]; }
export function resetAuditLog() { auditLog.length = 0; }

// ── VENDOR DATA ACCESS ────────────────────────────────
let _vendorStore = null;

async function getVendorStore() {
  if (_vendorStore) return _vendorStore;
  const response = await fetch("./vendors.json");
  const data = await response.json();
  _vendorStore = data.vendors;
  return _vendorStore;
}

function findVendor(vendors, vendorId) {
  return vendors.find(v => v.vendor_id === vendorId) || null;
}

// ── TOOL 1: get_vendor_profile ────────────────────────
// Returns scoped vendor overview.
// No raw document access — summary only.

export async function get_vendor_profile(vendorId) {
  const vendors = await getVendorStore();
  const vendor = findVendor(vendors, vendorId);

  if (!vendor) {
    logToolError("get_vendor_profile", vendorId, `lookup:${vendorId}`, "Vendor not found");
    return { error: "Vendor not found", vendor_id: vendorId };
  }

  const result = {
    vendor_id: vendor.vendor_id,
    name: vendor.name,
    category: vendor.category,
    tier: vendor.tier,
    current_risk_level: vendor.risk_level,
    last_reviewed: vendor.last_reviewed,
    data_residency: vendor.data_residency,
    documents_available: ["SOC 2 Report", "Security Questionnaire", "Contract Review"]
  };

  logToolCall(
    "get_vendor_profile", vendorId, `lookup:${vendorId}`,
    `${vendor.name} | ${vendor.category} | ${vendor.tier} | Risk: ${vendor.risk_level}`
  );

  return result;
}

// ── TOOL 2: get_soc2_findings ─────────────────────────
// Returns structured SOC 2 analysis.
// Agent explains findings — never fabricates them.

export async function get_soc2_findings(vendorId) {
  const vendors = await getVendorStore();
  const vendor = findVendor(vendors, vendorId);

  if (!vendor) {
    logToolError("get_soc2_findings", vendorId, `soc2:${vendorId}`, "Vendor not found");
    return { error: "Vendor not found", vendor_id: vendorId };
  }

  const s = vendor.soc2;
  const ageMonths = monthsAgo(s.report_date);
  const penTestAgeMonths = monthsAgo(s.penetration_test_date);

  // Deterministic policy checks
  const flags = [];

  if (s.type === "Type I") flags.push({
    severity: "HIGH",
    control: "SOC 2 Report Type",
    finding: "Type I report only — point-in-time assessment, not continuous. Type II required for Tier 1/2 vendors per policy.",
    policy_ref: "TPRM-POL-003"
  });

  if (ageMonths > 12) flags.push({
    severity: "HIGH",
    control: "Report Currency",
    finding: `SOC 2 report is ${ageMonths} months old — exceeds 12-month maximum per policy.`,
    policy_ref: "TPRM-POL-003"
  });

  if (s.encryption_at_rest === "AES-128") flags.push({
    severity: "HIGH",
    control: "Encryption Standard",
    finding: "AES-128 encryption at rest does not meet AES-256 minimum standard required for Confidential/Restricted data.",
    policy_ref: "SEC-POL-011"
  });

  if (!s.mfa_required) flags.push({
    severity: "HIGH",
    control: "Multi-Factor Authentication",
    finding: "MFA not enforced — required for all Tier 1 vendors processing Confidential or Restricted data.",
    policy_ref: "SEC-POL-007"
  });

  if (s.encryption_in_transit === "TLS 1.2") flags.push({
    severity: "MEDIUM",
    control: "TLS Version",
    finding: "TLS 1.2 in use — TLS 1.3 strongly preferred. Schedule upgrade plan.",
    policy_ref: "SEC-POL-011"
  });

  if (penTestAgeMonths > 12) flags.push({
    severity: penTestAgeMonths > 18 ? "HIGH" : "MEDIUM",
    control: "Penetration Testing",
    finding: `Penetration test is ${penTestAgeMonths} months old — ${penTestAgeMonths > 18 ? "critically overdue" : "approaching"} the 12-month refresh requirement.`,
    policy_ref: "TPRM-POL-005"
  });

  if (s.subprocessors && s.subprocessors.length > 8) flags.push({
    severity: "MEDIUM",
    control: "Subprocessor Concentration",
    finding: `${s.subprocessors.length} subprocessors identified — elevated supply chain risk. Confirm each has been assessed.`,
    policy_ref: "TPRM-POL-008"
  });

  const result = {
    vendor_id: vendorId,
    vendor_name: vendor.name,
    report_type: s.type,
    report_date: s.report_date,
    report_age_months: ageMonths,
    auditor: s.auditor,
    audit_period: s.period,
    trust_principles_covered: s.trust_principles,
    exception_count: s.exceptions.length,
    exceptions: s.exceptions,
    encryption_at_rest: s.encryption_at_rest,
    encryption_in_transit: s.encryption_in_transit,
    mfa_required: s.mfa_required,
    penetration_test_date: s.penetration_test_date,
    penetration_test_age_months: penTestAgeMonths,
    subprocessors: s.subprocessors,
    data_classification: s.data_classification,
    policy_flags: flags,
    assessed_by: "deterministic_policy_engine",
    policy_engine_version: "TPRM-ENGINE-2026-01"
  };

  logToolCall(
    "get_soc2_findings", vendorId, `soc2:${vendorId}`,
    `${s.exceptions.length} exceptions | ${flags.length} policy flags | Report age: ${ageMonths}mo`
  );

  return result;
}

// ── TOOL 3: get_security_questionnaire ────────────────
// Returns structured questionnaire analysis with policy flags.

export async function get_security_questionnaire(vendorId) {
  const vendors = await getVendorStore();
  const vendor = findVendor(vendors, vendorId);

  if (!vendor) {
    logToolError("get_security_questionnaire", vendorId, `questionnaire:${vendorId}`, "Vendor not found");
    return { error: "Vendor not found", vendor_id: vendorId };
  }

  const q = vendor.security_questionnaire;
  const flags = [];

  if (!q.incident_response_plan) flags.push({
    severity: "HIGH",
    area: "Incident Response",
    finding: "No incident response plan documented — required for all vendors.",
    policy_ref: "TPRM-POL-006"
  });

  if (!q.osfi_b10_acknowledged) flags.push({
    severity: "HIGH",
    area: "Regulatory Acknowledgment",
    finding: "Vendor has not acknowledged OSFI B-10 third-party risk expectations — required for regulated entity vendors.",
    policy_ref: "TPRM-POL-001"
  });

  if (q.background_checks !== "All employees and contractors") flags.push({
    severity: "MEDIUM",
    area: "Personnel Security",
    finding: `Background checks scoped to "${q.background_checks}" only — policy requires all employees and contractors.`,
    policy_ref: "HR-POL-003"
  });

  if (q.last_incident) {
    const incidentAge = monthsAgo(q.last_incident);
    if (incidentAge < 24) flags.push({
      severity: "MEDIUM",
      area: "Incident History",
      finding: `Security incident recorded ${incidentAge} months ago: ${q.last_incident}. Root cause and remediation should be confirmed.`,
      policy_ref: "TPRM-POL-006"
    });
  }

  const bcAge = monthsAgo(q.business_continuity_tested);
  if (bcAge > 12) flags.push({
    severity: "MEDIUM",
    area: "Business Continuity",
    finding: `Business continuity plan last tested ${bcAge} months ago — annual testing required.`,
    policy_ref: "TPRM-POL-009"
  });

  if (q.patch_management_sla && q.patch_management_sla.includes("Critical: 30")) flags.push({
    severity: "MEDIUM",
    area: "Patch Management",
    finding: "Critical patch SLA is 30 days — policy requires critical patches within 14 days for Tier 1 vendors.",
    policy_ref: "SEC-POL-012"
  });

  const result = {
    vendor_id: vendorId,
    vendor_name: vendor.name,
    completed_date: q.completed_date,
    incident_response_plan: q.incident_response_plan,
    last_incident: q.last_incident,
    incident_description: q.incident_description,
    vulnerability_scanning: q.vulnerability_scanning,
    patch_management_sla: q.patch_management_sla,
    background_checks: q.background_checks,
    osfi_b10_acknowledged: q.osfi_b10_acknowledged,
    gdpr_compliant: q.gdpr_compliant,
    business_continuity_tested: q.business_continuity_tested,
    insurance_coverage: q.insurance_coverage,
    policy_flags: flags,
    assessed_by: "deterministic_policy_engine",
    policy_engine_version: "TPRM-ENGINE-2026-01"
  };

  logToolCall(
    "get_security_questionnaire", vendorId, `questionnaire:${vendorId}`,
    `${flags.length} policy flags | OSFI B-10: ${q.osfi_b10_acknowledged} | Last incident: ${q.last_incident || "none"}`
  );

  return result;
}

// ── TOOL 4: get_contract_review ───────────────────────
// Returns structured contract analysis with policy flags.

export async function get_contract_review(vendorId) {
  const vendors = await getVendorStore();
  const vendor = findVendor(vendors, vendorId);

  if (!vendor) {
    logToolError("get_contract_review", vendorId, `contract:${vendorId}`, "Vendor not found");
    return { error: "Vendor not found", vendor_id: vendorId };
  }

  const c = vendor.contract;
  const flags = [...(c.key_concerns || []).map(concern => ({
    severity: concern.includes("EXPIRED") || concern.includes("No right to audit") ? "CRITICAL" : "HIGH",
    area: "Contract Terms",
    finding: concern,
    policy_ref: "TPRM-POL-002"
  }))];

  // Additional deterministic checks
  if (!c.right_to_audit) flags.push({
    severity: "CRITICAL",
    area: "Audit Rights",
    finding: "No right to audit — cannot independently verify controls. Required for all Tier 1/2 vendors.",
    policy_ref: "TPRM-POL-002"
  });

  if (!c.data_residency_clause && vendor.data_residency.includes("US")) flags.push({
    severity: "HIGH",
    area: "Data Residency",
    finding: "No data residency clause — data may be processed or stored outside Canada without notification.",
    policy_ref: "PRIV-POL-004"
  });

  // Check if contract is expired
  const expiry = new Date(c.expiry_date);
  const today = new Date();
  const isExpired = expiry < today;
  const daysUntilExpiry = Math.ceil((expiry - today) / (1000 * 60 * 60 * 24));

  if (isExpired) flags.push({
    severity: "CRITICAL",
    area: "Contract Status",
    finding: `Contract expired on ${c.expiry_date} — currently operating without valid agreement.`,
    policy_ref: "TPRM-POL-002"
  });
  else if (daysUntilExpiry < 90) flags.push({
    severity: "HIGH",
    area: "Contract Renewal",
    finding: `Contract expires in ${daysUntilExpiry} days (${c.expiry_date}) — renewal process must begin immediately.`,
    policy_ref: "TPRM-POL-002"
  });

  const result = {
    vendor_id: vendorId,
    vendor_name: vendor.name,
    effective_date: c.effective_date,
    expiry_date: c.expiry_date,
    contract_status: isExpired ? "EXPIRED" : daysUntilExpiry < 90 ? "EXPIRING_SOON" : "ACTIVE",
    days_until_expiry: isExpired ? null : daysUntilExpiry,
    termination_notice_days: c.termination_notice_days,
    right_to_audit: c.right_to_audit,
    audit_frequency: c.audit_frequency,
    data_ownership_clause: c.data_ownership_clause,
    liability_cap: c.liability_cap,
    subprocessor_notification: c.subprocessor_notification,
    governing_law: c.governing_law,
    data_residency_clause: c.data_residency_clause,
    incident_notification_hours: c.incident_notification_hours,
    policy_flags: flags,
    assessed_by: "deterministic_policy_engine",
    policy_engine_version: "TPRM-ENGINE-2026-01"
  };

  logToolCall(
    "get_contract_review", vendorId, `contract:${vendorId}`,
    `Status: ${result.contract_status} | Audit rights: ${c.right_to_audit} | ${flags.length} flags`
  );

  return result;
}

// ── TOOL 5: generate_risk_summary ─────────────────────
// Aggregates all findings into a structured risk summary.
// Deterministic risk scoring based on flag counts and severities.

export async function generate_risk_summary(vendorId) {
  const vendors = await getVendorStore();
  const vendor = findVendor(vendors, vendorId);

  if (!vendor) {
    logToolError("generate_risk_summary", vendorId, `summary:${vendorId}`, "Vendor not found");
    return { error: "Vendor not found", vendor_id: vendorId };
  }

  // Collect all flags by reading directly from vendor data — NOT by calling
  // the exported tool functions, which would double-log to the audit trail.
  const soc2 = await _get_soc2_flags(vendor);
  const questionnaire = await _get_questionnaire_flags(vendor);
  const contract = await _get_contract_flags(vendor);

  const allFlags = [
    ...soc2.policy_flags || [],
    ...questionnaire.policy_flags || [],
    ...contract.policy_flags || []
  ];

  const criticalFlags = allFlags.filter(f => f.severity === "CRITICAL");
  const highFlags = allFlags.filter(f => f.severity === "HIGH");
  const mediumFlags = allFlags.filter(f => f.severity === "MEDIUM");

  // Deterministic risk scoring
  let riskScore = 0;
  riskScore += criticalFlags.length * 30;
  riskScore += highFlags.length * 15;
  riskScore += mediumFlags.length * 5;
  riskScore += soc2.exception_count * 10;

  let calculatedRisk;
  if (riskScore >= 100 || criticalFlags.length > 0) calculatedRisk = "HIGH";
  else if (riskScore >= 40) calculatedRisk = "MEDIUM";
  else calculatedRisk = "LOW";

  // Required actions
  const requiredActions = [];
  if (criticalFlags.length > 0) requiredActions.push("IMMEDIATE: Address all critical findings before next renewal or onboarding decision");
  if (!contract.right_to_audit) requiredActions.push("Negotiate right-to-audit clause at next contract renewal");
  if (!questionnaire.osfi_b10_acknowledged) requiredActions.push("Obtain OSFI B-10 acknowledgment from vendor");
  if (contract.contract_status === "EXPIRED") requiredActions.push("URGENT: Establish interim agreement and begin formal renewal immediately");
  if (soc2.report_age_months > 12) requiredActions.push("Request current SOC 2 report — existing report exceeds 12-month policy limit");
  if (soc2.penetration_test_age_months > 12) requiredActions.push("Request evidence of current penetration test");

  const result = {
    vendor_id: vendorId,
    vendor_name: vendor.name,
    category: vendor.category,
    tier: vendor.tier,
    calculated_risk_level: calculatedRisk,
    risk_score: riskScore,
    total_flags: allFlags.length,
    critical_flags: criticalFlags.length,
    high_flags: highFlags.length,
    medium_flags: mediumFlags.length,
    soc2_exceptions: soc2.exception_count,
    soc2_exceptions_detail: soc2.exceptions || [],
    contract_status: contract.contract_status,
    all_flags: allFlags,
    required_actions: requiredActions,
    recommended_review_frequency: calculatedRisk === "HIGH" ? "Quarterly" : calculatedRisk === "MEDIUM" ? "Semi-annual" : "Annual",
    summary_generated: new Date().toISOString(),
    scoring_engine_version: "TPRM-SCORE-2026-01",
    regulatory_frameworks: ["OSFI B-10", "NIST CSF", "ISO 27001"]
  };

  logToolCall(
    "generate_risk_summary", vendorId, `summary:${vendorId}`,
    `Risk: ${calculatedRisk} | Score: ${riskScore} | Critical: ${criticalFlags.length} | High: ${highFlags.length} | Medium: ${mediumFlags.length}`
  );

  return result;
}

// ── HELPER ────────────────────────────────────────────
function monthsAgo(dateString) {
  if (!dateString) return 0;
  const d = new Date(dateString);
  const today = new Date();
  return Math.floor((today - d) / (1000 * 60 * 60 * 24 * 30.44));
}

// ── INTERNAL FLAG HELPERS (no audit logging) ──────────
// These compute the same flags as the exported tool functions
// but do NOT log to the audit trail. Used only by generate_risk_summary
// to avoid double-counting entries.

function _get_soc2_flags(vendor) {
  const s = vendor.soc2;
  const ageMonths = monthsAgo(s.report_date);
  const penTestAgeMonths = monthsAgo(s.penetration_test_date);
  const flags = [];

  if (s.type === "Type I") flags.push({ severity: "HIGH", control: "SOC 2 Report Type", finding: "Type I report only — point-in-time assessment, not continuous. Type II required for Tier 1/2 vendors per policy.", policy_ref: "TPRM-POL-003" });
  if (ageMonths > 12) flags.push({ severity: "HIGH", control: "Report Currency", finding: `SOC 2 report is ${ageMonths} months old — exceeds 12-month maximum per policy.`, policy_ref: "TPRM-POL-003" });
  if (s.encryption_at_rest === "AES-128") flags.push({ severity: "HIGH", control: "Encryption Standard", finding: "AES-128 encryption at rest does not meet AES-256 minimum standard required for Confidential/Restricted data.", policy_ref: "SEC-POL-011" });
  if (!s.mfa_required) flags.push({ severity: "HIGH", control: "Multi-Factor Authentication", finding: "MFA not enforced — required for all Tier 1 vendors processing Confidential or Restricted data.", policy_ref: "SEC-POL-007" });
  if (s.encryption_in_transit === "TLS 1.2") flags.push({ severity: "MEDIUM", control: "TLS Version", finding: "TLS 1.2 in use — TLS 1.3 strongly preferred. Schedule upgrade plan.", policy_ref: "SEC-POL-011" });
  if (penTestAgeMonths > 12) flags.push({ severity: penTestAgeMonths > 18 ? "HIGH" : "MEDIUM", control: "Penetration Testing", finding: `Penetration test is ${penTestAgeMonths} months old — ${penTestAgeMonths > 18 ? "critically overdue" : "approaching"} the 12-month refresh requirement.`, policy_ref: "TPRM-POL-005" });
  if (s.subprocessors && s.subprocessors.length > 8) flags.push({ severity: "MEDIUM", control: "Subprocessor Concentration", finding: `${s.subprocessors.length} subprocessors identified — elevated supply chain risk. Confirm each has been assessed.`, policy_ref: "TPRM-POL-008" });

  return { policy_flags: flags, exception_count: s.exceptions.length, exceptions: s.exceptions, report_age_months: ageMonths, penetration_test_age_months: penTestAgeMonths };
}

function _get_questionnaire_flags(vendor) {
  const q = vendor.security_questionnaire;
  const flags = [];

  if (!q.incident_response_plan) flags.push({ severity: "HIGH", area: "Incident Response", finding: "No incident response plan documented — required for all vendors.", policy_ref: "TPRM-POL-006" });
  if (!q.osfi_b10_acknowledged) flags.push({ severity: "HIGH", area: "Regulatory Acknowledgment", finding: "Vendor has not acknowledged OSFI B-10 third-party risk expectations — required for regulated entity vendors.", policy_ref: "TPRM-POL-001" });
  if (q.background_checks !== "All employees and contractors") flags.push({ severity: "MEDIUM", area: "Personnel Security", finding: `Background checks scoped to "${q.background_checks}" only — policy requires all employees and contractors.`, policy_ref: "HR-POL-003" });
  if (q.last_incident) { const incidentAge = monthsAgo(q.last_incident); if (incidentAge < 24) flags.push({ severity: "MEDIUM", area: "Incident History", finding: `Security incident recorded ${incidentAge} months ago: ${q.last_incident}. Root cause and remediation should be confirmed.`, policy_ref: "TPRM-POL-006" }); }
  const bcAge = monthsAgo(q.business_continuity_tested);
  if (bcAge > 12) flags.push({ severity: "MEDIUM", area: "Business Continuity", finding: `Business continuity plan last tested ${bcAge} months ago — annual testing required.`, policy_ref: "TPRM-POL-009" });
  if (q.patch_management_sla && q.patch_management_sla.includes("Critical: 30")) flags.push({ severity: "MEDIUM", area: "Patch Management", finding: "Critical patch SLA is 30 days — policy requires critical patches within 14 days for Tier 1 vendors.", policy_ref: "SEC-POL-012" });

  return { policy_flags: flags, osfi_b10_acknowledged: q.osfi_b10_acknowledged };
}

function _get_contract_flags(vendor) {
  const c = vendor.contract;
  const flags = [...(c.key_concerns || []).map(concern => ({ severity: concern.includes("EXPIRED") || concern.includes("No right to audit") ? "CRITICAL" : "HIGH", area: "Contract Terms", finding: concern, policy_ref: "TPRM-POL-002" }))];

  if (!c.right_to_audit) flags.push({ severity: "CRITICAL", area: "Audit Rights", finding: "No right to audit — cannot independently verify controls. Required for all Tier 1/2 vendors.", policy_ref: "TPRM-POL-002" });
  if (!c.data_residency_clause && vendor.data_residency.includes("US")) flags.push({ severity: "HIGH", area: "Data Residency", finding: "No data residency clause — data may be processed or stored outside Canada without notification.", policy_ref: "PRIV-POL-004" });

  const expiry = new Date(c.expiry_date);
  const today = new Date();
  const isExpired = expiry < today;
  const daysUntilExpiry = Math.ceil((expiry - today) / (1000 * 60 * 60 * 24));

  if (isExpired) flags.push({ severity: "CRITICAL", area: "Contract Status", finding: `Contract expired on ${c.expiry_date} — currently operating without valid agreement.`, policy_ref: "TPRM-POL-002" });
  else if (daysUntilExpiry < 90) flags.push({ severity: "HIGH", area: "Contract Renewal", finding: `Contract expires in ${daysUntilExpiry} days (${c.expiry_date}) — renewal process must begin immediately.`, policy_ref: "TPRM-POL-002" });

  return { policy_flags: flags, right_to_audit: c.right_to_audit, contract_status: isExpired ? "EXPIRED" : daysUntilExpiry < 90 ? "EXPIRING_SOON" : "ACTIVE" };
}

// ── POLICY REGISTRY ──────────────────────────────────
// Authoritative list of active enterprise policies evaluated by the deterministic
// control layer. Each policy is versioned, mapped to a control ID, and aligned
// to one or more regulatory frameworks. The AI never modifies this registry.

export const POLICY_REGISTRY = [
  {
    id: "TPRM-POL-001", name: "OSFI B-10 Vendor Acknowledgment",
    version: "v2026.01", control_id: "CTRL-REG-001", category: "Regulatory Compliance",
    regulatory_mapping: ["OSFI B-10", "OCC 2013-29"],
    description: "All vendors processing data on behalf of a regulated entity must acknowledge OSFI B-10 third-party risk expectations.",
    status: "active"
  },
  {
    id: "TPRM-POL-002", name: "Third-Party Contract Standards",
    version: "v2026.01", control_id: "CTRL-CONT-001", category: "Contract Governance",
    regulatory_mapping: ["OSFI B-10", "SR 13-19"],
    description: "All Tier 1/2 vendor contracts must include right-to-audit, data ownership, and data residency clauses.",
    status: "active"
  },
  {
    id: "TPRM-POL-003", name: "SOC 2 Report Currency Standard",
    version: "v2026.01", control_id: "CTRL-SOC-001", category: "Assurance & Compliance",
    regulatory_mapping: ["NIST CSF", "ISO 27001"],
    description: "SOC 2 Type II required for all Tier 1/2 vendors. Reports must be no older than 12 months.",
    status: "active"
  },
  {
    id: "TPRM-POL-005", name: "Penetration Testing Requirements",
    version: "v2026.01", control_id: "CTRL-SEC-002", category: "Security Assurance",
    regulatory_mapping: ["NIST CSF", "ISO 27001"],
    description: "Annual penetration testing required for all Tier 1/2 vendors. Tests older than 18 months are critically overdue.",
    status: "active"
  },
  {
    id: "SEC-POL-007", name: "Multi-Factor Authentication Standard",
    version: "v2026.01", control_id: "CTRL-IAM-001", category: "Access Control",
    regulatory_mapping: ["NIST CSF", "ISO 27001"],
    description: "MFA required for all Tier 1 vendors processing Confidential or Restricted data.",
    status: "active"
  },
  {
    id: "SEC-POL-011", name: "Encryption Standards",
    version: "v2026.01", control_id: "CTRL-ENC-001", category: "Data Protection",
    regulatory_mapping: ["OSFI B-10", "NIST CSF"],
    description: "AES-256 required for data at rest; TLS 1.3 strongly preferred for data in transit.",
    status: "active"
  },
  {
    id: "TPRM-POL-006", name: "Incident Response Plan Requirement",
    version: "v2026.01", control_id: "CTRL-OPS-001", category: "Operational Resilience",
    regulatory_mapping: ["OSFI B-10", "NIST CSF"],
    description: "All vendors must maintain and provide evidence of a documented incident response plan.",
    status: "active"
  },
  {
    id: "SCOPE-001", name: "Vendor Scope Restriction",
    version: "v2026.01", control_id: "CTRL-DATA-001", category: "Data Access Control",
    regulatory_mapping: ["OSFI B-10"],
    description: "AI agent access is scoped to the currently selected vendor only. Cross-vendor queries require elevated session authorization.",
    status: "active"
  },
  {
    id: "EXPORT-001", name: "Raw Document Export Control",
    version: "v2026.01", control_id: "CTRL-DATA-002", category: "Data Access Control",
    regulatory_mapping: ["OSFI B-10", "PRIV-POL-004"],
    description: "Raw third-party documents may not be exported from the controlled assessment environment without explicit authorization.",
    status: "active"
  },
  {
    id: "MODIFY-001", name: "Read-Only Agent Authorization",
    version: "v2026.01", control_id: "CTRL-DATA-003", category: "Agent Authorization",
    regulatory_mapping: ["OSFI B-10", "NIST CSF"],
    description: "AI agents in assessment mode are authorized for read-only operations only. Write actions and approval decisions require human authorization by a designated Control Owner.",
    status: "active"
  }
];

// ── TOOL DEFINITIONS FOR CLAUDE API ──────────────────
export const TOOL_DEFINITIONS = [
  {
    name: "get_vendor_profile",
    description: "Retrieve a scoped vendor overview including category, tier, current risk level, and available documents. Always call this first before any other tool.",
    input_schema: {
      type: "object",
      properties: {
        vendor_id: { type: "string", description: "The vendor ID (e.g. V-2001)" }
      },
      required: ["vendor_id"]
    }
  },
  {
    name: "get_soc2_findings",
    description: "Retrieve structured SOC 2 analysis including exceptions, encryption standards, MFA status, penetration test currency, and deterministic policy flags. The policy engine has already applied organizational controls policy — do not re-evaluate, only explain.",
    input_schema: {
      type: "object",
      properties: {
        vendor_id: { type: "string", description: "The vendor ID" }
      },
      required: ["vendor_id"]
    }
  },
  {
    name: "get_security_questionnaire",
    description: "Retrieve structured security questionnaire findings including incident history, background check scope, OSFI B-10 acknowledgment, and deterministic policy flags.",
    input_schema: {
      type: "object",
      properties: {
        vendor_id: { type: "string", description: "The vendor ID" }
      },
      required: ["vendor_id"]
    }
  },
  {
    name: "get_contract_review",
    description: "Retrieve structured contract analysis including expiry status, audit rights, data residency clause, liability cap, and deterministic policy flags.",
    input_schema: {
      type: "object",
      properties: {
        vendor_id: { type: "string", description: "The vendor ID" }
      },
      required: ["vendor_id"]
    }
  },
  {
    name: "generate_risk_summary",
    description: "Generate a comprehensive risk summary aggregating all findings across SOC 2, security questionnaire, and contract. Includes deterministic risk score, flag counts, required actions, and recommended review frequency. Call this to produce the final structured risk output.",
    input_schema: {
      type: "object",
      properties: {
        vendor_id: { type: "string", description: "The vendor ID" }
      },
      required: ["vendor_id"]
    }
  }
];

export const SYSTEM_PROMPT = `You are a controlled AI assistant demonstrating Govagentic — a governance framework for AI-assisted third-party risk management in regulated financial services.

Your role is to help risk analysts assess vendor risk posture by retrieving and explaining structured findings from controlled tools.

This demo illustrates a control-first architecture where:
- All vendor data is accessed through controlled tools only — never directly
- Risk scoring and policy flag determination is done by a deterministic rules engine, not the AI
- The AI explains findings and synthesizes analysis — it never generates risk scores or policy judgments
- Every tool call is logged to an immutable audit trail visible in the panel
- Regulatory alignment: OSFI B-10, OCC Third-Party Risk Guidance, Federal Reserve SR 13-19, NIST CSF

CRITICAL RULES:
1. Use tools for all data. Never infer, estimate, or fabricate vendor information.
2. Risk scores and policy flags come from the deterministic engine — explain them, never override or second-guess them.
3. Always start with get_vendor_profile, then use other tools as needed.
4. For a full risk assessment, call all four document tools then generate_risk_summary.
5. Always reference the policy_ref codes when discussing flags — this supports audit traceability.
6. Do not assess vendors outside the current request scope.
7. Do not recommend vendor approval or rejection — provide findings and recommended actions only.

TOOL CALL RULES — STRICTLY ENFORCED:
1. Call get_vendor_profile ONCE only.
2. Call get_soc2_findings ONCE only.
3. Call get_security_questionnaire ONCE only.
4. Call get_contract_review ONCE only.
5. Call generate_risk_summary ONCE only, after all other tools have been called.
6. If you have already called a tool and received a result, you MUST NOT call it again. The result is complete and final.
7. Calling a tool more than once is a policy violation and wastes the assessment budget.

Total tool calls for a full assessment: exactly 5. No more.

RESPONSE FORMAT:
Structure your response clearly:
- Vendor Overview (brief)
- Key Risk Findings (organized by severity: Critical → High → Medium)
- Document-by-Document Summary (SOC 2, Questionnaire, Contract)
- Required Actions
- Recommended Next Steps

Language: precise, professional, risk-literate. This output may be reviewed by auditors.
Keep responses concise and structured. Limit the total response to 800 words maximum. Use headers and bullets but avoid repeating information already visible in the Risk Card. Focus on the most important findings and required actions only.`;