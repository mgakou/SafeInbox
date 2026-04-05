// ================================================================
// utils/logger.js — journalisation locale des analyses SafeInbox
// Stockage: chrome.storage.local (sans backend)
// ================================================================

const STORAGE_KEY = "safeInboxAnalysisLogs";
const DEFAULT_MAX_LOGS = 300;

function nowIso() {
  return new Date().toISOString();
}

function hashString(input = "") {
  let h = 5381;
  for (let i = 0; i < input.length; i++) {
    h = (h * 33) ^ input.charCodeAt(i);
  }
  return (h >>> 0).toString(36);
}

function normalizeUrl(url = "") {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}${u.hash || ""}`;
  } catch {
    return url || "";
  }
}

export function buildEmailViewId(email = {}, gmailUrl = "") {
  const sender = (email.sender || "").toLowerCase().trim();
  const subject = (email.subject || "").trim();
  const bodyLen = Number(email.body?.length || email.bodyLength || 0);
  const linksLen = Array.isArray(email.links) ? email.links.length : Number(email.linkCount || 0);
  const attLen = Array.isArray(email.attachments) ? email.attachments.length : Number(email.attachmentCount || 0);
  const key = `${sender}|${subject}|${bodyLen}|${linksLen}|${attLen}|${normalizeUrl(gmailUrl)}`;
  return `scan_${hashString(key)}`;
}

async function getLogState() {
  const { [STORAGE_KEY]: logs = [] } = await chrome.storage.local.get({ [STORAGE_KEY]: [] });
  return Array.isArray(logs) ? logs : [];
}

async function setLogState(logs = [], maxLogs = DEFAULT_MAX_LOGS) {
  const clean = Array.isArray(logs) ? logs.slice(-maxLogs) : [];
  await chrome.storage.local.set({ [STORAGE_KEY]: clean });
}

function sanitizeEmail(email = {}) {
  const links = Array.isArray(email.links) ? email.links : [];
  const attachments = Array.isArray(email.attachments) ? email.attachments : [];
  return {
    sender: email.sender || "",
    senderName: email.senderName || "",
    subject: email.subject || "",
    bodyLength: Number(email.bodyLength ?? email.body?.length ?? 0),
    links,
    linkCount: links.length,
    attachments,
    attachmentCount: attachments.length,
  };
}

export async function upsertAnalysisLog(entry, options = {}) {
  const maxLogs = Number(options.maxLogs || DEFAULT_MAX_LOGS);
  const timestamp = entry?.timestamp || nowIso();
  const viewId = entry?.viewId || buildEmailViewId(entry?.email || {}, entry?.gmailUrl || "");
  if (!viewId) return null;

  const logs = await getLogState();
  const idx = logs.findIndex((l) => l.viewId === viewId);

  const normalized = {
    schemaVersion: "1.0",
    viewId,
    timestamp,
    updatedAt: nowIso(),
    gmailUrl: normalizeUrl(entry?.gmailUrl || ""),
    email: sanitizeEmail(entry?.email || {}),
    analysis: {
      engine: entry?.analysis?.engine || "none",
      riskScore: Number.isFinite(entry?.analysis?.riskScore) ? entry.analysis.riskScore : null,
      reasons: Array.isArray(entry?.analysis?.reasons) ? entry.analysis.reasons : [],
      threshold: Number.isFinite(entry?.analysis?.threshold) ? entry.analysis.threshold : null,
      mode: entry?.analysis?.mode || "auto",
    },
    decision: {
      bannerShown: Boolean(entry?.decision?.bannerShown),
      trustedSender: Boolean(entry?.decision?.trustedSender),
      ignoredSender: Boolean(entry?.decision?.ignoredSender),
      skipped: Boolean(entry?.decision?.skipped),
      skipReason: entry?.decision?.skipReason || null,
    },
    userActions: Array.isArray(entry?.userActions) ? entry.userActions : [],
  };

  if (idx >= 0) {
    const prev = logs[idx];
    logs[idx] = {
      ...prev,
      ...normalized,
      userActions: Array.isArray(prev.userActions) ? prev.userActions : [],
      timestamp: prev.timestamp || normalized.timestamp,
      updatedAt: nowIso(),
    };
  } else {
    logs.push(normalized);
  }

  await setLogState(logs, maxLogs);
  return normalized;
}

export async function appendUserAction(viewId, type, details = {}) {
  if (!viewId || !type) return;
  const logs = await getLogState();
  const idx = logs.findIndex((l) => l.viewId === viewId);
  if (idx < 0) return;

  const action = {
    type,
    timestamp: nowIso(),
    details,
  };

  const prevActions = Array.isArray(logs[idx].userActions) ? logs[idx].userActions : [];
  logs[idx].userActions = [...prevActions, action];
  logs[idx].updatedAt = nowIso();

  await chrome.storage.local.set({ [STORAGE_KEY]: logs });
}

export async function getAnalysisLogs() {
  return await getLogState();
}

export async function buildExportPayload() {
  const logs = await getLogState();
  return {
    tool: "SafeInbox",
    exportVersion: "1.0",
    exportedAt: nowIso(),
    total: logs.length,
    logs,
  };
}
