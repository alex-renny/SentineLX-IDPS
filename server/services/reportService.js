import Alert from "../models/Alert.js";

const RANGE_WINDOWS = {
  "1h": 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function resolveReportRange({ range = "24h", start, end } = {}) {
  const now = new Date();

  if (range === "custom") {
    const startDate = new Date(start);
    const endDate = new Date(end);
    if (Number.isNaN(startDate.getTime()) || Number.isNaN(endDate.getTime())) {
      const error = new Error("A valid start and end date are required for a custom range");
      error.statusCode = 400;
      throw error;
    }
    if (startDate > endDate) {
      const error = new Error("The start date must be before the end date");
      error.statusCode = 400;
      throw error;
    }
    return { range, start: startDate, end: endDate };
  }

  const duration = RANGE_WINDOWS[range] || RANGE_WINDOWS["24h"];
  return { range: RANGE_WINDOWS[range] ? range : "24h", start: new Date(now - duration), end: now };
}

const displayThreat = (type) => String(type || "UNKNOWN").replaceAll("_", " ");

export async function getSecurityReport(options = {}) {
  const period = resolveReportRange(options);
  const match = { detected_at: { $gte: period.start, $lte: period.end } };

  const [summaryRows, threatRows, severityRows, sourceRows, blockedAlerts, alerts] = await Promise.all([
    Alert.aggregate([
      { $match: match },
      {
        $group: {
          _id: null,
          totalAlerts: { $sum: 1 },
          blocked: { $sum: { $cond: [{ $eq: ["$status", "BLOCKED"] }, 1, 0] } },
        },
      },
    ]),
    Alert.aggregate([{ $match: match }, { $group: { _id: "$type", count: { $sum: 1 } } }, { $sort: { count: -1, _id: 1 } }]),
    Alert.aggregate([{ $match: match }, { $group: { _id: "$severity", count: { $sum: 1 } } }]),
    Alert.aggregate([
      { $match: { ...match, source_ip: { $nin: [null, ""] } } },
      { $group: { _id: "$source_ip", count: { $sum: 1 } } },
      { $sort: { count: -1, _id: 1 } },
      { $limit: 10 },
    ]),
    Alert.find({ ...match, status: "BLOCKED" })
      .sort({ detected_at: -1 })
      .select("source_ip type prevention_action detected_at")
      .limit(50)
      .lean(),
    Alert.find(match).sort({ detected_at: -1 }).lean(),
  ]);

  const summary = summaryRows[0] || { totalAlerts: 0, blocked: 0 };
  const severityMap = Object.fromEntries(severityRows.map((item) => [item._id, item.count]));

  return {
    period: { ...period, start: period.start.toISOString(), end: period.end.toISOString() },
    summary: {
      totalAlerts: summary.totalAlerts,
      blocked: summary.blocked,
      severities: SEVERITIES.map((severity) => ({ severity, count: severityMap[severity] || 0 })),
    },
    threats: threatRows.map((item) => ({ type: item._id || "UNKNOWN", label: displayThreat(item._id), count: item.count })),
    topSources: sourceRows.map((item) => ({ sourceIp: item._id, count: item.count })),
    blockedSources: blockedAlerts.map((alert) => ({
      sourceIp: alert.source_ip || "Unknown",
      threat: displayThreat(alert.type),
      action: alert.prevention_action === "BLOCK_SIMULATED" ? "BLOCK_SIMULATED" : "BLOCKED",
      detectedAt: alert.detected_at,
    })),
    alerts,
  };
}

export function escapeCsv(value) {
  const text = value == null ? "" : String(value);
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export function reportCsv(report) {
  const header = ["timestamp", "type", "severity", "source_ip", "status", "prevention_action"];
  const rows = report.alerts.map((alert) => [
    new Date(alert.detected_at).toISOString(),
    alert.type,
    alert.severity,
    alert.source_ip,
    alert.status,
    alert.prevention_action,
  ].map(escapeCsv).join(","));
  return [header.join(","), ...rows].join("\r\n");
}
