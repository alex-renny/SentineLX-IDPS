import Alert from "../models/Alert.js";

let ioInstance = null;
let currentEngineStatus = "STARTING";

export function initializeAlertService(io) {
  ioInstance = io;

  console.log("🚨 Alert service initialized");
}

export function broadcastEngineStatus(status, details = {}) {
  currentEngineStatus = status;

  if (!ioInstance) {
    console.log(
      `⚠️ Socket.IO not ready. Engine status stored: ${status}`
    );
    return;
  }

  ioInstance.emit("ENGINE_STATUS", {
    status,
    timestamp: new Date().toISOString(),
    ...details,
  });

  console.log(`📡 Engine status broadcast: ${status}`);
}

export function getEngineStatus() {
  return currentEngineStatus;
}

export function broadcastNetworkTraffic(traffic) {
  ioInstance?.emit("NETWORK_TRAFFIC", traffic);
}

function buildTimeline(alert) {
  const detectedAt = alert.detected_at
    ? new Date(alert.detected_at)
    : alert.timestamp
    ? new Date(alert.timestamp)
    : new Date();

  const timeline = [
    {
      status: "DETECTED",
      at: detectedAt,
      note: "Alert created by detection engine",
    },
  ];

  if (alert.status === "BLOCKED") {
    timeline.push({
      status: "BLOCKED",
      at: detectedAt,
      note:
        alert.prevention?.rule
          ? `Firewall rule ${alert.prevention.rule}`
          : "Automatic prevention",
    });
  }

  return timeline;
}

export async function broadcastAlert(alert) {
  try {
    if (String(process.env.SENTINELX_ALERTS_ENABLED || "true").toLowerCase() !== "true") {
      return null;
    }
    if (!alert) {
      console.warn("⚠️ Empty security alert received");
      return null;
    }

    const prevention = alert.prevention || null;
    const preventionAction =
      alert.prevention_action ||
      prevention?.action ||
      "NONE";

    const status =
      alert.status === "BLOCKED" || preventionAction === "BLOCKED"
        ? "BLOCKED"
        : "DETECTED";

    const payload = {
      type: alert.type || "UNKNOWN",
      severity: alert.severity || "MEDIUM",
      source_ip: alert.source_ip || null,
      destination_ip: alert.destination_ip || null,
      ports_detected: alert.ports_detected || 0,
      window_seconds: alert.window_seconds || 0,
      attempts: alert.attempts || 0,
      packets_per_second: alert.packets_per_second || 0,
      peak_packets_per_second: alert.peak_packets_per_second || 0,
      sustained_packets_per_second: alert.sustained_packets_per_second || 0,
      sustained_window_seconds: alert.sustained_window_seconds || 0,
      ddos_peak_threshold: alert.ddos_peak_threshold || 0,
      sustained_threshold: alert.sustained_threshold || 0,
      classification: alert.classification || alert.type || "UNKNOWN",
      validation_reason: alert.validation_reason || "",
      threshold: alert.threshold || 0,
      target: alert.target || null,
      service: alert.service || null,
      message: alert.message || "Security event detected",
      status,
      prevention_action: preventionAction,
      prevention,
      detected_at: alert.detected_at
        ? new Date(alert.detected_at)
        : alert.timestamp
        ? new Date(alert.timestamp)
        : new Date(),
    };

    payload.timeline = Array.isArray(alert.timeline) && alert.timeline.length
      ? alert.timeline
      : buildTimeline(payload);

    const saveAlerts = String(process.env.SENTINELX_ALERT_SAVE || "true").toLowerCase() === "true";
    const savedAlert = saveAlerts ? await Alert.create(payload) : { toObject: () => payload, ...payload };

    if (saveAlerts) {
      const maximum = Number(process.env.SENTINELX_ALERT_MAX_STORED || 5000);
      const overflow = await Alert.find().sort({ detected_at: -1 }).skip(maximum).select("_id").lean();
      if (overflow.length) await Alert.deleteMany({ _id: { $in: overflow.map((item) => item._id) } });
    }

    console.log(
      `🚨 Alert saved: ${savedAlert.type} | ${savedAlert.severity} | ${savedAlert.status}`
    );

    if (ioInstance && String(process.env.SENTINELX_SOCKET_NOTIFICATIONS || "true").toLowerCase() === "true") {
      const dashboardAlert = {
        ...savedAlert.toObject(),
        received_at: new Date().toISOString(),
      };

      ioInstance.emit("security-alert", dashboardAlert);

      console.log("📡 Alert broadcast to dashboard");
    } else {
      console.warn("⚠️ Socket.IO instance not initialized");
    }

    return savedAlert;
  } catch (error) {
    console.error("❌ Alert service error:", error.message);
    return null;
  }
}

export function emitAlertUpdated(alert) {
  if (!ioInstance || !alert) {
    return;
  }

  ioInstance.emit("alert-updated", alert);
}
