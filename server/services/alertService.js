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

    const savedAlert = await Alert.create(payload);

    console.log(
      `🚨 Alert saved: ${savedAlert.type} | ${savedAlert.severity} | ${savedAlert.status}`
    );

    if (ioInstance) {
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
