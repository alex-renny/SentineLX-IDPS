import Alert from "../models/Alert.js";

let ioInstance = null;
let currentEngineStatus = "STARTING";

// ============================================================
// INITIALIZE ALERT SERVICE
// ============================================================

export function initializeAlertService(io) {
  ioInstance = io;

  console.log("🚨 Alert service initialized");
}

// ============================================================
// ENGINE STATUS
// ============================================================

export function broadcastEngineStatus(status) {
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
  });

  console.log(`📡 Engine status broadcast: ${status}`);
}
export function getEngineStatus() {
  return currentEngineStatus;
}

// ============================================================
// BROADCAST ALERT
// ============================================================

export async function broadcastAlert(alert) {
  try {
    if (!alert) {
      console.warn("⚠️ Empty security alert received");
      return null;
    }

    // --------------------------------------------------------
    // Save alert to MongoDB
    // --------------------------------------------------------

    const savedAlert = await Alert.create({
      type: alert.type || "UNKNOWN",

      severity: alert.severity || "MEDIUM",

      source_ip: alert.source_ip || null,

      destination_ip: alert.destination_ip || null,

      ports_detected: alert.ports_detected || 0,

      window_seconds: alert.window_seconds || 0,

      message:
        alert.message ||
        "Security event detected",

      detected_at: alert.timestamp
        ? new Date(alert.timestamp)
        : new Date(),
    });

    console.log(
      `🚨 Alert saved: ${savedAlert.type} | ${savedAlert.severity}`
    );

    // --------------------------------------------------------
    // Broadcast to connected dashboards
    // --------------------------------------------------------

    if (ioInstance) {
      const dashboardAlert = {
        ...savedAlert.toObject(),

        received_at:
          new Date().toISOString(),
      };

      ioInstance.emit(
        "security-alert",
        dashboardAlert
      );

      console.log(
        "📡 Alert broadcast to dashboard"
      );
    } else {
      console.warn(
        "⚠️ Socket.IO instance not initialized"
      );
    }

    return savedAlert;

  } catch (error) {

    console.error(
      "❌ Alert service error:",
      error.message
    );

    return null;
  }
}