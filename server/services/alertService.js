import Alert from "../models/Alert.js";

let ioInstance = null;

export function initializeAlertService(io) {
  ioInstance = io;

  console.log("🚨 Alert service initialized");
}

export async function broadcastAlert(alert) {
  try {
    // Save alert to MongoDB
    const savedAlert = await Alert.create({
      type: alert.type,
      severity: alert.severity || "MEDIUM",
      source_ip: alert.source_ip || null,
      destination_ip: alert.destination_ip || null,
      ports_detected: alert.ports_detected || 0,
      window_seconds: alert.window_seconds || 0,
      message: alert.message || "Security event detected",
      detected_at: alert.timestamp
        ? new Date(alert.timestamp)
        : new Date(),
    });

    console.log(
      `🚨 Alert saved: ${savedAlert.type} | ${savedAlert.severity}`
    );

    // Send live alert to connected dashboards
    if (ioInstance) {
      ioInstance.emit("security-alert", {
        ...savedAlert.toObject(),
        received_at: new Date().toISOString(),
      });

      console.log("📡 Alert broadcast to dashboard");
    }

    return savedAlert;
  } catch (error) {
    console.error(
      "❌ Failed to save security alert:",
      error.message
    );

    return null;
  }
}