let ioInstance = null;

export function initializeAlertService(io) {
  ioInstance = io;
  console.log("🚨 Alert service initialized");
}

export function broadcastAlert(alert) {
  if (!ioInstance) {
    console.warn("⚠️ Socket.IO is not initialized");
    return;
  }

  ioInstance.emit("security-alert", {
    ...alert,
    received_at: new Date().toISOString()
  });

  console.log("🚨 Security alert broadcast:", alert.type);
}