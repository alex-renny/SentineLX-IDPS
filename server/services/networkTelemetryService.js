let latestTraffic = {
  success: true,
  timestamp: null,
  capture_interface: null,
  local_ip: null,
  capture_status: "WAITING",
  duration: 0,
  packet_count: 0,
  alert_count: 0,
  packets: [],
};

export function updateNetworkTelemetry(scan = {}) {
  latestTraffic = {
    success: true,
    timestamp: scan.timestamp || new Date().toISOString(),
    capture_interface: scan.capture_interface || null,
    local_ip: scan.local_ip || null,
    capture_status: scan.success === false ? "ERROR" : "LIVE",
    duration: Number(scan.duration) || 0,
    packet_count: Number(scan.packet_count) || 0,
    alert_count: Number(scan.alert_count) || 0,
    // Keep the server and Socket.IO payload bounded while retaining recent traffic.
    packets: Array.isArray(scan.packets) ? scan.packets.slice(-100) : [],
  };

  return latestTraffic;
}

export function getNetworkTelemetry() {
  return latestTraffic;
}
