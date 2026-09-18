import Settings from "../models/Settings.js";

const integer = (value, name, min, max) => {
  if (!Number.isInteger(Number(value)) || Number(value) < min || Number(value) > max) {
    const error = new Error(`${name} must be an integer between ${min} and ${max}`);
    error.statusCode = 400;
    throw error;
  }
  return Number(value);
};

const bool = (value, name) => {
  if (typeof value !== "boolean") { const error = new Error(`${name} must be true or false`); error.statusCode = 400; throw error; }
  return value;
};

export function defaultSettings() {
  return {
    detectors: { portScan: true, bruteForce: true, ddos: true, abnormalTraffic: true },
    thresholds: { portScanPorts: 30, portScanWindow: 10, bruteForceAttempts: 20, bruteForceWindow: 60, ddosThreshold: 1000, ddosPeakThreshold: 3000, ddosSustainedThreshold: 1500, ddosValidationWindow: 5 },
    prevention: { mode: "test", autoBlock: false },
    network: { captureInterface: "", captureDuration: 5, captureInterval: 1 },
    alerts: { liveAlerts: true, saveToDatabase: true, socketNotifications: true, maximumStoredAlerts: 5000 },
  };
}

export async function getSettings() {
  const stored = await Settings.findOne({ key: "global" }).lean();
  return stored?.config || defaultSettings();
}

export function validateSettings(raw) {
  const defaults = defaultSettings();
  const config = {
    detectors: { ...defaults.detectors, ...(raw?.detectors || {}) },
    thresholds: { ...defaults.thresholds, ...(raw?.thresholds || {}) },
    prevention: { ...defaults.prevention, ...(raw?.prevention || {}) },
    network: { ...defaults.network, ...(raw?.network || {}) },
    alerts: { ...defaults.alerts, ...(raw?.alerts || {}) },
  };
  Object.entries(config.detectors).forEach(([key, value]) => bool(value, `Detector ${key}`));
  ["portScanPorts", "portScanWindow", "bruteForceAttempts", "bruteForceWindow", "ddosThreshold", "ddosPeakThreshold", "ddosSustainedThreshold", "ddosValidationWindow"].forEach((key) => { config.thresholds[key] = integer(config.thresholds[key], key, 1, 1000000); });
  if (config.thresholds.ddosPeakThreshold < config.thresholds.ddosThreshold || config.thresholds.ddosSustainedThreshold < config.thresholds.ddosThreshold) { const error = new Error("DDoS peak and sustained thresholds cannot be below the observation threshold"); error.statusCode = 400; throw error; }
  if (!["test", "active"].includes(config.prevention.mode)) { const error = new Error("Prevention mode must be test or active"); error.statusCode = 400; throw error; }
  config.prevention.autoBlock = bool(config.prevention.autoBlock, "Auto block");
  config.network.captureInterface = String(config.network.captureInterface || "").trim().slice(0, 120);
  config.network.captureDuration = integer(config.network.captureDuration, "Capture duration", 1, 60);
  config.network.captureInterval = integer(config.network.captureInterval, "Capture interval", 0, 60);
  Object.entries(config.alerts).filter(([key]) => key !== "maximumStoredAlerts").forEach(([key, value]) => bool(value, `Alert setting ${key}`));
  config.alerts.maximumStoredAlerts = integer(config.alerts.maximumStoredAlerts, "Maximum stored alerts", 100, 100000);
  return config;
}

export function applyRuntimeSettings(config) {
  const { detectors, thresholds, prevention, network, alerts } = config;
  Object.assign(process.env, {
    SENTINELX_PORT_SCAN_ENABLED: String(detectors.portScan), SENTINELX_BRUTE_FORCE_ENABLED: String(detectors.bruteForce), SENTINELX_DDOS_ENABLED: String(detectors.ddos), SENTINELX_ABNORMAL_TRAFFIC_ENABLED: String(detectors.abnormalTraffic),
    SENTINELX_PORT_SCAN_THRESHOLD: String(thresholds.portScanPorts), SENTINELX_PORT_SCAN_WINDOW: String(thresholds.portScanWindow), SENTINELX_BRUTE_FORCE_THRESHOLD: String(thresholds.bruteForceAttempts), SENTINELX_BRUTE_FORCE_WINDOW: String(thresholds.bruteForceWindow), SENTINELX_DDOS_THRESHOLD: String(thresholds.ddosThreshold), SENTINELX_DDOS_PEAK_THRESHOLD: String(thresholds.ddosPeakThreshold), SENTINELX_DDOS_SUSTAINED_THRESHOLD: String(thresholds.ddosSustainedThreshold), SENTINELX_DDOS_SUSTAINED_WINDOW: String(thresholds.ddosValidationWindow),
    SENTINELX_PREVENTION_MODE: prevention.mode, SENTINELX_PREVENTION_AUTO_BLOCK: String(prevention.autoBlock), SENTINELX_FIREWALL_ENFORCEMENT: prevention.mode === "active" ? "enabled" : "disabled",
    SENTINELX_CAPTURE_INTERFACE: network.captureInterface, SENTINELX_CAPTURE_DURATION: String(network.captureDuration), SENTINELX_CAPTURE_INTERVAL: String(network.captureInterval),
    SENTINELX_ALERTS_ENABLED: String(alerts.liveAlerts), SENTINELX_ALERT_SAVE: String(alerts.saveToDatabase), SENTINELX_SOCKET_NOTIFICATIONS: String(alerts.socketNotifications), SENTINELX_ALERT_MAX_STORED: String(alerts.maximumStoredAlerts),
  });
}

export async function saveSettings(raw) {
  const config = validateSettings(raw);
  await Settings.findOneAndUpdate({ key: "global" }, { config }, { upsert: true, new: true, setDefaultsOnInsert: true });
  applyRuntimeSettings(config);
  return config;
}
