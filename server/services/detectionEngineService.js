import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ENGINE_ROOT = path.resolve(
  __dirname,
  "../../detection-engine"
);

const WORKER_PATH = path.join(
  ENGINE_ROOT,
  "worker.py"
);

let engineProcess = null;
let engineRunning = false;

let ioInstance = null;

// ============================================================
// START DETECTION ENGINE
// ============================================================

export function startDetectionEngine(io) {

  if (engineProcess) {
    console.log("🛡️ Detection engine already running");
    return;
  }

  ioInstance = io;

  console.log("🛡️ Starting SentinelX detection engine...");

  engineProcess = spawn(
    "python",
    [WORKER_PATH],
    {
      cwd: ENGINE_ROOT,
      windowsHide: true
    }
  );

  engineRunning = true;

  let buffer = "";

  // ==========================================================
  // STDOUT
  // ==========================================================

  engineProcess.stdout.on(
    "data",
    (data) => {

      buffer += data.toString();

      const lines = buffer.split(/\r?\n/);

      buffer = lines.pop();

      for (const line of lines) {

        if (!line.trim()) {
          continue;
        }

        try {

          const event = JSON.parse(line);

          handleEngineEvent(event);

        } catch (error) {

          console.error(
            "⚠️ Invalid engine JSON:",
            line
          );

        }

      }

    }
  );

  // ==========================================================
  // STDERR
  // ==========================================================

  engineProcess.stderr.on(
    "data",
    (data) => {

      console.error(
        "🐍 Detection Engine:",
        data.toString().trim()
      );

    }
  );

  // ==========================================================
  // PROCESS EXIT
  // ==========================================================

  engineProcess.on(
    "close",
    (code) => {

      console.log(
        `🛡️ Detection Engine stopped (code ${code})`
      );

      engineProcess = null;
      engineRunning = false;

    }
  );

  console.log(
    "🛡️ Detection Engine: STARTED"
  );
}


// ============================================================
// HANDLE ENGINE EVENT
// ============================================================

function handleEngineEvent(event) {

  if (!event) {
    return;
  }

  // ----------------------------------------------------------
  // ENGINE STATUS
  // ----------------------------------------------------------

  if (event.type === "ENGINE_STATUS") {

    console.log(
      `🛡️ Engine status: ${event.status}`
    );

    ioInstance?.emit(
      "engine_status",
      event
    );

    return;
  }

  // ----------------------------------------------------------
  // ENGINE INFO
  // ----------------------------------------------------------

  if (event.type === "ENGINE_INFO") {

    ioInstance?.emit(
      "engine_info",
      event
    );

    return;
  }

  // ----------------------------------------------------------
  // SCAN COMPLETE
  // ----------------------------------------------------------

  if (event.type === "SCAN_COMPLETE") {

    console.log(
      `📡 Network scan: ${event.packet_count} packets, ${event.alert_count} alerts`
    );

    ioInstance?.emit(
      "network_scan",
      event
    );

    // Forward individual alerts
    if (
      Array.isArray(event.alerts)
    ) {

      for (const alert of event.alerts) {

        handleSecurityAlert(
          alert
        );

      }

    }

    return;
  }

  // ----------------------------------------------------------
  // SECURITY ALERT
  // ----------------------------------------------------------

  if (event.type === "SECURITY_ALERT") {

    handleSecurityAlert(
      event.alert
    );

    return;
  }

  // ----------------------------------------------------------
  // ENGINE ERROR
  // ----------------------------------------------------------

  if (event.type === "ENGINE_ERROR") {

    console.error(
      "🚨 Detection Engine Error:",
      event.error
    );

    ioInstance?.emit(
      "engine_error",
      event
    );

  }

}


// ============================================================
// SECURITY ALERT
// ============================================================

function handleSecurityAlert(alert) {

  if (!alert) {
    return;
  }

  console.log(
    `🚨 SECURITY ALERT: ${alert.type} | ${alert.severity} | ${alert.source_ip}`
  );

  ioInstance?.emit(
    "security_alert",
    alert
  );

}


// ============================================================
// STOP ENGINE
// ============================================================

export function stopDetectionEngine() {

  if (!engineProcess) {
    return;
  }

  console.log(
    "🛑 Stopping detection engine..."
  );

  engineProcess.kill();

  engineProcess = null;

  engineRunning = false;
}


// ============================================================
// ENGINE STATUS
// ============================================================

export function getDetectionEngineStatus() {

  return {
    running: engineRunning,
    pid: engineProcess?.pid || null
  };

}