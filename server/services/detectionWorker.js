import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

import {
  broadcastAlert,
  broadcastEngineStatus,
} from "./alertService.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const workerPath = path.resolve(
  __dirname,
  "../../detection-engine/worker.py"
);

let worker = null;

export function startDetectionWorker() {
  if (worker) {
    console.log("⚠️ Detection worker is already running");
    return;
  }

  console.log("🛡️ Starting SentinelX detection engine...");

  worker = spawn(
    "python",
    [workerPath],
    {
      cwd: path.dirname(workerPath),
      stdio: ["ignore", "pipe", "pipe"],
    }
  );

  worker.stdout.on("data", (data) => {
    const lines = data
      .toString()
      .split(/\r?\n/)
      .filter(Boolean);

    for (const line of lines) {
      try {
        const event = JSON.parse(line);

        if (event.type === "ENGINE_STATUS") {
          console.log(
            `🛡️ Detection Engine: ${event.status}`
          );

          broadcastEngineStatus(event.status);
        }

        if (event.type === "SCAN_COMPLETE") {
          console.log(
            `📡 Network scan (${event.capture_interface}): ${event.packet_count} packets, ${event.alert_count} alerts`
          );

          broadcastEngineStatus("STARTED", {
            captureInterface: event.capture_interface,
            packetCount: event.packet_count,
            alertCount: event.alert_count,
            scannedAt: event.timestamp,
            detectors: event.detectors,
          });
        }

        if (event.type === "SECURITY_ALERT") {
          console.log("🚨 SECURITY ALERT");

          broadcastAlert(event.alert);
        }

        if (event.type === "ENGINE_ERROR") {
          console.error(
            "❌ Detection Engine Error:",
            event.error || event.message || "Unknown detection engine error",
            event.component ? `(${event.component})` : ""
          );
        }
      } catch (error) {
        console.error(
          "❌ Invalid detection engine output:",
          line
        );
      }
    }
  });

  worker.stderr.on("data", (data) => {
    const message = data.toString().trim();

    if (message) {
      console.error(
        "Detection Engine stderr:",
        message
      );
    }
  });

  worker.on("error", (error) => {
    console.error(
      "❌ Failed to start detection engine:",
      error
    );

    broadcastEngineStatus("STOPPED");

    worker = null;
  });

  worker.on("exit", (code) => {
    console.log(
      `🛑 Detection engine stopped with code ${code}`
    );

    broadcastEngineStatus("STOPPED");

    worker = null;
  });
}

export function stopDetectionWorker() {
  if (!worker) {
    return;
  }

  console.log("🛑 Stopping detection engine...");

  worker.kill();

  worker = null;

  broadcastEngineStatus("STOPPED");
}
