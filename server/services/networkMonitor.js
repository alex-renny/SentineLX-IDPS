import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const pythonScript = path.resolve(
  __dirname,
  "../../detection-engine/network/monitor.py"
);

export function captureNetworkTraffic() {
  return new Promise((resolve, reject) => {
    const python = spawn("python", [pythonScript]);

    let output = "";
    let errorOutput = "";

    python.stdout.on("data", (data) => {
      output += data.toString();
    });

    python.stderr.on("data", (data) => {
      errorOutput += data.toString();
    });

    python.on("error", (error) => {
      reject(error);
    });

    python.on("close", (code) => {
      if (code !== 0) {
        reject(
          new Error(
            errorOutput || `Python exited with code ${code}`
          )
        );
        return;
      }

      try {
        const result = JSON.parse(output);
        resolve(result);
      } catch (error) {
        reject(
          new Error(
            `Invalid JSON from network monitor: ${error.message}`
          )
        );
      }
    });
  });
}