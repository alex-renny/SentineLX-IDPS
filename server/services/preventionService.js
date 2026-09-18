import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ENGINE_ROOT = path.resolve(
  __dirname,
  "../../detection-engine"
);

export function getPreventionMode() {
  const mode = (
    process.env.SENTINELX_PREVENTION_MODE || "test"
  ).toLowerCase();

  return mode === "active" ? "active" : "test";
}

export function isAutoBlockEnabled() {
  return (
    String(process.env.SENTINELX_PREVENTION_AUTO_BLOCK || "false")
      .toLowerCase() === "true"
  );
}

export function getPreventionConfig() {
  const mode = getPreventionMode();
  const autoBlock = isAutoBlockEnabled();
  const liveBlocking = mode === "active";

  return {
    mode,
    auto_block: autoBlock,
    live_blocking: liveBlocking,
    rule_prefix: "SentinelX-IDPS-BLOCK",
    warning: liveBlocking
      ? autoBlock
        ? "Active mode with auto-block: detection can create real Windows Firewall rules immediately."
        : "Active mode: Block IP in the dashboard creates a real Windows Firewall rule. Detection only queues BLOCK_PENDING."
      : "Test mode simulates blocks only. Set SENTINELX_PREVENTION_MODE=active to create real firewall rules.",
  };
}

function runPreventionCli(action, ip, reason) {
  return new Promise((resolve, reject) => {
    const args = ["-m", "prevention.cli", action];

    if (ip) {
      args.push(ip);
    }

    if (reason) {
      args.push(reason);
    }

    const child = spawn("python", args, {
      cwd: ENGINE_ROOT,
      windowsHide: true,
      env: process.env,
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (error) => {
      reject(error);
    });

    child.on("close", () => {
      const line = stdout
        .split(/\r?\n/)
        .map((item) => item.trim())
        .filter(Boolean)
        .at(-1);

      if (!line) {
        reject(
          new Error(
            stderr.trim() || "Prevention engine returned no result"
          )
        );
        return;
      }

      try {
        resolve(JSON.parse(line));
      } catch (error) {
        reject(
          new Error(
            `Invalid prevention output: ${line}`
          )
        );
      }
    });
  });
}

export async function blockIp(ip, reason = "Manual operator block") {
  return runPreventionCli("block", ip, reason);
}

export async function unblockIp(ip) {
  return runPreventionCli("unblock", ip);
}

export async function listFirewallRules() {
  return runPreventionCli("list");
}
