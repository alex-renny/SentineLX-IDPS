import { useEffect, useState } from "react";
import {
  ShieldAlert,
  Ban,
  Activity,
  Wifi,
  Cpu,
  MemoryStick,
  Server,
  LockKeyhole,
  HardDrive,
} from "lucide-react";

import Layout from "../components/layout/Layout";
import StatCard from "../components/cards/StatCard";
import api from "../services/api";
import socket from "../services/socket";

export default function Dashboard() {
  const [system, setSystem] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [alerts, setAlerts] = useState([]);
  const [engineStatus, setEngineStatus] = useState("Connecting");
  const [captureStatus, setCaptureStatus] = useState(null);
  const [detectorStatus, setDetectorStatus] = useState(null);
  const engineOnline = engineStatus === "Online" && !error;

  const fetchSystemStats = async () => {
    try {
      const response = await api.get("/system/stats");

      if (response.data.success) {
        setSystem(response.data.data);
        setError("");
      }
    } catch (err) {
      console.error("System stats error:", err);
      setError("Unable to connect to detection engine");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSystemStats();

    const interval = setInterval(fetchSystemStats, 3000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
  // ----------------------------------------------------------
  // Load existing alerts from MongoDB
  // ----------------------------------------------------------

  const fetchAlerts = async () => {
    try {
      const response = await api.get("/alerts?limit=20");

      if (response.data.success) {
        setAlerts(response.data.alerts || []);
      }
    } catch (err) {
      console.error("Alert fetch error:", err);
    }
  };

  fetchAlerts();

  // ----------------------------------------------------------
  // ENGINE STATUS
  // ----------------------------------------------------------

  const handleEngineStatus = (data) => {
    console.log("🛡️ Engine status:", data);

    if (data.status === "STARTED") {
      setEngineStatus("Online");
    }

    if (data.status === "STOPPED") {
      setEngineStatus("Offline");
    }

    if (data.captureInterface) {
      setCaptureStatus({
        interface: data.captureInterface,
        packetCount: data.packetCount ?? 0,
        alertCount: data.alertCount ?? 0,
        scannedAt: data.scannedAt || data.timestamp,
      });
    }

    if (data.detectors) {
      setDetectorStatus(data.detectors);
    }
  };

  // ----------------------------------------------------------
  // LIVE SECURITY ALERT
  // ----------------------------------------------------------

  const handleSecurityAlert = (data) => {
    console.log("🚨 LIVE SECURITY ALERT:", data);

    const alert = data.alert || data;

    setAlerts((previous) => {
      const alertId = alert._id || alert.id;

      // Prevent duplicate MongoDB/socket alert
      if (
        alertId &&
        previous.some(
          (item) =>
            (item._id || item.id) === alertId
        )
      ) {
        return previous;
      }

      return [
        alert,
        ...previous,
      ].slice(0, 20);
    });
  };

  // ----------------------------------------------------------
  // SOCKET.IO LISTENERS
  // ----------------------------------------------------------

  socket.on(
    "ENGINE_STATUS",
    handleEngineStatus
  );

  socket.on(
    "security-alert",
    handleSecurityAlert
  );

  // ----------------------------------------------------------
  // CLEANUP
  // ----------------------------------------------------------

  return () => {
    socket.off(
      "ENGINE_STATUS",
      handleEngineStatus
    );

    socket.off(
      "security-alert",
      handleSecurityAlert
    );
  };
}, []);

  const cpu = system?.system?.cpu?.usage ?? 0;
  const memory = system?.system?.memory?.usage ?? 0;
  const disk = system?.system?.disk?.usage ?? 0;
  const processes = system?.processes?.length ?? 0;

  return (
    <Layout>
      {/* Header */}
      <section className="mb-6">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
          
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
              Security Operations Center
            </p>

            <h1 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">
              SentinelX Dashboard
            </h1>

            <p className="mt-2 max-w-2xl text-sm text-slate-500">
              Real-time system and security monitoring.
            </p>
          </div>

          {/* Detection Engine Status */}
          <div
            className={`flex items-center gap-2 rounded-xl border px-4 py-2.5 ${
              engineOnline
                ? "border-emerald-500/20 bg-emerald-500/5"
                : engineStatus === "Offline"
                ? "border-red-500/20 bg-red-500/5"
                : "border-yellow-500/20 bg-yellow-500/5"
            }`}
          >
            <span
              className={`h-2.5 w-2.5 rounded-full ${
                engineOnline
                  ? "animate-pulse bg-emerald-400"
                  : engineStatus === "Offline"
                  ? "bg-red-400"
                  : "animate-pulse bg-yellow-400"
              }`}
            />

            <span
              className={`text-xs font-medium ${
                engineOnline
                  ? "text-emerald-400"
                  : engineStatus === "Offline"
                  ? "text-red-400"
                  : "text-yellow-400"
              }`}
            >
              {engineStatus === "Online"
                ? "Detection Engine Online"
                : engineStatus === "Offline"
                ? "Engine Offline"
                : "Connecting..."}
            </span>
          </div>

        </div>
      </section>

      {/* Stats */}
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          title="CPU Usage"
          value={loading ? "--" : `${cpu}%`}
          subtitle={`${system?.system?.cpu?.cores ?? "--"} logical cores`}
          icon={Cpu}
          iconClass="bg-cyan-500/10 text-cyan-400"
        />

        <StatCard
          title="Memory Usage"
          value={loading ? "--" : `${memory}%`}
          subtitle={
            system
              ? `${system.system.memory.used} GB / ${system.system.memory.total} GB`
              : "Loading..."
          }
          icon={MemoryStick}
          iconClass="bg-purple-500/10 text-purple-400"
        />

        <StatCard
          title="Disk Usage"
          value={loading ? "--" : `${disk}%`}
          subtitle={
            system
              ? `${system.system.disk.free} GB free`
              : "Loading..."
          }
          icon={HardDrive}
          iconClass="bg-orange-500/10 text-orange-400"
        />

        <StatCard
          title="Processes"
          value={loading ? "--" : processes}
          subtitle="Processes monitored"
          icon={Server}
          iconClass="bg-emerald-500/10 text-emerald-400"
        />
      </section>

      {/* Monitoring */}
      <section className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* System overview */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 xl:col-span-2">
          <div className="mb-6 flex items-center justify-between">
            <div>
              <h2 className="font-semibold text-white">
                System Monitoring
              </h2>

              <p className="mt-1 text-xs text-slate-500">
                Live telemetry from your machine
              </p>
            </div>

            <div className="flex items-center gap-2 text-xs text-emerald-400">
              <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />
              Live
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <MonitorCard
              title="CPU"
              value={cpu}
              unit="%"
              icon={Cpu}
            />

            <MonitorCard
              title="Memory"
              value={memory}
              unit="%"
              icon={MemoryStick}
            />

            <MonitorCard
              title="Disk"
              value={disk}
              unit="%"
              icon={HardDrive}
            />
          </div>

          <div className="mt-6 rounded-xl border border-slate-800 bg-slate-950/50 p-4">
            <div className="flex flex-col gap-2 text-xs sm:flex-row sm:items-center sm:justify-between">
              <span className="text-slate-500">
                Hostname
              </span>

              <span className="break-all font-mono text-cyan-400">
                {system?.system?.hostname ?? "Loading..."}
              </span>
            </div>

            <div className="mt-3 flex flex-col gap-2 text-xs sm:flex-row sm:items-center sm:justify-between">
              <span className="text-slate-500">
                Operating System
              </span>

              <span className="text-slate-300">
                {system?.system?.platform ?? "Loading..."}
              </span>
            </div>

            <div className="mt-3 flex flex-col gap-2 text-xs sm:flex-row sm:items-center sm:justify-between">
              <span className="text-slate-500">
                Last Update
              </span>

              <span className="text-slate-300">
                {system
                  ? new Date(
                      system.system.timestamp
                    ).toLocaleTimeString()
                  : "Loading..."}
              </span>
            </div>
          </div>
        </div>

        {/* Security */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="font-semibold text-white">
            Security Status
          </h2>

          <p className="mt-1 text-xs text-slate-500">
            Current protection state
          </p>

          <div className="mt-6 space-y-4">
            <SecurityStatus
              icon={ShieldAlert}
              title="Threat Detection"
              status="Active"
            />

            <SecurityStatus
              icon={LockKeyhole}
              title="Brute-force Monitor"
              status={
                detectorStatus
                  ? `${detectorStatus.brute_force.threshold} failures / ${detectorStatus.brute_force.window_seconds}s`
                  : "Waiting for engine"
              }
            />

            <SecurityStatus
              icon={LockKeyhole}
              title="Firewall"
              status="Protected"
            />

            <SecurityStatus
              icon={Wifi}
              title="Network Monitor"
              status={
                captureStatus
                  ? `${captureStatus.packetCount} packets captured`
                  : "Waiting for capture"
              }
            />

            <SecurityStatus
              icon={Activity}
              title="Traffic Flood Monitor"
              status={
                detectorStatus
                  ? `${detectorStatus.ddos.threshold} packets/s`
                  : "Waiting for engine"
              }
            />

            <SecurityStatus
              icon={Ban}
              title="Prevention Engine"
              status="Standby"
            />
          </div>

          {captureStatus && (
            <div className="mt-4 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-3 text-xs">
              <p className="font-medium text-cyan-300">
                Capturing on {captureStatus.interface}
              </p>
              <p className="mt-1 text-slate-400">
                Last scan: {captureStatus.packetCount} packets, {captureStatus.alertCount} alerts
                {captureStatus.scannedAt
                  ? ` · ${new Date(captureStatus.scannedAt).toLocaleTimeString()}`
                  : ""}
              </p>
            </div>
          )}
        </div>
      </section>

      {/* Security Alerts */}

      <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="mb-5 flex items-center justify-between">
          <div>
            <h2 className="font-semibold text-white">
              Live Security Alerts
            </h2>

            <p className="mt-1 text-xs text-slate-500">
              Real-time threats detected by SentinelX
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs text-cyan-400">
            <span className="h-2 w-2 animate-pulse rounded-full bg-cyan-400" />
            Live
          </div>
        </div>

        {alerts.length === 0 ? (
          <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-6 text-center">
            <ShieldAlert
              size={28}
              className="mx-auto text-slate-700"
            />

            <p className="mt-3 text-sm text-slate-500">
              No security alerts detected
            </p>

            <p className="mt-1 text-xs text-slate-600">
              SentinelX is monitoring your system
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {alerts.map((alert) => (
              <div
                key={alert._id || alert.id}
                className="rounded-xl border border-red-500/20 bg-red-500/5 p-4"
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">

                  <div className="flex items-start gap-3">
                    <div className="rounded-lg bg-red-500/10 p-2 text-red-400">
                      <ShieldAlert size={18} />
                    </div>

                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-semibold text-red-400">
                          {alert.type}
                        </span>

                        <span className="rounded-md bg-red-500/10 px-2 py-1 text-[10px] font-bold text-red-400">
                          {alert.severity}
                        </span>
                      </div>

                      <p className="mt-1 text-sm text-slate-400">
                        {alert.message}
                      </p>
                    </div>
                  </div>

                  <div className="text-left sm:text-right">
                    <p className="font-mono text-xs text-cyan-400">
                      {alert.source_ip || "Unknown IP"}
                    </p>

                    <p className="mt-1 text-[10px] text-slate-600">
                      {alert.received_at
                        ? new Date(
                            alert.received_at
                          ).toLocaleTimeString()
                        : ""}
                    </p>
                  </div>

                </div>

                {(alert.ports_detected || alert.window_seconds) && (
                  <div className="mt-3 flex flex-wrap gap-2">

                    {alert.ports_detected && (
                      <span className="rounded-lg border border-orange-500/10 bg-orange-500/5 px-3 py-1.5 text-[11px] text-orange-400">
                        🔌 {alert.ports_detected} ports detected
                      </span>
                    )}

                    {alert.window_seconds && (
                      <span className="rounded-lg border border-purple-500/10 bg-purple-500/5 px-3 py-1.5 text-[11px] text-purple-400">
                        ⏱️ {alert.window_seconds}s detection window
                      </span>
                    )}

                    {alert.attempts > 0 && (
                      <span className="rounded-lg border border-yellow-500/10 bg-yellow-500/5 px-3 py-1.5 text-[11px] text-yellow-300">
                        🔐 {alert.attempts} failed {alert.service || "login"} attempts
                      </span>
                    )}

                    {alert.packets_per_second > 0 && (
                      <span className="rounded-lg border border-red-500/10 bg-red-500/5 px-3 py-1.5 text-[11px] text-red-300">
                        🌊 {alert.packets_per_second} packets/s (limit {alert.threshold})
                      </span>
                    )}

                    {alert.target && (
                      <span className="rounded-lg border border-cyan-500/10 bg-cyan-500/5 px-3 py-1.5 text-[11px] text-cyan-300">
                        Target: {alert.target}
                      </span>
                    )}

                  </div>
                )}

                {alert.prevention && (
                  <div className="mt-3 rounded-xl border border-emerald-500/10 bg-emerald-500/5 p-3">
                    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs">

                      <span className="font-semibold text-emerald-400">
                        🛡️ Prevention
                      </span>

                      <span className="text-slate-400">
                        Action:
                        <span className="ml-1 font-semibold text-emerald-300">
                          {alert.prevention.action || "PROCESSED"}
                        </span>
                      </span>

                      {alert.prevention.mode && (
                        <span className="text-slate-400">
                          Mode:
                          <span className="ml-1 font-semibold text-cyan-400">
                            {alert.prevention.mode}
                          </span>
                        </span>
                      )}

                      {alert.prevention.ip && (
                        <span className="font-mono text-slate-400">
                          IP:
                          <span className="ml-1 text-cyan-400">
                            {alert.prevention.ip}
                          </span>
                        </span>
                      )}

                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Processes */}
      <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="mb-5 flex items-center justify-between">
          <div>
            <h2 className="font-semibold text-white">
              Top Processes
            </h2>

            <p className="mt-1 text-xs text-slate-500">
              Processes currently monitored by SentinelX
            </p>
          </div>

          <Activity
            size={19}
            className="text-cyan-400"
          />
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[600px] text-left">
            <thead>
              <tr className="border-b border-slate-800 text-xs uppercase tracking-wider text-slate-600">
                <th className="pb-3">PID</th>
                <th className="pb-3">Process</th>
                <th className="pb-3">User</th>
                <th className="pb-3">CPU</th>
                <th className="pb-3">Memory</th>
              </tr>
            </thead>

            <tbody>
              {system?.processes?.map((process) => (
                <tr
                  key={process.pid}
                  className="border-b border-slate-900 text-sm"
                >
                  <td className="py-3 font-mono text-slate-500">
                    {process.pid}
                  </td>

                  <td className="py-3 font-medium text-slate-300">
                    {process.name}
                  </td>

                  <td className="max-w-[200px] truncate py-3 text-slate-500">
                    {process.username}
                  </td>

                  <td className="py-3 text-cyan-400">
                    {process.cpu}%
                  </td>

                  <td className="py-3 text-purple-400">
                    {process.memory}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </Layout>
  );
}

function MonitorCard({
  title,
  value,
  unit,
  icon: Icon,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-500">
          {title}
        </span>

        <Icon size={17} className="text-slate-600" />
      </div>

      <div className="mt-4">
        <span className="text-3xl font-bold text-white">
          {value}
        </span>

        <span className="ml-1 text-sm text-slate-500">
          {unit}
        </span>
      </div>

      <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-slate-800">
        <div
          className="h-full rounded-full bg-cyan-400 transition-all duration-700"
          style={{
            width: `${Math.min(value, 100)}%`,
          }}
        />
      </div>
    </div>
  );
}

function SecurityStatus({
  icon: Icon,
  title,
  status,
}) {
  return (
    <div className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950/50 p-4">
      <div className="flex items-center gap-3">
        <div className="rounded-lg bg-cyan-500/10 p-2 text-cyan-400">
          <Icon size={17} />
        </div>

        <span className="text-sm text-slate-300">
          {title}
        </span>
      </div>

      <span className="text-xs font-medium text-emerald-400">
        {status}
      </span>
    </div>
  );
}
