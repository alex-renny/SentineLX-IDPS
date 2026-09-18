import {
  Bar,
  BarChart,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const COLORS = ["#22d3ee", "#a78bfa", "#f59e0b", "#34d399", "#fb7185"];

function formatBytes(value = 0) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function groupedData(packets, field, label, max = 5) {
  const values = packets.reduce((result, packet) => {
    const key = packet[field] ?? "Unknown";
    result[key] = (result[key] || 0) + 1;
    return result;
  }, {});

  return Object.entries(values)
    .map(([name, value]) => ({ [label]: name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, max);
}

export default function TrafficOverview({ traffic, history = [], compact = false }) {
  const packets = traffic?.packets || [];
  const topSources = groupedData(packets, "source_ip", "source");
  const topPorts = groupedData(packets, "destination_port", "port");
  const protocols = groupedData(packets, "protocol", "protocol");
  const totalBytes = packets.reduce((sum, packet) => sum + (Number(packet.packet_size) || 0), 0);
  const packetsPerSecond = traffic?.duration
    ? Math.round((traffic.packet_count || packets.length) / traffic.duration)
    : 0;
  const chartHistory = history.length
    ? history
    : [{ time: "Now", packets: packetsPerSecond, bytes: totalBytes }];

  return (
    <section className="mt-6 space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <TrafficMetric label="Packets / sec" value={packetsPerSecond} detail={`${traffic?.packet_count || 0} in latest scan`} />
        <TrafficMetric label="Traffic volume" value={formatBytes(totalBytes)} detail={`${packets.length} packet samples`} />
        <TrafficMetric label="Capture interface" value={traffic?.capture_interface || "Waiting"} detail={traffic?.timestamp ? `Updated ${new Date(traffic.timestamp).toLocaleTimeString()}` : "Awaiting engine scan"} />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <ChartCard title="Packets per second">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={chartHistory}>
              <XAxis dataKey="time" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} width={32} />
              <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 10 }} />
              <Line type="monotone" dataKey="packets" stroke="#22d3ee" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Traffic volume">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={chartHistory}>
              <XAxis dataKey="time" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} width={45} />
              <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 10 }} formatter={(value) => formatBytes(value)} />
              <Bar dataKey="bytes" fill="#a78bfa" radius={[5, 5, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Top source IPs">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart layout="vertical" data={topSources} margin={{ left: 24 }}>
              <XAxis type="number" hide />
              <YAxis dataKey="source" type="category" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} width={100} />
              <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 10 }} />
              <Bar dataKey="value" fill="#22d3ee" radius={[0, 5, 5, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Top destination ports">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={topPorts}>
              <XAxis dataKey="port" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} width={32} />
              <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 10 }} />
              <Bar dataKey="value" fill="#f59e0b" radius={[5, 5, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Protocols">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={protocols} dataKey="value" nameKey="protocol" cx="50%" cy="50%" outerRadius={75} label={({ protocol, percent }) => `${protocol} ${(percent * 100).toFixed(0)}%`}>
                {protocols.map((entry, index) => <Cell key={entry.protocol} fill={COLORS[index % COLORS.length]} />)}
              </Pie>
              <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 10 }} />
            </PieChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {!compact && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="mb-5 flex items-center justify-between">
            <div><h2 className="font-semibold text-white">Live network traffic</h2><p className="mt-1 text-xs text-slate-500">Latest packets captured by the detection engine</p></div>
            <span className="text-xs text-cyan-400">{topPorts.length ? `Top port: ${topPorts[0].port}` : "Waiting for traffic"}</span>
          </div>
          <div className="overflow-x-auto"><table className="w-full min-w-[720px] text-left text-sm"><thead><tr className="border-b border-slate-800 text-xs uppercase tracking-wider text-slate-600"><th className="pb-3">Source</th><th className="pb-3">Destination</th><th className="pb-3">Protocol</th><th className="pb-3">Port</th><th className="pb-3">Size</th><th className="pb-3">Time</th></tr></thead><tbody>{packets.length === 0 ? <tr><td colSpan="6" className="py-8 text-center text-slate-500">Waiting for the first network capture…</td></tr> : packets.slice().reverse().map((packet, index) => <tr key={`${packet.timestamp}-${index}`} className="border-b border-slate-900"><td className="py-3 font-mono text-cyan-400">{packet.source_ip}</td><td className="py-3 font-mono text-slate-300">{packet.destination_ip}</td><td className="py-3 text-slate-300">{packet.protocol}</td><td className="py-3 text-slate-400">{packet.destination_port ?? "—"}</td><td className="py-3 text-slate-400">{formatBytes(packet.packet_size)}</td><td className="py-3 text-slate-500">{packet.timestamp ? new Date(packet.timestamp).toLocaleTimeString() : "—"}</td></tr>)}</tbody></table></div>
        </div>
      )}
    </section>
  );
}

function TrafficMetric({ label, value, detail }) { return <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4"><p className="text-xs uppercase tracking-wider text-slate-500">{label}</p><p className="mt-2 truncate text-2xl font-bold text-white">{value}</p><p className="mt-1 truncate text-xs text-slate-500">{detail}</p></div>; }
function ChartCard({ title, children }) { return <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5"><h2 className="mb-4 font-semibold text-white">{title}</h2>{children}</div>; }
