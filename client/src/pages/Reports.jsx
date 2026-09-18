import { useEffect, useState } from "react";
import { BarChart3, Download, FileText, FileSpreadsheet, ShieldCheck, Users } from "lucide-react";
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Layout from "../components/layout/Layout";
import api from "../services/api";

const RANGES = [["1h", "Last 1 hour"], ["24h", "Last 24 hours"], ["7d", "Last 7 days"], ["30d", "Last 30 days"], ["custom", "Custom range"]];
const COLORS = { CRITICAL: "#f43f5e", HIGH: "#fb923c", MEDIUM: "#facc15", LOW: "#38bdf8" };
const INITIAL_NOW = new Date();
const dateTimeLocal = (value) => new Date(new Date(value) - new Date(value).getTimezoneOffset() * 60000).toISOString().slice(0, 16);

export default function Reports() {
  const [range, setRange] = useState("24h");
  const [start, setStart] = useState(dateTimeLocal(INITIAL_NOW.getTime() - 86400000));
  const [end, setEnd] = useState(dateTimeLocal(INITIAL_NOW));
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [exporting, setExporting] = useState("");
  const params = () => ({ range, ...(range === "custom" ? { start: new Date(start).toISOString(), end: new Date(end).toISOString() } : {}) });
  const fetchReport = async () => {
    setLoading(true);
    try { const response = await api.get("/reports", { params: params() }); setReport(response.data.report); setError(""); }
    catch (requestError) { setError(requestError.response?.data?.message || "Unable to load the security report."); }
    finally { setLoading(false); }
  };
  useEffect(() => {
    const initialFetch = window.setTimeout(fetchReport, 0);
    return () => window.clearTimeout(initialFetch);
  }, [range]); // eslint-disable-line react-hooks/exhaustive-deps
  const exportReport = async (format) => {
    setExporting(format);
    try {
      const response = await api.get(`/reports/export/${format}`, { params: params(), responseType: "blob" });
      const name = response.headers["content-disposition"]?.match(/filename="?([^";]+)"?/)?.[1] || `sentinelx-report.${format}`;
      const url = URL.createObjectURL(new Blob([response.data])); const link = document.createElement("a"); link.href = url; link.download = name; link.click(); URL.revokeObjectURL(url);
    } catch { setError(`Unable to export ${format.toUpperCase()}.`); } finally { setExporting(""); }
  };
  const severityRows = report?.summary?.severities || [];
  const maximumSeverity = Math.max(...severityRows.map((item) => item.count), 1);
  const periodText = report ? `${new Date(report.period.start).toLocaleString()} - ${new Date(report.period.end).toLocaleString()}` : "Loading period...";
  return <Layout>
    <section className="mb-6 flex flex-col justify-between gap-4 xl:flex-row xl:items-end"><div><p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">Security intelligence</p><h1 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">Reports</h1><p className="mt-2 text-sm text-slate-500">Analyze detected threats, recurring sources, and prevention activity.</p></div><div className="flex flex-wrap gap-2"><ExportButton icon={FileText} label="Export PDF" busy={exporting === "pdf"} onClick={() => exportReport("pdf")} /><ExportButton icon={FileSpreadsheet} label="Export CSV" busy={exporting === "csv"} onClick={() => exportReport("csv")} /></div></section>
    <section className="mb-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-4"><div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between"><label className="block text-xs font-semibold uppercase tracking-wider text-slate-500">Time range<select value={range} onChange={(event) => setRange(event.target.value)} className="mt-2 block w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-cyan-500 sm:w-56">{RANGES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>{range === "custom" && <div className="flex flex-col gap-3 sm:flex-row sm:items-end"><label className="text-xs text-slate-500">Start<input type="datetime-local" value={start} onChange={(event) => setStart(event.target.value)} className="mt-2 block rounded-xl border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-white" /></label><label className="text-xs text-slate-500">End<input type="datetime-local" value={end} onChange={(event) => setEnd(event.target.value)} className="mt-2 block rounded-xl border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-white" /></label><button onClick={fetchReport} className="rounded-xl bg-cyan-500 px-4 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-400">Apply range</button></div>}<p className="text-xs text-slate-500">{periodText}</p></div></section>
    {error && <div className="mb-6 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-300">{error}</div>}
    <section className="grid grid-cols-2 gap-4 lg:grid-cols-4"><Stat title="Total alerts" value={report?.summary?.totalAlerts ?? 0} color="text-cyan-400" /><Stat title="Critical" value={severityRows.find((item) => item.severity === "CRITICAL")?.count ?? 0} color="text-rose-400" /><Stat title="High" value={severityRows.find((item) => item.severity === "HIGH")?.count ?? 0} color="text-orange-400" /><Stat title="Blocked" value={report?.summary?.blocked ?? 0} color="text-emerald-400" /></section>
    <section className="mt-6 grid gap-6 xl:grid-cols-2"><Panel title="Threat types" icon={ShieldCheck} subtitle="Detected attacks by classification">{loading ? <Loading /> : report?.threats?.length ? <ResponsiveContainer width="100%" height={260}><BarChart data={report.threats} layout="vertical" margin={{ left: 16, right: 24 }}><XAxis type="number" hide /><YAxis type="category" dataKey="label" width={105} tick={{ fill: "#94a3b8", fontSize: 11 }} /><Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12 }} cursor={{ fill: "#1e293b" }} /><Bar dataKey="count" fill="#22d3ee" radius={[0, 5, 5, 0]} /></BarChart></ResponsiveContainer> : <Empty text="No threat detections in this period." />}</Panel><Panel title="Severity distribution" icon={BarChart3} subtitle="Alert count by severity">{loading ? <Loading /> : <div className="grid gap-4 md:grid-cols-[180px_1fr] md:items-center"><ResponsiveContainer width="100%" height={180}><PieChart><Pie data={severityRows.filter((item) => item.count)} dataKey="count" nameKey="severity" innerRadius={48} outerRadius={74} paddingAngle={3}>{severityRows.filter((item) => item.count).map((item) => <Cell key={item.severity} fill={COLORS[item.severity]} />)}</Pie><Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12 }} /></PieChart></ResponsiveContainer><div className="space-y-4">{severityRows.map((item) => <div key={item.severity}><div className="mb-1 flex justify-between text-xs"><span className="font-medium text-slate-300">{item.severity}</span><span className="text-slate-500">{item.count}</span></div><div className="h-2 overflow-hidden rounded-full bg-slate-800"><div className="h-full rounded-full" style={{ width: `${(item.count / maximumSeverity) * 100}%`, backgroundColor: COLORS[item.severity] }} /></div></div>)}</div></div>}</Panel></section>
    <section className="mt-6 grid gap-6 xl:grid-cols-2"><Panel title="Top source IPs" icon={Users} subtitle="Sources with the most recorded alerts"><SourceTable rows={report?.topSources || []} loading={loading} /></Panel><Panel title="Blocked sources" icon={ShieldCheck} subtitle="Prevention actions recorded in this report period"><BlockedTable rows={report?.blockedSources || []} loading={loading} /></Panel></section>
  </Layout>;
}
function ExportButton({ icon: Icon, label, busy, onClick }) { return <button disabled={busy} onClick={onClick} className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm font-medium text-slate-200 hover:border-cyan-500/60 hover:text-cyan-300 disabled:opacity-60"><Icon size={17} />{busy ? "Preparing..." : label}<Download size={15} /></button>; }
function Stat({ title, value, color }) { return <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4"><p className="text-xs font-semibold uppercase tracking-wider text-slate-500">{title}</p><p className={`mt-2 text-3xl font-bold ${color}`}>{value}</p></div>; }
function Panel({ title, subtitle, icon: Icon, children }) { return <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5"><div className="mb-5 flex items-start gap-3"><div className="rounded-lg bg-cyan-500/10 p-2 text-cyan-400"><Icon size={18} /></div><div><h2 className="font-semibold text-white">{title}</h2><p className="mt-1 text-xs text-slate-500">{subtitle}</p></div></div>{children}</div>; }
function Loading() { return <div className="flex h-44 items-center justify-center text-sm text-slate-500">Loading report...</div>; }
function Empty({ text }) { return <div className="flex h-44 items-center justify-center rounded-xl border border-dashed border-slate-800 text-sm text-slate-500">{text}</div>; }
function SourceTable({ rows, loading }) { if (loading) return <Loading />; if (!rows.length) return <Empty text="No source IPs in this period." />; return <div className="space-y-3">{rows.map((row, index) => <div key={row.sourceIp} className="flex items-center justify-between rounded-xl bg-slate-950/50 px-4 py-3"><div className="flex items-center gap-3"><span className="w-5 text-xs text-slate-600">{index + 1}</span><span className="font-mono text-sm text-cyan-300">{row.sourceIp}</span></div><span className="text-sm font-semibold text-white">{row.count} <span className="text-xs font-normal text-slate-500">alerts</span></span></div>)}</div>; }
function BlockedTable({ rows, loading }) { if (loading) return <Loading />; if (!rows.length) return <Empty text="No blocked sources in this period." />; return <div className="max-h-72 overflow-auto"><table className="w-full text-left text-sm"><thead className="text-xs uppercase text-slate-500"><tr><th className="pb-3">IP</th><th className="pb-3">Threat</th><th className="pb-3">Action</th></tr></thead><tbody>{rows.map((row, index) => <tr key={`${row.sourceIp}-${index}`} className="border-t border-slate-800"><td className="py-3 font-mono text-cyan-300">{row.sourceIp}</td><td className="py-3 text-slate-300">{row.threat}</td><td className="py-3"><span className="rounded-full bg-emerald-500/10 px-2 py-1 text-xs font-medium text-emerald-400">{row.action}</span></td></tr>)}</tbody></table></div>; }
