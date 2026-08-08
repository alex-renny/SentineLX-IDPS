import { ArrowUpRight, ArrowDownRight } from "lucide-react";

export default function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  trendType = "up",
  iconClass = "text-cyan-400 bg-cyan-500/10",
}) {
  const positive = trendType === "up";

  return (
    <div className="group rounded-2xl border border-slate-800 bg-slate-900/60 p-5 transition hover:border-slate-700 hover:bg-slate-900">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
            {title}
          </p>

          <p className="mt-2 text-2xl font-bold tracking-tight text-white sm:text-3xl">
            {value}
          </p>
        </div>

        {Icon && (
          <div
            className={`rounded-xl p-3 ${iconClass}`}
          >
            <Icon size={21} />
          </div>
        )}
      </div>

      <div className="mt-4 flex items-center justify-between">
        <span className="text-xs text-slate-500">
          {subtitle}
        </span>

        {trend && (
          <span
            className={`flex items-center gap-1 text-xs font-medium ${
              positive
                ? "text-emerald-400"
                : "text-red-400"
            }`}
          >
            {positive ? (
              <ArrowUpRight size={14} />
            ) : (
              <ArrowDownRight size={14} />
            )}

            {trend}
          </span>
        )}
      </div>
    </div>
  );
}