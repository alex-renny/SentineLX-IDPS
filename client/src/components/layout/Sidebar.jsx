import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Network,
  ShieldAlert,
  FileText,
  Settings,
  Shield,
  X,
} from "lucide-react";

const navigation = [
  {
    name: "Dashboard",
    path: "/",
    icon: LayoutDashboard,
  },
  {
    name: "Network Monitor",
    path: "/network",
    icon: Network,
  },
  {
    name: "Threats",
    path: "/threats",
    icon: ShieldAlert,
  },
  {
    name: "Reports",
    path: "/reports",
    icon: FileText,
  },
  {
    name: "Settings",
    path: "/settings",
    icon: Settings,
  },
];

export default function Sidebar({ mobileOpen, setMobileOpen }) {
  return (
    <>
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={`
          fixed left-0 top-0 z-50 flex h-screen w-72 flex-col
          border-r border-slate-800 bg-slate-950
          transition-transform duration-300
          lg:translate-x-0
          ${mobileOpen ? "translate-x-0" : "-translate-x-full"}
        `}
      >
        {/* Logo */}
        <div className="flex h-20 items-center justify-between border-b border-slate-800 px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-400">
              <Shield size={24} />
            </div>

            <div>
              <h1 className="font-bold tracking-wide text-white">
                SentinelX
              </h1>

              <p className="text-[10px] uppercase tracking-widest text-slate-500">
                IDPS Platform
              </p>
            </div>
          </div>

          <button
            onClick={() => setMobileOpen(false)}
            className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white lg:hidden"
          >
            <X size={20} />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-2 overflow-y-auto p-4">
          <p className="mb-3 px-3 text-[11px] font-semibold uppercase tracking-widest text-slate-500">
            Security Operations
          </p>

          {navigation.map((item) => {
            const Icon = item.icon;

            return (
              <NavLink
                key={item.path}
                to={item.path}
                onClick={() => setMobileOpen(false)}
                className={({ isActive }) =>
                  `
                  flex items-center gap-3 rounded-xl px-4 py-3
                  text-sm font-medium transition-all
                  ${
                    isActive
                      ? "bg-cyan-500/10 text-cyan-400 shadow-lg shadow-cyan-500/5"
                      : "text-slate-400 hover:bg-slate-900 hover:text-white"
                  }
                  `
                }
              >
                <Icon size={19} />
                <span>{item.name}</span>
              </NavLink>
            );
          })}
        </nav>

        {/* System status */}
        <div className="border-t border-slate-800 p-4">
          <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-emerald-400" />

              <span className="text-sm font-medium text-emerald-400">
                System Protected
              </span>
            </div>

            <p className="mt-2 text-xs text-slate-500">
              Detection engine is operational.
            </p>
          </div>
        </div>
      </aside>
    </>
  );
}