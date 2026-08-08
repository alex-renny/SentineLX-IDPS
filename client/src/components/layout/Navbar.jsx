import {
  Menu,
  Bell,
  ShieldCheck,
  ChevronDown,
} from "lucide-react";

export default function Navbar({ setMobileOpen }) {
  return (
    <header className="sticky top-0 z-30 flex h-20 items-center justify-between border-b border-slate-800 bg-slate-950/90 px-4 backdrop-blur-xl sm:px-6 lg:px-8">
      {/* Left */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => setMobileOpen(true)}
          className="rounded-xl border border-slate-800 bg-slate-900 p-2.5 text-slate-300 hover:text-white lg:hidden"
        >
          <Menu size={20} />
        </button>

        <div>
          <h2 className="text-lg font-semibold text-white sm:text-xl">
            Security Overview
          </h2>

          <p className="hidden text-xs text-slate-500 sm:block">
            Real-time infrastructure monitoring
          </p>
        </div>
      </div>

      {/* Right */}
      <div className="flex items-center gap-2 sm:gap-4">
        {/* Protection status */}
        <div className="hidden items-center gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-3 py-2 sm:flex">
          <ShieldCheck size={17} className="text-emerald-400" />

          <span className="text-xs font-medium text-emerald-400">
            Protected
          </span>
        </div>

        {/* Notifications */}
        <button className="relative rounded-xl border border-slate-800 bg-slate-900 p-2.5 text-slate-400 transition hover:text-white">
          <Bell size={19} />

          <span className="absolute right-2 top-2 h-2 w-2 rounded-full bg-red-500 ring-2 ring-slate-900" />
        </button>

        {/* User */}
        <button className="hidden items-center gap-2 rounded-xl border border-slate-800 bg-slate-900 px-3 py-2 sm:flex">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyan-500/10 text-xs font-bold text-cyan-400">
            A
          </div>

          <span className="text-sm text-slate-300">
            Analyst
          </span>

          <ChevronDown size={15} className="text-slate-500" />
        </button>
      </div>
    </header>
  );
}