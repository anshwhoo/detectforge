import React from 'react';

export default function Navbar({ activeTab, setActiveTab, onRefresh, lastUpdated, isRefreshing }) {
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'rules', label: 'Rules' },
    { id: 'coverage', label: 'ATT&CK Coverage' },
    { id: 'pipeline', label: 'Pipeline Activity' },
    { id: 'monitoring', label: 'Monitoring' }
  ];

  return (
    <header className="sticky top-0 z-50 bg-slate-900/90 backdrop-blur-md border-b border-slate-800 px-4 md:px-8 py-3 flex flex-col md:flex-row items-center justify-between gap-4">
      <div className="flex items-center gap-3 w-full md:w-auto justify-between">
        <div className="flex items-center gap-3 cursor-pointer" onClick={() => setActiveTab('overview')}>
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-blue-600 flex items-center justify-center text-white font-black text-xl shadow-lg shadow-emerald-500/20">
            DF
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-slate-100 flex items-center gap-2">
              DetectForge
              <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono font-normal flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                v1.0.0
              </span>
            </h1>
            <p className="text-xs text-slate-400">Detection-as-Code CI/CD Pipeline</p>
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <nav className="flex items-center gap-1 bg-slate-950/60 p-1 rounded-xl border border-slate-800/80 overflow-x-auto max-w-full">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 rounded-lg text-xs md:text-sm font-medium transition-all whitespace-nowrap focus:outline-none focus:ring-2 focus:ring-emerald-500/40 cursor-pointer ${
              activeTab === tab.id
                ? 'bg-slate-800 text-emerald-400 shadow-sm border border-emerald-500/30 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* Live Polling Indicator, Refresh & Timestamp */}
      <div className="flex items-center gap-3 text-xs text-slate-400">
        <div className="hidden sm:flex items-center gap-1.5 bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800 font-mono text-[11px]">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span>Live Polling (30s)</span>
        </div>

        {lastUpdated && (
          <span className="hidden md:inline font-mono">
            Updated: {lastUpdated}
          </span>
        )}

        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-all font-medium disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-emerald-500/40 cursor-pointer"
          title="Re-fetch JSON data files immediately"
        >
          <svg
            className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-emerald-400' : ''}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          {isRefreshing ? 'Refreshing...' : 'Refresh Data'}
        </button>
      </div>
    </header>
  );
}
