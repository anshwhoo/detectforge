import React from 'react';

export default function MonitoringTab() {
  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-12 text-center backdrop-blur-sm space-y-4">
        <div className="w-16 h-16 rounded-2xl bg-amber-500/10 border border-amber-500/20 text-amber-400 flex items-center justify-center text-2xl mx-auto">
          ⚡
        </div>
        
        <div className="max-w-md mx-auto">
          <span className="px-3 py-1 rounded-full text-xs font-bold font-mono bg-amber-500/10 text-amber-400 border border-amber-500/20 uppercase tracking-wider">
            Coming Soon — Stretch Goal
          </span>
          <h2 className="text-xl font-bold text-slate-100 mt-3">Live SIEM Rule Health Monitoring</h2>
          <p className="text-xs text-slate-400 mt-2 leading-relaxed">
            Real-time telemetry fires-per-day charts and false-positive rate tracking. 
            This static dashboard will connect to a secure proxy endpoint exposing live Wazuh Indexer analytics safely.
          </p>
        </div>

        <div className="pt-4 max-w-lg mx-auto grid grid-cols-2 gap-3 text-left">
          <div className="p-4 bg-slate-950/60 border border-slate-800/80 rounded-xl">
            <div className="text-xs font-bold text-slate-300">Rule Fires Per Day</div>
            <div className="text-[11px] text-slate-500 mt-1">Sourced from OpenSearch wazuh-alerts-* queries.</div>
          </div>
          <div className="p-4 bg-slate-950/60 border border-slate-800/80 rounded-xl">
            <div className="text-xs font-bold text-slate-300">FP Rate Tracking</div>
            <div className="text-[11px] text-slate-500 mt-1">Analyst feedback loop informing rule tweaks.</div>
          </div>
        </div>
      </div>
    </div>
  );
}
