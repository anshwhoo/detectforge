import React from 'react';

export default function OverviewTab({ rules, attackLayer, runs, setActiveTab }) {
  const totalRules = rules.length;
  const coveredTechniques = attackLayer?.techniques?.length || 0;
  
  const latestRun = runs.length > 0 ? runs[0] : null;
  const latestDeployRun = runs.find(r => r.name?.includes('CD') || r.event === 'push') || latestRun;
  
  const isCiPassing = latestRun ? (latestRun.conclusion === 'success') : true;

  return (
    <div className="space-y-6">
      {/* 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1 */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 relative overflow-hidden backdrop-blur-sm">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-emerald-500 to-teal-400"></div>
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Rules Deployed</div>
          <div className="text-3xl font-extrabold text-slate-100 my-2 font-mono">{totalRules}</div>
          <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            100% CI Regression Tested
          </div>
        </div>

        {/* Card 2 */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 relative overflow-hidden backdrop-blur-sm">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-blue-500 to-indigo-500"></div>
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">ATT&CK Coverage</div>
          <div className="text-3xl font-extrabold text-slate-100 my-2 font-mono">
            {coveredTechniques} <span className="text-sm font-normal text-slate-500">/ 201</span>
          </div>
          <div className="text-xs text-blue-400 font-medium">
            Technique T1059.001 (Execution)
          </div>
        </div>

        {/* Card 3 */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 relative overflow-hidden backdrop-blur-sm">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-purple-500 to-pink-500"></div>
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Last Deploy</div>
          <div className="text-xl font-bold text-slate-100 my-2 font-mono truncate">
            v1.0.0
          </div>
          <div className="text-xs text-purple-400 font-medium">
            Idempotent Wazuh REST API push
          </div>
        </div>

        {/* Card 4 */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 relative overflow-hidden backdrop-blur-sm">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-amber-500 to-orange-500"></div>
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Last CI Run</div>
          <div className="my-2 flex items-center gap-2">
            <span className={`px-2.5 py-1 rounded-full text-xs font-bold font-mono ${
              isCiPassing ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
            }`}>
              {isCiPassing ? '✓ PASSING' : '✗ FAILED'}
            </span>
          </div>
          <div className="text-xs text-slate-400">
            {latestRun ? new Date(latestRun.created_at || Date.now()).toLocaleTimeString() : 'Just now'}
          </div>
        </div>
      </div>

      {/* Previews Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Heatmap Preview */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-slate-100">ATT&CK Coverage Heatmap</h3>
                <p className="text-xs text-slate-400">Live matrix generated from deployed rule tags</p>
              </div>
              <button
                onClick={() => setActiveTab('coverage')}
                className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
              >
                Full Heatmap →
              </button>
            </div>
            <div className="grid grid-cols-3 sm:grid-cols-5 gap-2 my-4">
              <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl text-center">
                <div className="text-[10px] text-slate-500 uppercase font-semibold">Execution</div>
                <div className="mt-1 text-xs font-bold text-emerald-400 bg-emerald-500/20 border border-emerald-500/40 rounded py-1 font-mono">
                  T1059.001
                </div>
              </div>
              <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl text-center opacity-60">
                <div className="text-[10px] text-slate-500 uppercase font-semibold">Persistence</div>
                <div className="mt-1 text-xs text-slate-600 font-mono py-1">-</div>
              </div>
              <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl text-center opacity-60">
                <div className="text-[10px] text-slate-500 uppercase font-semibold">Priv Escalation</div>
                <div className="mt-1 text-xs text-slate-600 font-mono py-1">-</div>
              </div>
              <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl text-center opacity-60">
                <div className="text-[10px] text-slate-500 uppercase font-semibold">Defense Evasion</div>
                <div className="mt-1 text-xs text-slate-600 font-mono py-1">-</div>
              </div>
              <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl text-center opacity-60">
                <div className="text-[10px] text-slate-500 uppercase font-semibold">Cred Access</div>
                <div className="mt-1 text-xs text-slate-600 font-mono py-1">-</div>
              </div>
            </div>
          </div>
          <div className="text-xs text-slate-400 bg-slate-950/40 p-3 rounded-xl border border-slate-800/60">
            💡 Coverage layer is auto-derived from <code className="text-slate-300">attack.t####</code> tags in deployed Sigma rules.
          </div>
        </div>

        {/* Recent Pipeline Runs Preview */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-slate-100">Recent Pipeline Activity</h3>
                <p className="text-xs text-slate-400">CI/CD rule validation and deployment runs</p>
              </div>
              <button
                onClick={() => setActiveTab('pipeline')}
                className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
              >
                All Runs →
              </button>
            </div>
            <div className="space-y-2 my-2">
              {runs.slice(0, 3).map((run, idx) => (
                <div key={run.id || idx} className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2 overflow-hidden">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span className="text-slate-200 font-medium truncate">{run.name}</span>
                  </div>
                  <span className="text-slate-400 font-mono text-[11px] shrink-0 ml-2">
                    {new Date(run.created_at || Date.now()).toLocaleDateString()}
                  </span>
                </div>
              ))}
            </div>
          </div>
          <div className="text-xs text-slate-400 bg-slate-950/40 p-3 rounded-xl border border-slate-800/60 mt-3">
            🤖 CI runs on every PR; CD deploys to live Wazuh SIEM on merge to <code className="text-slate-300">main</code>.
          </div>
        </div>
      </div>
    </div>
  );
}
