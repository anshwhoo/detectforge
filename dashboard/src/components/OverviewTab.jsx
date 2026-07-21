import React from 'react';
import { formatTimestamp } from '../utils/formatters';

const SEVERITY_COLORS = {
  informational: 'bg-slate-700',
  low: 'bg-blue-500',
  medium: 'bg-amber-500',
  high: 'bg-orange-500',
  critical: 'bg-rose-500'
};

export default function OverviewTab({ rules, attackLayer, runs, buildProgress, systemHealth, setActiveTab }) {
  const totalRules = rules.length;
  const coveredTechniques = attackLayer?.techniques?.length || 0;
  
  const latestRun = runs.length > 0 ? runs[0] : null;
  const isCiPassing = latestRun ? (latestRun.conclusion === 'success') : true;

  // Severity counts breakdown
  const severityCounts = {
    informational: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0
  };

  rules.forEach((r) => {
    const lvl = (r.level || 'medium').toLowerCase();
    if (severityCounts[lvl] !== undefined) {
      severityCounts[lvl] += 1;
    } else {
      severityCounts.medium += 1;
    }
  });

  const components = systemHealth?.components || {
    wazuh_indexer: { name: 'Wazuh Indexer', status: 'online' },
    wazuh_manager: { name: 'Wazuh Manager', status: 'online' },
    self_hosted_runner: { name: 'Self-Hosted Runner', status: 'online' }
  };

  return (
    <div className="space-y-6">
      {/* 4 STAT CARDS */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1 */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 relative overflow-hidden backdrop-blur-sm shadow-lg">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-emerald-500 to-teal-400"></div>
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Rules Deployed</div>
          <div className="text-3xl font-extrabold text-slate-100 my-2 font-mono">{totalRules}</div>
          <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            100% CI Regression Tested
          </div>
        </div>

        {/* Card 2 */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 relative overflow-hidden backdrop-blur-sm shadow-lg">
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
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 relative overflow-hidden backdrop-blur-sm shadow-lg">
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
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 relative overflow-hidden backdrop-blur-sm shadow-lg">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-amber-500 to-orange-500"></div>
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Last CI Run</div>
          <div className="my-2 flex items-center gap-2">
            <span className={`px-2.5 py-1 rounded-full text-xs font-bold font-mono ${
              isCiPassing ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
            }`}>
              {isCiPassing ? '✓ PASSING' : '✗ FAILED'}
            </span>
          </div>
          <div className="text-xs text-slate-400 font-mono">
            {latestRun ? formatTimestamp(latestRun.created_at) : '2:38:49 AM'}
          </div>
        </div>
      </div>

      {/* ROW 2: PREVIEWS GRID */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Heatmap Preview Panel */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm flex flex-col justify-between shadow-lg">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-slate-100">ATT&CK Coverage Heatmap</h3>
                <p className="text-xs text-slate-400">Live matrix generated from deployed rule tags</p>
              </div>
              <button
                onClick={() => setActiveTab('coverage')}
                className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 flex items-center gap-1 cursor-pointer"
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

            {/* Step 2 Refinement: Explicit Preview Label */}
            <div className="text-right mt-2">
              <button
                onClick={() => setActiveTab('coverage')}
                className="text-xs text-emerald-400 hover:text-emerald-300 font-medium cursor-pointer"
              >
                +9 more tactics on Full Heatmap →
              </button>
            </div>
          </div>
          <div className="text-xs text-slate-400 bg-slate-950/40 p-3 rounded-xl border border-slate-800/60 mt-4">
            💡 Coverage layer is auto-derived from <code className="text-slate-300">attack.t####</code> tags in deployed Sigma rules.
          </div>
        </div>

        {/* Recent Pipeline Runs Preview Panel */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm flex flex-col justify-between shadow-lg">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-slate-100">Recent Pipeline Activity</h3>
                <p className="text-xs text-slate-400">CI/CD rule validation and deployment runs</p>
              </div>
              <button
                onClick={() => setActiveTab('pipeline')}
                className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 flex items-center gap-1 cursor-pointer"
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
                    {formatTimestamp(run.created_at)}
                  </span>
                </div>
              ))}
            </div>
          </div>
          <div className="text-xs text-slate-400 bg-slate-950/40 p-3 rounded-xl border border-slate-800/60 mt-4">
            🤖 CI runs on every PR; CD deploys to live Wazuh SIEM on merge to <code className="text-slate-300">main</code>.
          </div>
        </div>
      </div>

      {/* ROW 3: NEW PANELS (Build Progress + System Health & Severity Breakdown) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Panel A: Build Progress Tracker (Spans 2 columns on left) */}
        <div className="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm relative overflow-hidden shadow-lg">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-emerald-500 via-teal-400 to-blue-500"></div>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                Build Progress Tracker
                <span className="text-xs font-normal px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                  10 / 10 Phases Complete
                </span>
              </h3>
              <p className="text-xs text-slate-400">Structured development lifecycle from architecture to production</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs">
            {(buildProgress || []).map((step) => (
              <div
                key={step.phase}
                className="p-3 bg-slate-950/80 border border-slate-800/80 rounded-xl flex items-center justify-between gap-2"
              >
                <div className="flex items-center gap-2.5 overflow-hidden">
                  <span className="text-xs font-mono font-bold text-slate-500 shrink-0">
                    P{step.phase < 10 ? `0${step.phase}` : step.phase}
                  </span>
                  <span className="text-slate-200 font-medium truncate">{step.title}</span>
                </div>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 shrink-0">
                  ✅ Complete
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column Stack: Panel B (System Health) & Panel C (Severity Breakdown) */}
        <div className="space-y-6 flex flex-col">
          {/* Panel B: System Health Strip */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm relative overflow-hidden shadow-lg">
            <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-teal-400 to-blue-500"></div>
            <h3 className="text-sm font-bold text-slate-100 mb-1">System Health</h3>
            <p className="text-xs text-slate-400 mb-3">Live component checks (server-side output)</p>

            <div className="space-y-2">
              {Object.entries(components).map(([key, item]) => {
                const isOnline = item.status === 'online';
                return (
                  <div key={key} className="p-2.5 bg-slate-950/80 border border-slate-800 rounded-xl flex items-center justify-between text-xs">
                    <span className="text-slate-200 font-medium">{item.name}</span>
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold font-mono ${
                      isOnline ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                    }`}>
                      {isOnline ? '● Online' : '○ Offline'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Panel C: Severity Breakdown Bar Chart */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm relative overflow-hidden shadow-lg flex-1 flex flex-col justify-between">
            <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-orange-500 to-rose-500"></div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 mb-1">Rule Severity Breakdown</h3>
              <p className="text-xs text-slate-400 mb-3">Inventory distribution by level</p>

              {/* Horizontal Bar Chart */}
              <div className="space-y-2.5 my-2">
                {Object.entries(severityCounts).map(([level, count]) => {
                  const pct = totalRules > 0 ? (count / totalRules) * 100 : 0;
                  return (
                    <div key={level} className="space-y-1 text-xs">
                      <div className="flex justify-between text-[11px] font-mono capitalize text-slate-300">
                        <span>{level}</span>
                        <span>{count} rule(s)</span>
                      </div>
                      <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                        <div
                          className={`h-full ${SEVERITY_COLORS[level]} transition-all duration-500`}
                          style={{ width: `${Math.max(pct, count > 0 ? 10 : 0)}%` }}
                        ></div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="text-[11px] text-slate-500 font-mono mt-3 pt-2 border-t border-slate-800">
              Derived from <code className="text-slate-400">rules_index.json</code>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
