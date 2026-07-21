import React, { useState } from 'react';

const ENTERPRISE_TACTICS = [
  { id: 'execution', name: 'Execution' },
  { id: 'persistence', name: 'Persistence' },
  { id: 'privilege-escalation', name: 'Privilege Escalation' },
  { id: 'defense-evasion', name: 'Defense Evasion' },
  { id: 'credential-access', name: 'Credential Access' },
  { id: 'discovery', name: 'Discovery' },
  { id: 'lateral-movement', name: 'Lateral Movement' }
];

const SAMPLE_TECHNIQUES = {
  'execution': [
    { id: 'T1059.001', name: 'PowerShell' },
    { id: 'T1059.003', name: 'Windows Command Shell' },
    { id: 'T1204.002', name: 'Malicious File' }
  ],
  'persistence': [
    { id: 'T1547.001', name: 'Registry Run Keys' },
    { id: 'T1053.005', name: 'Scheduled Task' }
  ],
  'privilege-escalation': [
    { id: 'T1548.002', name: 'Bypass UAC' }
  ],
  'defense-evasion': [
    { id: 'T1027', name: 'Obfuscated Files' },
    { id: 'T1112', name: 'Modify Registry' }
  ],
  'credential-access': [
    { id: 'T1003.001', name: 'LSASS Memory Dump' }
  ],
  'discovery': [
    { id: 'T1082', name: 'System Information Discovery' }
  ],
  'lateral-movement': [
    { id: 'T1021.001', name: 'Remote Desktop Protocol' }
  ]
};

export default function AttackCoverageTab({ attackLayer, rules, setActiveTab }) {
  const [pinnedTechnique, setPinnedTechnique] = useState(null);
  const [hoveredTechnique, setHoveredTechnique] = useState(null);

  // Build technique map from attackLayer JSON
  const layerTechniqueMap = {};
  (attackLayer?.techniques || []).forEach((t) => {
    layerTechniqueMap[t.techniqueID] = t;
  });

  const getTechniqueData = (techId) => {
    return layerTechniqueMap[techId] || { techniqueID: techId, score: 0, color: null, comment: '' };
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100">MITRE ATT&CK Matrix Coverage Heatmap</h2>
          <p className="text-xs text-slate-400">Live layer schema v4.5 generated from deployed rules' ATT&CK tags</p>
        </div>
        <div className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-3 py-1.5 rounded-lg border border-emerald-500/20">
          Domain: Enterprise ATT&CK v14
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Heatmap Grid (3 Cols) */}
        <div className="lg:col-span-3 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm overflow-x-auto">
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 min-w-[700px]">
            {ENTERPRISE_TACTICS.map((tactic) => (
              <div key={tactic.id} className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-3 flex flex-col gap-2">
                <div className="text-[11px] font-bold text-blue-400 uppercase tracking-wider pb-2 border-b border-slate-800 truncate">
                  {tactic.name}
                </div>

                {SAMPLE_TECHNIQUES[tactic.id]?.map((tech) => {
                  const data = getTechniqueData(tech.id);
                  const isCovered = data.score > 0;
                  const isPinned = pinnedTechnique?.id === tech.id;

                  return (
                    <div
                      key={tech.id}
                      onClick={() => setPinnedTechnique({ ...tech, data })}
                      onMouseEnter={() => setHoveredTechnique({ ...tech, data })}
                      onMouseLeave={() => setHoveredTechnique(null)}
                      className={`p-2.5 rounded-lg border text-left cursor-pointer transition-all relative ${
                        isCovered
                          ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300 shadow-sm shadow-emerald-500/10'
                          : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:bg-slate-800/60'
                      } ${isPinned ? 'ring-2 ring-emerald-400' : ''}`}
                    >
                      <div className="font-mono text-[11px] font-bold flex items-center justify-between">
                        <span>{tech.id}</span>
                        {isCovered && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500 text-slate-950 font-black">
                            {data.score}
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] mt-1 font-medium leading-tight truncate">
                        {tech.name}
                      </div>

                      {/* Tooltip on Hover */}
                      {hoveredTechnique?.id === tech.id && (
                        <div className="absolute left-1/2 -translate-x-1/2 bottom-full mb-2 z-20 w-48 bg-slate-950 border border-slate-700 p-2.5 rounded-xl text-[11px] text-slate-200 shadow-xl pointer-events-none">
                          <div className="font-mono font-bold text-emerald-400">{tech.id}</div>
                          <div className="font-semibold">{tech.name}</div>
                          <div className="mt-1 text-slate-400">Rules covering: <strong className="text-white">{data.score}</strong></div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>

          {/* Color Legend Fixed at Bottom */}
          <div className="mt-6 pt-4 border-t border-slate-800 flex flex-wrap items-center justify-between gap-4 text-xs text-slate-400">
            <div className="flex items-center gap-4">
              <span className="font-semibold text-slate-300">Coverage Intensity Legend:</span>
              <div className="flex items-center gap-1.5">
                <span className="w-3.5 h-3.5 rounded bg-slate-900 border border-slate-800"></span>
                <span>0 Rules (Uncovered)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3.5 h-3.5 rounded bg-emerald-500/20 border border-emerald-500/50"></span>
                <span>1-2 Rules (Covered)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3.5 h-3.5 rounded bg-emerald-500 border border-emerald-400"></span>
                <span>3+ Rules (High Coverage)</span>
              </div>
            </div>
            <span className="font-mono text-[11px]">Schema: Layer 4.5</span>
          </div>
        </div>

        {/* Pinned Side Detail Panel (1 Col) */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm">
          {pinnedTechnique ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <span className="text-xs font-bold text-emerald-400 font-mono">{pinnedTechnique.id}</span>
                <button
                  onClick={() => setPinnedTechnique(null)}
                  className="text-xs text-slate-400 hover:text-slate-200"
                >
                  ✕ Close
                </button>
              </div>

              <div>
                <h3 className="font-bold text-slate-100 text-sm">{pinnedTechnique.name}</h3>
                <p className="text-xs text-slate-400 mt-1">
                  {pinnedTechnique.data.score > 0
                    ? `Covered by ${pinnedTechnique.data.score} active Sigma rule(s).`
                    : 'No active rules currently cover this technique.'}
                </p>
              </div>

              {pinnedTechnique.data.score > 0 && (
                <div className="space-y-2">
                  <div className="text-[10px] font-bold uppercase text-slate-500 tracking-wider">Covering Rules</div>
                  {rules
                    .filter((r) => r.tags.some((t) => t.toLowerCase().includes(pinnedTechnique.id.toLowerCase())))
                    .map((r) => (
                      <div key={r.id} className="p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-1">
                        <div className="font-semibold text-xs text-slate-200">{r.title}</div>
                        <div className="text-[10px] font-mono text-slate-500">{r.file_path}</div>
                        <button
                          onClick={() => setActiveTab('rules')}
                          className="mt-2 text-[11px] font-medium text-emerald-400 hover:underline inline-flex items-center gap-1"
                        >
                          View in Rule Catalog →
                        </button>
                      </div>
                    ))}
                </div>
              )}
            </div>
          ) : (
            <div className="h-full min-h-[240px] flex flex-col items-center justify-center text-center p-4 text-slate-500">
              <svg className="w-8 h-8 mb-2 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122" />
              </svg>
              <p className="text-xs">Click any technique cell in the matrix to pin details and view covering rules.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
