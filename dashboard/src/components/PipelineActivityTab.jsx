import React, { useState, useMemo } from 'react';
import { AreaChart, Area, PieChart, Pie, Cell, Tooltip, ResponsiveContainer, CartesianGrid, XAxis } from 'recharts';
import { formatDateShort } from '../utils/formatters';

export default function PipelineActivityTab({ runs }) {
  const [filterType, setFilterType] = useState('all');

  const filteredRuns = useMemo(() => {
    return runs.filter((r) => {
      const isCi = r.name?.includes('CI') || r.event === 'pull_request';
      const isCd = r.name?.includes('CD') || r.event === 'push';
      if (filterType === 'ci') return isCi;
      if (filterType === 'cd') return isCd;
      return true;
    });
  }, [runs, filterType]);

  // Calculate CI/CD Pass Rate
  const passRateStats = useMemo(() => {
    if (runs.length === 0) return { passPct: 100, passed: 0, total: 0 };
    const passed = runs.filter((r) => r.conclusion === 'success').length;
    const total = runs.length;
    const passPct = Math.round((passed / total) * 100);
    return { passPct, passed, total };
  }, [runs]);

  // Recharts Pass Rate Gauge Data
  const gaugeData = useMemo(() => {
    return [
      { name: 'Passed', value: passRateStats.passPct, color: '#10b981' },
      { name: 'Failed/Other', value: 100 - passRateStats.passPct, color: '#334155' }
    ];
  }, [passRateStats]);

  // Recharts Trend Line Data (sparkline per run)
  const trendData = useMemo(() => {
    return [...runs].reverse().map((r, i) => ({
      runNum: `#${i + 1}`,
      passVal: r.conclusion === 'success' ? 100 : 0,
      name: r.name
    }));
  }, [runs]);

  return (
    <div className="space-y-6">
      {/* RECHARTS PASS RATE GAUGE & TREND ROW */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Gauge Card (1 Col) */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm shadow-lg flex flex-col items-center justify-between text-center">
          <div className="w-full text-left">
            <h3 className="text-sm font-bold text-slate-100">CI/CD Pass Rate</h3>
            <p className="text-xs text-slate-400">Success rate across recent workflow executions</p>
          </div>

          <div className="h-44 w-full relative flex items-center justify-center my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={gaugeData}
                  cx="50%"
                  cy="70%"
                  startAngle={180}
                  endAngle={0}
                  innerRadius={60}
                  outerRadius={85}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {gaugeData.map((entry, index) => (
                    <Cell key={`gauge-${index}`} fill={entry.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute top-[55%] left-1/2 -translate-x-1/2 -translate-y-1/2 text-center">
              <div className="text-2xl font-black text-slate-100 font-mono">{passRateStats.passPct}%</div>
              <div className="text-[10px] text-emerald-400 font-semibold uppercase tracking-wider">Pass Rate</div>
            </div>
          </div>

          <div className="text-xs text-slate-400 font-mono">
            {passRateStats.passed} / {passRateStats.total} runs succeeded
          </div>
        </div>

        {/* Trend Area Chart (2 Cols) */}
        <div className="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm shadow-lg flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100 mb-1">Execution Status Trend</h3>
            <p className="text-xs text-slate-400 mb-3">Historical pass/fail status per pipeline run over time</p>
          </div>

          <div className="h-40 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="passGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="runNum" stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#020617', borderColor: '#334155', borderRadius: '10px', fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="passVal" name="Status %" stroke="#10b981" strokeWidth={2} fillOpacity={1} fill="url(#passGradient)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Header & Filter Controls */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100">CI/CD Pipeline Execution History</h2>
          <p className="text-xs text-slate-400">Automated GitHub Actions workflows for rule testing and deployment</p>
        </div>

        {/* Filter Toggle */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800">
          <button
            onClick={() => setFilterType('all')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              filterType === 'all' ? 'bg-slate-800 text-slate-100 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All Runs
          </button>
          <button
            onClick={() => setFilterType('ci')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              filterType === 'ci' ? 'bg-slate-800 text-emerald-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            CI Only
          </button>
          <button
            onClick={() => setFilterType('cd')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              filterType === 'cd' ? 'bg-slate-800 text-blue-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            CD Only
          </button>
        </div>
      </div>

      {/* Runs List */}
      <div className="space-y-3">
        {filteredRuns.length === 0 ? (
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-12 text-center text-slate-500">
            No pipeline execution history matches the selected filter.
          </div>
        ) : (
          filteredRuns.map((run, idx) => {
            const isSuccess = run.conclusion === 'success';
            const isPending = run.status === 'in_progress';
            const runUrl = run.html_url || 'https://github.com/anshwhoo/detectforge/actions';

            return (
              <div
                key={run.id || idx}
                className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 md:p-5 backdrop-blur-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4 hover:border-slate-700 transition-all"
              >
                <div className="flex items-start gap-3.5">
                  {/* Status Indicator */}
                  <div className="mt-1">
                    {isPending ? (
                      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-amber-500/20 text-amber-400">
                        <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                        </svg>
                      </span>
                    ) : isSuccess ? (
                      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-emerald-500/20 text-emerald-400 font-bold text-xs">
                        ✓
                      </span>
                    ) : (
                      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-rose-500/20 text-rose-400 font-bold text-xs">
                        ✕
                      </span>
                    )}
                  </div>

                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-bold text-slate-100">{run.name}</h3>
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-400">
                        {run.event}
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 font-mono mt-1 line-clamp-1">{run.commit_message}</p>
                  </div>
                </div>

                <div className="flex items-center gap-4 w-full md:w-auto justify-between md:justify-end border-t md:border-t-0 pt-3 md:pt-0 border-slate-800">
                  <span className="text-xs text-slate-400 font-mono">
                    {formatDateShort(run.created_at)}
                  </span>

                  <a
                    href={runUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-all"
                  >
                    View Run
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                  </a>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
