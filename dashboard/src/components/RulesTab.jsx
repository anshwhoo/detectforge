import React, { useState, useMemo } from 'react';

const SEVERITY_COLORS = {
  informational: 'bg-slate-800 text-slate-300 border-slate-700',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  critical: 'bg-rose-500/15 text-rose-400 border-rose-500/30'
};

const STATUS_COLORS = {
  experimental: 'bg-slate-800 text-slate-400 border-slate-700',
  test: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  stable: 'bg-teal-500/15 text-teal-300 border-teal-500/30'
};

export default function RulesTab({ rules }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [expandedId, setExpandedId] = useState(null);

  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      const matchesSearch = rule.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            rule.id.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesSeverity = severityFilter === 'all' || rule.level === severityFilter;
      const matchesStatus = statusFilter === 'all' || rule.status === statusFilter;
      return matchesSearch && matchesSeverity && matchesStatus;
    });
  }, [rules, searchTerm, severityFilter, statusFilter]);

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm flex flex-col md:flex-row gap-4 justify-between items-center">
        <div className="relative w-full md:w-96">
          <input
            type="text"
            placeholder="Search rules by title or ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 pl-10 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/40"
          />
          <svg className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          {/* Severity Dropdown */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-emerald-500/40"
          >
            <option value="all">All Severities</option>
            <option value="informational">Informational</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>

          {/* Status Dropdown */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-emerald-500/40"
          >
            <option value="all">All Statuses</option>
            <option value="experimental">Experimental</option>
            <option value="test">Test</option>
            <option value="stable">Stable</option>
          </select>
        </div>
      </div>

      {/* Rules Inventory Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] uppercase font-bold tracking-wider text-slate-400">
                <th className="py-3.5 px-5">Rule Title</th>
                <th className="py-3.5 px-4">Severity</th>
                <th className="py-3.5 px-4">ATT&CK Tags</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-sm">
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan="5" className="py-12 text-center text-slate-500">
                    <p className="text-sm font-medium">No Sigma rules match the selected search or filter parameters.</p>
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule) => {
                  const isExpanded = expandedId === rule.id;
                  const githubUrl = `https://github.com/anshwhoo/detectforge/blob/main/${rule.file_path}`;

                  return (
                    <React.Fragment key={rule.id}>
                      <tr className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-4 px-5">
                          <div className="font-semibold text-slate-100">{rule.title}</div>
                          <div className="text-xs font-mono text-slate-500 mt-0.5">{rule.file_path}</div>
                        </td>
                        <td className="py-4 px-4">
                          <span className={`inline-block px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase border ${SEVERITY_COLORS[rule.level] || SEVERITY_COLORS.medium}`}>
                            {rule.level}
                          </span>
                        </td>
                        <td className="py-4 px-4">
                          <div className="flex flex-wrap gap-1">
                            {rule.tags.map((tag, idx) => (
                              <span key={idx} className="px-2 py-0.5 rounded-md bg-blue-500/10 border border-blue-500/20 text-blue-400 text-[11px] font-mono">
                                {tag}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="py-4 px-4">
                          <span className={`inline-block px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${STATUS_COLORS[rule.status] || STATUS_COLORS.test}`}>
                            {rule.status}
                          </span>
                        </td>
                        <td className="py-4 px-4 text-right">
                          <button
                            onClick={() => toggleExpand(rule.id)}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-all"
                            title="Toggle rule details"
                          >
                            <svg className={`w-4 h-4 transition-transform ${isExpanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                            </svg>
                          </button>
                        </td>
                      </tr>

                      {/* Expanded Details Row */}
                      {isExpanded && (
                        <tr className="bg-slate-950/80">
                          <td colSpan="5" className="p-5 border-t border-b border-slate-800">
                            <div className="space-y-3 text-xs">
                              <div>
                                <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">Description</span>
                                <p className="text-slate-300 mt-1">{rule.description || 'No description provided.'}</p>
                              </div>

                              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                  <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">Logsource Category</span>
                                  <div className="mt-1 font-mono text-emerald-400 bg-slate-900 p-2 rounded-lg border border-slate-800">
                                    {JSON.stringify(rule.logsource)}
                                  </div>
                                </div>

                                <div>
                                  <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">Known False Positives</span>
                                  <ul className="mt-1 space-y-1 text-slate-400 list-disc list-inside">
                                    {rule.falsepositives && rule.falsepositives.length > 0 ? (
                                      rule.falsepositives.map((fp, idx) => <li key={idx}>{fp}</li>)
                                    ) : (
                                      <li>None documented</li>
                                    )}
                                  </ul>
                                </div>
                              </div>

                              <div className="pt-2 flex items-center justify-between">
                                <span className="font-mono text-[11px] text-slate-500">ID: {rule.id}</span>
                                <a
                                  href={githubUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-medium transition-all"
                                >
                                  View on GitHub
                                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                                  </svg>
                                </a>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
