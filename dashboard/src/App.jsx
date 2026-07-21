import React, { useState, useEffect, useCallback } from 'react';
import Navbar from './components/Navbar';
import OverviewTab from './components/OverviewTab';
import RulesTab from './components/RulesTab';
import AttackCoverageTab from './components/AttackCoverageTab';
import PipelineActivityTab from './components/PipelineActivityTab';
import MonitoringTab from './components/MonitoringTab';
import { formatTimestamp } from './utils/formatters';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [rules, setRules] = useState([]);
  const [attackLayer, setAttackLayer] = useState({ techniques: [] });
  const [pipelineRuns, setPipelineRuns] = useState([]);
  const [buildProgress, setBuildProgress] = useState([]);
  const [systemHealth, setSystemHealth] = useState(null);
  const [coverageHistory, setCoverageHistory] = useState([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState('');

  const loadData = useCallback(async () => {
    setIsRefreshing(true);
    const basePath = import.meta.env.BASE_URL.replace(/\/$/, '');
    try {
      const [rulesRes, layerRes, runsRes, buildRes, healthRes, historyRes] = await Promise.all([
        fetch(`${basePath}/data/rules_index.json?t=${Date.now()}`),
        fetch(`${basePath}/data/attack_coverage_layer.json?t=${Date.now()}`),
        fetch(`${basePath}/data/pipeline_runs.json?t=${Date.now()}`),
        fetch(`${basePath}/data/build_progress.json?t=${Date.now()}`),
        fetch(`${basePath}/data/system_health.json?t=${Date.now()}`),
        fetch(`${basePath}/data/coverage_history.json?t=${Date.now()}`)
      ]);

      if (rulesRes.ok) setRules(await rulesRes.json());
      if (layerRes.ok) setAttackLayer(await layerRes.json());
      if (runsRes.ok) setPipelineRuns(await runsRes.json());
      if (buildRes.ok) setBuildProgress(await buildRes.json());
      if (healthRes.ok) setSystemHealth(await healthRes.json());
      if (historyRes.ok) setCoverageHistory(await historyRes.json());

      setLastUpdated(formatTimestamp(new Date()));
    } catch (err) {
      console.error('Failed fetching dashboard data:', err);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  // Initial load + 30-second live polling interval
  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      loadData();
    }, 30000);
    return () => clearInterval(interval);
  }, [loadData]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans antialiased">
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onRefresh={loadData}
        lastUpdated={lastUpdated}
        isRefreshing={isRefreshing}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-8">
        {activeTab === 'overview' && (
          <OverviewTab
            rules={rules}
            attackLayer={attackLayer}
            runs={pipelineRuns}
            buildProgress={buildProgress}
            systemHealth={systemHealth}
            coverageHistory={coverageHistory}
            setActiveTab={setActiveTab}
          />
        )}
        {activeTab === 'rules' && <RulesTab rules={rules} />}
        {activeTab === 'coverage' && (
          <AttackCoverageTab
            attackLayer={attackLayer}
            rules={rules}
            setActiveTab={setActiveTab}
          />
        )}
        {activeTab === 'pipeline' && <PipelineActivityTab runs={pipelineRuns} />}
        {activeTab === 'monitoring' && <MonitoringTab />}
      </main>

      <footer className="border-t border-slate-900 bg-slate-950 text-slate-600 text-xs py-4 px-8 text-center font-mono">
        DetectForge — Detection-as-Code CI/CD Pipeline & Analytics Dashboard
      </footer>
    </div>
  );
}
