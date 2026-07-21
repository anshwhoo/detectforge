import React, { useState, useEffect, useCallback } from 'react';
import Navbar from './components/Navbar';
import OverviewTab from './components/OverviewTab';
import RulesTab from './components/RulesTab';
import AttackCoverageTab from './components/AttackCoverageTab';
import PipelineActivityTab from './components/PipelineActivityTab';
import MonitoringTab from './components/MonitoringTab';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [rules, setRules] = useState([]);
  const [attackLayer, setAttackLayer] = useState({ techniques: [] });
  const [pipelineRuns, setPipelineRuns] = useState([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState('');

  const loadData = useCallback(async () => {
    setIsRefreshing(true);
    const basePath = import.meta.env.BASE_URL.replace(/\/$/, '');
    try {
      const [rulesRes, layerRes, runsRes] = await Promise.all([
        fetch(`${basePath}/data/rules_index.json?t=${Date.now()}`),
        fetch(`${basePath}/data/attack_coverage_layer.json?t=${Date.now()}`),
        fetch(`${basePath}/data/pipeline_runs.json?t=${Date.now()}`)
      ]);

      if (rulesRes.ok) setRules(await rulesRes.json());
      if (layerRes.ok) setAttackLayer(await layerRes.json());
      if (runsRes.ok) setPipelineRuns(await runsRes.json());

      setLastUpdated(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
    } catch (err) {
      console.error('Failed fetching dashboard data:', err);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
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
