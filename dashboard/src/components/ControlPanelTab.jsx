import React, { useState, useEffect, useCallback, useRef } from 'react';
import Editor from '@monaco-editor/react';

const BACKEND_URL = 'http://127.0.0.1:8001';

const DEFAULT_SIGMA_TEMPLATE = `title: Suspicious Scheduled Task Creation via Schtasks
id: ${crypto.randomUUID ? crypto.randomUUID() : 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'}
status: experimental
description: Detects creation of a scheduled task via schtasks.exe, which is commonly used by adversaries for persistence.
author: DetectForge Team
date: ${new Date().toISOString().split('T')[0].replace(/-/g, '/')}
references:
  - https://attack.mitre.org/techniques/T1053/005/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\schtasks.exe'
    CommandLine|contains|all:
      - '/create'
  condition: selection
falsepositives:
  - Legitimate administrative software deployment scripts
level: medium
tags:
  - attack.persistence
  - attack.t1053.005`;

const DEFAULT_TP_SAMPLE = `{
  "metadata": {
    "source": "OTRF-Security-Datasets",
    "technique_id": "T1053.005"
  },
  "event": {
    "EventID": 1,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "EventData": {
      "Image": "C:\\\\Windows\\\\System32\\\\schtasks.exe",
      "CommandLine": "schtasks.exe /create /tn MaintenanceScript /tr C:\\\\Users\\\\Public\\\\update.bat /sc daily",
      "User": "CORP\\\\victim"
    }
  }
}`;

const DEFAULT_FP_SAMPLE = `{
  "metadata": {
    "source": "Hand-crafted",
    "description": "Legitimate system update scheduled task"
  },
  "event": {
    "EventID": 1,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "EventData": {
      "Image": "C:\\\\Windows\\\\System32\\\\schtasks.exe",
      "CommandLine": "schtasks.exe /query /fo LIST /v",
      "User": "NT AUTHORITY\\\\SYSTEM"
    }
  }
}`;

export default function ControlPanelTab() {
  const [token, setToken] = useState('');
  const [status, setStatus] = useState(null);
  const [loadingAction, setLoadingAction] = useState(null);
  const [backendConnected, setBackendConnected] = useState(false);

  // Section B state
  const [ruleSlug, setRuleSlug] = useState('scheduled_task_creation');
  const [techniqueId, setTechniqueId] = useState('T1053.005');
  const [ruleYaml, setRuleYaml] = useState(DEFAULT_SIGMA_TEMPLATE);
  const [tpJson, setTpJson] = useState(DEFAULT_TP_SAMPLE);
  const [fpJson, setFpJson] = useState(DEFAULT_FP_SAMPLE);
  const [knownTechniques, setKnownTechniques] = useState([]);
  const [isCustomTechnique, setIsCustomTechnique] = useState(false);

  // Live Capture & Boundary Variant state
  const [captureStartTime, setCaptureStartTime] = useState(null);
  const [isCapturing, setIsCapturing] = useState(false);
  const [capturedEvents, setCapturedEvents] = useState(null);
  const [boundaryJson, setBoundaryJson] = useState('');
  const [saveWarning, setSaveWarning] = useState(null);

  // Terminal & SSE Stream State
  const [terminalLogs, setTerminalLogs] = useState([]);
  const [streamStatus, setStreamStatus] = useState(null); // 'IDLE', 'RUNNING', 'SUCCESS', 'FAILED'
  const consoleEndRef = useRef(null);

  // Section C state (Ship It)
  const [branchName, setBranchName] = useState('feature/schtask-persistence');
  const [commitMsg, setCommitMsg] = useState('feat(rules): add T1053.005 scheduled task creation rule');
  const [prTitle, setPrTitle] = useState('feat: T1053.005 scheduled task persistence detection');
  const [prDesc, setPrDesc] = useState('Adds Sigma detection for malicious scheduled task creation via schtasks.exe along with TP/FP telemetry corpus.');
  const [createdPrUrl, setCreatedPrUrl] = useState('');
  const [isPrMerged, setIsPrMerged] = useState(false);

  // Section D state (Rollback)
  const [selectedRuleId, setSelectedRuleId] = useState('c8b31a89-2917-4d92-93d3-0570b5550a18');

  // Fetch or refresh session token from backend
  const fetchToken = useCallback(async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/auth/token`);
      if (res.ok) {
        const data = await res.json();
        setToken(data.token);
        setBackendConnected(true);
        return data.token;
      }
    } catch (err) {
      console.warn('Control Panel backend unreachable:', err);
      setBackendConnected(false);
    }
    return '';
  }, []);

  // Initialize token and check backend
  useEffect(() => {
    fetchToken();
  }, [fetchToken]);

  // Load the list of techniques that have a real curated reference sample
  useEffect(() => {
    fetch(`${BACKEND_URL}/api/rules/known-techniques`)
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => setKnownTechniques(data))
      .catch(() => setKnownTechniques([]));
  }, []);

  // Builds a starter Sigma rule matching whatever technique was picked, so the YAML
  // editor doesn't keep showing an unrelated leftover rule (e.g. still describing
  // scheduled tasks after picking Windows Command Shell) while the TP/FP samples next
  // to it are for something else entirely. The detection logic is only a starting
  // point - Image|endswith is a safe guess from the real reference sample, but the
  // CommandLine fragment to key on is a judgment call left as a TODO for a human.
  const buildStarterYaml = (technique) => {
    const exeName = technique.sample_image ? technique.sample_image.split('\\').pop() : 'process.exe';
    const [base, sub] = technique.technique_id.split('.');
    const mitreUrl = sub
      ? `https://attack.mitre.org/techniques/${base}/${sub}/`
      : `https://attack.mitre.org/techniques/${base}/`;
    const tacticTag = technique.tactic ? technique.tactic.replace(/-/g, '_') : 'execution';
    return `title: Suspicious ${technique.display_name} Activity
id: ${crypto.randomUUID ? crypto.randomUUID() : 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'}
status: experimental
description: TODO - describe what makes this pattern suspicious.
author: DetectForge Team
date: ${new Date().toISOString().split('T')[0].replace(/-/g, '/')}
references:
  - ${mitreUrl}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\${exeName}'
    # TODO: reference CommandLine for this technique's sample - narrow this down:
    # ${technique.sample_image ? '(see the True Positive sample editor for the full command line)' : ''}
    CommandLine|contains: 'TODO'
  condition: selection
falsepositives:
  - TODO
level: medium
tags:
  - attack.${tacticTag}
  - attack.${technique.technique_id.toLowerCase()}`;
  };

  const handleTechniqueSelect = (value) => {
    if (value === '__custom__') {
      setIsCustomTechnique(true);
      return;
    }
    setIsCustomTechnique(false);
    setTechniqueId(value);
    const match = knownTechniques.find((t) => t.technique_id === value);
    if (match) {
      setRuleSlug(match.slug);
      setRuleYaml(buildStarterYaml(match));
    }
  };

  // Poll system status
  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/status`);
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
        setBackendConnected(true);
      }
    } catch {
      setBackendConnected(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  // Auto-scroll terminal logs
  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [terminalLogs]);

  // Helper for POST requests with auto-token-refresh retry
  const postAction = async (endpoint, payload) => {
    let activeToken = token;
    if (!activeToken) {
      activeToken = await fetchToken();
    }
    if (!activeToken) throw new Error('Security token missing or backend offline');

    let res = await fetch(`${BACKEND_URL}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-DetectForge-Token': activeToken
      },
      body: JSON.stringify(payload)
    });

    // Auto-retry once if token is stale (403 Forbidden)
    if (res.status === 403) {
      activeToken = await fetchToken();
      if (activeToken) {
        res = await fetch(`${BACKEND_URL}${endpoint}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-DetectForge-Token': activeToken
          },
          body: JSON.stringify(payload)
        });
      }
    }

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Action failed');
    return data;
  };

  // Stack controls
  const handleStackAction = async (endpoint, name) => {
    setLoadingAction(name);
    try {
      await postAction(endpoint, {});
      await fetchStatus();
    } catch (err) {
      alert(`Error: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  // SSE Stream runner (Lint, Convert, Test)
  const runSSEStream = async (endpointPath, label) => {
    let activeToken = token;
    if (!activeToken) {
      activeToken = await fetchToken();
    }
    if (!activeToken) {
      alert('Backend token missing or unreachable');
      return;
    }
    setTerminalLogs([`[*] Starting ${label}...`]);
    setStreamStatus('RUNNING');

    const eventSource = new EventSource(`${BACKEND_URL}${endpointPath}?token=${encodeURIComponent(activeToken)}`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.line) {
          setTerminalLogs((prev) => [...prev, data.line]);
        }
        if (data.status) {
          setStreamStatus(data.status);
          setTerminalLogs((prev) => [
            ...prev,
            `[*] ${label} Finished with status: ${data.status} (Exit Code: ${data.exit_code})`
          ]);
          eventSource.close();
        }
      } catch (err) {
        console.error('SSE Error:', err);
      }
    };

    eventSource.onerror = (err) => {
      console.error('EventSource failed:', err);
      setTerminalLogs((prev) => [...prev, '[!] Error: Connection to backend stream failed']);
      setStreamStatus('FAILED');
      eventSource.close();
    };
  };

  // Fetch reference samples mini-form handler
  const handleFetchSamples = async () => {
    if (!techniqueId || !ruleSlug) {
      alert('Please specify both Technique ID and Rule Slug');
      return;
    }
    setLoadingAction('fetch-samples');
    try {
      const res = await postAction('/api/rules/fetch-samples', {
        technique_id: techniqueId,
        rule_slug: ruleSlug
      });
      if (res.tp_json) setTpJson(res.tp_json);
      if (res.is_placeholder) {
        setTerminalLogs((prev) => [
          ...prev,
          `[!] WARNING: No real reference data exists for ${techniqueId} - a generic placeholder was inserted into the True Positive sample. Replace it before trusting test results.`
        ]);
      } else {
        setTerminalLogs((prev) => [...prev, `[+] True Positive sample fetched for ${techniqueId}`]);
      }
    } catch (err) {
      alert(`Fetch failed: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  // Live FP Telemetry Capture handlers
  const handleStartCapture = async () => {
    setLoadingAction('capture-start');
    try {
      const res = await postAction('/api/rules/capture/start', {});
      setCaptureStartTime(res.start_time);
      setIsCapturing(true);
      setTerminalLogs((prev) => [...prev, `[*] Live FP Telemetry Capture started at ${res.start_time}`]);
    } catch (err) {
      alert(`Start capture failed: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  const handleStopCapture = async () => {
    if (!captureStartTime) return;
    setLoadingAction('capture-stop');
    try {
      const res = await postAction('/api/rules/capture/stop', { start_time: captureStartTime });
      setIsCapturing(false);
      setCapturedEvents(res.events || []);
      setTerminalLogs((prev) => [...prev, `[+] Live Capture stopped. Fetched ${res.events?.length || 0} matching Sysmon event(s).`]);
    } catch (err) {
      alert(`Stop capture failed: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  // Boundary Variant Generation (Rule Line Check)
  const handleGenerateBoundaryVariant = async () => {
    setLoadingAction('boundary');
    try {
      const res = await postAction('/api/rules/generate-boundary-variant', {
        rule_slug: ruleSlug,
        rule_yaml: ruleYaml,
        tp_json: tpJson
      });
      setBoundaryJson(res.boundary_json);
      setTerminalLogs((prev) => [...prev, `[+] Saved boundary variant to ${res.boundary_path}`]);
    } catch (err) {
      alert(`Generate boundary test failed: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  // Save rule & test set
  const handleSaveRule = async () => {
    setLoadingAction('save-rule');
    try {
      const res = await postAction('/api/rules/save', {
        title: 'New Rule',
        technique_id: techniqueId,
        rule_slug: ruleSlug,
        rule_yaml: ruleYaml,
        tp_json: tpJson,
        fp_json: fpJson
      });
      if (res.warning) {
        setSaveWarning(res.warning);
        setTerminalLogs((prev) => [...prev, `[!] Policy Warning: ${res.warning}`]);
      } else {
        setSaveWarning(null);
      }
      alert(`Success: ${res.message}${res.warning ? `\n\n⚠️ ${res.warning}` : ''}`);
      setTerminalLogs((prev) => [...prev, `[+] Saved rule to ${res.rule_path} & updated tests/manifest.yml`]);
    } catch (err) {
      alert(`Save failed: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  // Branch & PR handler
  const handleCreatePR = async () => {
    if (!branchName || !commitMsg || !prTitle) {
      alert('Please fill out all PR fields');
      return;
    }
    setLoadingAction('create-pr');
    try {
      const res = await postAction('/api/git/branch-and-pr', {
        branch_name: branchName,
        commit_message: commitMsg,
        pr_title: prTitle,
        pr_description: prDesc
      });
      setCreatedPrUrl(res.pr_url);
      setTerminalLogs((prev) => [...prev, `[+] PR Opened: ${res.pr_url}`]);
      alert(`PR Created Successfully!\nURL: ${res.pr_url}`);
    } catch (err) {
      alert(`PR creation failed: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  // Merge PR handler
  const handleMergePR = async () => {
    if (!createdPrUrl) {
      alert('No active PR created yet');
      return;
    }
    setLoadingAction('merge-pr');
    try {
      const res = await postAction('/api/git/merge-pr', {
        pr_number_or_url: createdPrUrl
      });
      setIsPrMerged(true);
      alert(`PR Merged! CD Deployment Triggered.`);
      setTerminalLogs((prev) => [...prev, `[+] PR Merged successfully. CD deployment underway.`]);
    } catch (err) {
      alert(`Merge Blocked: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  // Rollback handler
  const handleRollback = async () => {
    if (!selectedRuleId) {
      alert('Select a rule ID to roll back');
      return;
    }
    setLoadingAction('rollback');
    try {
      const res = await postAction('/api/rules/rollback', {
        rule_id: selectedRuleId
      });
      alert(`Rollback Complete: ${res.message}`);
      setTerminalLogs((prev) => [...prev, `[-] Rolled back rule ${selectedRuleId}`]);
    } catch (err) {
      alert(`Rollback failed: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  return (
    <div className="space-y-8 animate-fadeIn max-w-7xl mx-auto pb-16">
      {/* Header Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
              </svg>
              Local Engineering Control Panel
            </h2>
            <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-medium border ${
              backendConnected
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
            }`}>
              {backendConnected ? 'Backend Connected (127.0.0.1:8001)' : 'Backend Offline'}
            </span>
          </div>
          <p className="text-xs md:text-sm text-slate-400">
            Automate environment controls, Sigma rule creation, local test harness execution, PR workflows, and rule rollbacks.
          </p>
        </div>

        <a
          href="https://localhost:443"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 text-xs md:text-sm font-medium transition-all shadow-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/50 cursor-pointer whitespace-nowrap"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
          </svg>
          Open Wazuh Dashboard ↗
        </a>
      </div>

      {/* SECTION A: Local Environment */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-6 shadow-lg">
        <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
          Section A — Environment Controls & SIEM Health
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="text-xs text-slate-400 font-medium">Wazuh Indexer (Port 9200)</div>
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm text-slate-200 font-semibold">Indexer API</span>
              <span className={`px-2 py-0.5 rounded text-xs font-mono font-medium ${
                status?.indexer_api === 'online' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
              }`}>
                {status?.indexer_api === 'online' ? '● ONLINE' : '○ OFFLINE'}
              </span>
            </div>
          </div>

          <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="text-xs text-slate-400 font-medium">Wazuh Manager (Port 55000)</div>
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm text-slate-200 font-semibold">Manager Engine</span>
              <span className={`px-2 py-0.5 rounded text-xs font-mono font-medium ${
                status?.containers?.manager === 'online' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
              }`}>
                {status?.containers?.manager === 'online' ? '● ONLINE' : '○ OFFLINE'}
              </span>
            </div>
          </div>

          <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="text-xs text-slate-400 font-medium">Wazuh UI (Port 443)</div>
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm text-slate-200 font-semibold">Dashboard Stack</span>
              <span className={`px-2 py-0.5 rounded text-xs font-mono font-medium ${
                status?.containers?.dashboard === 'online' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
              }`}>
                {status?.containers?.dashboard === 'online' ? '● ONLINE' : '○ OFFLINE'}
              </span>
            </div>
          </div>

          <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="text-xs text-slate-400 font-medium">GitHub Runner</div>
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm text-slate-200 font-semibold">detectforge-runner</span>
              <span className={`px-2 py-0.5 rounded text-xs font-mono font-medium ${
                status?.runner === 'online' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
              }`}>
                {status?.runner === 'online' ? '● ONLINE' : '○ OFFLINE'}
              </span>
            </div>
          </div>

          <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="text-xs text-slate-400 font-medium">Sysmon Telemetry Agent</div>
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm text-slate-200 font-semibold">Sysmon Service</span>
              <span className={`px-2 py-0.5 rounded text-xs font-mono font-medium ${
                status?.sysmon === 'installed' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'
              }`}>
                {status?.sysmon === 'installed' ? '● INSTALLED' : '○ MISSING'}
              </span>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 pt-2">
          <button
            onClick={() => handleStackAction('/api/docker/up', 'docker-up')}
            disabled={loadingAction !== null}
            className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-xs transition-all shadow-md disabled:opacity-50 cursor-pointer"
          >
            {loadingAction === 'docker-up' ? 'Starting Docker...' : 'Start Docker Stack'}
          </button>

          <button
            onClick={() => handleStackAction('/api/docker/down', 'docker-down')}
            disabled={loadingAction !== null}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-rose-400 border border-slate-700 font-semibold text-xs transition-all disabled:opacity-50 cursor-pointer"
          >
            {loadingAction === 'docker-down' ? 'Stopping Docker...' : 'Stop Docker Stack'}
          </button>

          <div className="h-4 w-[1px] bg-slate-800 mx-1 hidden sm:block"></div>

          <button
            onClick={() => handleStackAction('/api/runner/start', 'runner-start')}
            disabled={loadingAction !== null}
            className="px-4 py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-slate-950 font-semibold text-xs transition-all shadow-md disabled:opacity-50 cursor-pointer"
          >
            {loadingAction === 'runner-start' ? 'Starting Runner...' : 'Start Runner'}
          </button>

          <button
            onClick={() => handleStackAction('/api/runner/stop', 'runner-stop')}
            disabled={loadingAction !== null}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 font-semibold text-xs transition-all disabled:opacity-50 cursor-pointer"
          >
            {loadingAction === 'runner-stop' ? 'Stopping Runner...' : 'Stop Runner'}
          </button>

          <div className="h-4 w-[1px] bg-slate-800 mx-1 hidden sm:block"></div>

          <button
            onClick={() => handleStackAction('/api/sysmon/install', 'sysmon-install')}
            disabled={loadingAction !== null || status?.sysmon === 'installed'}
            className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all shadow-md cursor-pointer ${
              status?.sysmon === 'installed'
                ? 'bg-slate-800 text-slate-500 border border-slate-700 opacity-60 cursor-not-allowed'
                : 'bg-indigo-600 hover:bg-indigo-500 text-slate-100'
            }`}
          >
            {loadingAction === 'sysmon-install' ? 'Installing Sysmon...' : status?.sysmon === 'installed' ? 'Sysmon Installed' : 'Install Sysmon'}
          </button>
        </div>
      </div>

      {/* SECTION B: Write & Test a Rule */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-6 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400"></span>
            Section B — Write, Edit & Validate Rule Telemetry
          </h3>

          {/* Mini-Form: Fetch Reference Sample */}
          <div className="flex items-center gap-2 bg-slate-950 p-1.5 rounded-xl border border-slate-800">
            {isCustomTechnique ? (
              <div className="flex items-center gap-1">
                <input
                  type="text"
                  placeholder="Technique (e.g. T1055)"
                  value={techniqueId}
                  onChange={(e) => setTechniqueId(e.target.value)}
                  autoFocus
                  title="Techniques outside the curated list fall back to a generic placeholder sample - a warning will show after fetching"
                  className="bg-slate-900 text-xs px-2.5 py-1.5 rounded-lg border border-amber-600/50 text-slate-100 font-mono w-32 focus:outline-none focus:ring-1 focus:ring-amber-500"
                />
                <button
                  type="button"
                  onClick={() => setIsCustomTechnique(false)}
                  title="Back to curated technique list"
                  className="text-slate-400 hover:text-slate-200 text-xs px-1 cursor-pointer"
                >
                  ✕
                </button>
              </div>
            ) : (
              <select
                value={techniqueId}
                onChange={(e) => handleTechniqueSelect(e.target.value)}
                title="Only these techniques have a real curated reference sample - anything else falls back to a placeholder"
                className="bg-slate-900 text-xs px-2.5 py-1.5 rounded-lg border border-slate-800 text-slate-100 font-mono w-56 focus:outline-none focus:ring-1 focus:ring-sky-500"
              >
                {knownTechniques.length === 0 && (
                  <option value={techniqueId}>{techniqueId} (loading list…)</option>
                )}
                {knownTechniques.map((t) => (
                  <option key={t.technique_id} value={t.technique_id}>
                    {t.technique_id} — {t.display_name}
                  </option>
                ))}
                <option value="__custom__">Custom technique ID…</option>
              </select>
            )}
            <input
              type="text"
              placeholder="Rule Slug (scheduled_task)"
              value={ruleSlug}
              onChange={(e) => setRuleSlug(e.target.value)}
              className="bg-slate-900 text-xs px-2.5 py-1.5 rounded-lg border border-slate-800 text-slate-100 font-mono w-40 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
            <button
              onClick={handleFetchSamples}
              disabled={loadingAction !== null}
              className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-slate-950 text-xs font-semibold transition-all disabled:opacity-50 cursor-pointer whitespace-nowrap"
            >
              {loadingAction === 'fetch-samples' ? 'Fetching...' : 'Fetch Reference Sample'}
            </button>
          </div>
        </div>

        {/* Monaco Editors Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Sigma YAML Editor */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span>Sigma Rule Definition (.yml)</span>
              <span className="text-emerald-400">rules/windows/process_creation/proc_{ruleSlug}.yml</span>
            </div>
            <div className="border border-slate-800 rounded-xl overflow-hidden shadow-inner h-80">
              <Editor
                height="100%"
                defaultLanguage="yaml"
                theme="vs-dark"
                value={ruleYaml}
                onChange={(val) => setRuleYaml(val || '')}
                options={{
                  minimap: { enabled: false },
                  fontSize: 12,
                  lineNumbers: 'on',
                  scrollBeyondLastLine: false
                }}
              />
            </div>
          </div>

          {/* TP & FP Sample JSON Editors */}
          <div className="space-y-4 flex flex-col justify-between">
            {/* True Positive Sample JSON */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="text-emerald-400 font-semibold">● True Positive Sample (Must Trigger)</span>
                <span>tests/true_positive/{ruleSlug}/sample.json</span>
              </div>
              <div className="border border-slate-800 rounded-xl overflow-hidden shadow-inner h-36">
                <Editor
                  height="100%"
                  defaultLanguage="json"
                  theme="vs-dark"
                  value={tpJson}
                  onChange={(val) => setTpJson(val || '')}
                  options={{ minimap: { enabled: false }, fontSize: 11, lineNumbers: 'off' }}
                />
              </div>
            </div>

            {/* False Positive Sample JSON */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400 flex-wrap gap-2">
                <span className="text-rose-400 font-semibold">○ False Positive Sample (Must NOT Trigger)</span>
                
                {/* Live FP Telemetry Capture Controls */}
                <div className="flex items-center gap-2">
                  {!isCapturing ? (
                    <button
                      onClick={handleStartCapture}
                      disabled={loadingAction !== null}
                      className="px-2.5 py-1 rounded bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/30 text-[11px] font-semibold transition-all cursor-pointer flex items-center gap-1"
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                      Start Capture
                    </button>
                  ) : (
                    <button
                      onClick={handleStopCapture}
                      disabled={loadingAction !== null}
                      className="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-500 text-slate-100 text-[11px] font-bold transition-all cursor-pointer animate-pulse"
                    >
                      Stop Capture
                    </button>
                  )}
                  <span>tests/false_positive/{ruleSlug}/legitimate.json</span>
                </div>
              </div>

              {/* Instructional Banner while capture is active */}
              {isCapturing && (
                <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-3 text-amber-300 text-xs font-medium flex items-center justify-between animate-pulse">
                  <span className="flex items-center gap-2">
                    <svg className="w-4 h-4 text-amber-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <span><strong>Live Capture Active:</strong> Perform the legitimate action to ignore, then click <strong>Stop Capture</strong>.</span>
                  </span>
                </div>
              )}

              {/* Multi-Event Captured Telemetry Picker Modal / Card */}
              {capturedEvents && (
                <div className="bg-slate-950 border border-amber-500/40 rounded-xl p-3 space-y-2 text-xs">
                  <div className="flex items-center justify-between font-bold text-amber-300 border-b border-slate-800 pb-1.5">
                    <span>Captured Sysmon Process Events ({capturedEvents.length}) — Select sample to keep:</span>
                    <button onClick={() => setCapturedEvents(null)} className="text-slate-400 hover:text-slate-200">✕</button>
                  </div>
                  <div className="space-y-1.5 max-h-48 overflow-y-auto">
                    {capturedEvents.length === 0 ? (
                      <p className="text-slate-500 italic p-1">No process creation events detected during this capture window.</p>
                    ) : (
                      capturedEvents.map((evt, idx) => (
                        <div key={idx} className="p-2 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-between gap-3 font-mono">
                          <div className="truncate text-slate-300 text-[11px]">
                            <span className="text-amber-400 font-bold">[{evt.event?.EventData?.Image?.split('\\').pop() || 'Process'}]</span>{' '}
                            {evt.event?.EventData?.CommandLine || 'No commandline'}
                          </div>
                          <button
                            onClick={() => {
                              setFpJson(JSON.stringify(evt, null, 2));
                              setCapturedEvents(null);
                            }}
                            className="px-2.5 py-1 bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold rounded text-[11px] whitespace-nowrap cursor-pointer"
                          >
                            Use as FP Sample
                          </button>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}

              <div className="border border-slate-800 rounded-xl overflow-hidden shadow-inner h-36">
                <Editor
                  height="100%"
                  defaultLanguage="json"
                  theme="vs-dark"
                  value={fpJson}
                  onChange={(val) => setFpJson(val || '')}
                  options={{ minimap: { enabled: false }, fontSize: 11, lineNumbers: 'off' }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* DISTINCT BOUNDARY TEST GENERATOR SUB-SECTION */}
        <div className="bg-slate-950/80 border border-indigo-500/30 rounded-xl p-4 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="space-y-0.5">
              <div className="flex items-center gap-2">
                <span className="font-bold text-xs text-indigo-300 font-mono">Boundary Variant (Rule Line Check)</span>
                <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  Boundary test — checks where the rule's line is drawn, does not replace a real false positive.
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Saves to <code className="text-indigo-400">tests/boundary_variants/{ruleSlug}/</code>. Isolated from false-positive test manifests.
              </p>
            </div>

            <button
              onClick={handleGenerateBoundaryVariant}
              disabled={loadingAction !== null}
              className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-slate-100 font-semibold text-xs transition-all shadow-md cursor-pointer whitespace-nowrap"
            >
              {loadingAction === 'boundary' ? 'Generating...' : 'Generate Boundary Test'}
            </button>
          </div>

          {boundaryJson && (
            <div className="space-y-1">
              <div className="text-[11px] font-mono text-indigo-400">Generated Boundary Variant Sample (tests/boundary_variants/{ruleSlug}/boundary_sample_1.json)</div>
              <div className="border border-indigo-500/30 rounded-lg overflow-hidden h-32">
                <Editor
                  height="100%"
                  defaultLanguage="json"
                  theme="vs-dark"
                  value={boundaryJson}
                  onChange={(val) => setBoundaryJson(val || '')}
                  options={{ minimap: { enabled: false }, fontSize: 11, lineNumbers: 'off' }}
                />
              </div>
            </div>
          )}
        </div>

        {/* Save Policy Warning Banner */}
        {saveWarning && (
          <div className="bg-rose-500/10 border border-rose-500/30 rounded-xl p-3 text-rose-300 text-xs font-medium flex items-center justify-between">
            <span className="flex items-center gap-2">
              <svg className="w-4 h-4 text-rose-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <span><strong>Policy Warning:</strong> {saveWarning}</span>
            </span>
            <button onClick={() => setSaveWarning(null)} className="text-rose-400 hover:text-rose-200 font-bold">✕</button>
          </div>
        )}

        {/* Local Validation & Test Action Buttons */}
        <div className="flex flex-wrap items-center gap-3 pt-2">
          <button
            onClick={handleSaveRule}
            disabled={loadingAction !== null}
            className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-xs transition-all shadow-md cursor-pointer"
          >
            Save Rule & Update Manifest
          </button>

          <button
            onClick={() => runSSEStream('/api/rules/lint/stream', 'Lint Rules')}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition-all cursor-pointer"
          >
            1. Lint Rule Syntax
          </button>

          <button
            onClick={() => runSSEStream('/api/rules/convert/stream', 'Convert to Lucene')}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition-all cursor-pointer"
          >
            2. Convert to Lucene
          </button>

          <button
            onClick={() => runSSEStream('/api/rules/test/stream', 'TP/FP Test Harness')}
            className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-slate-100 text-xs font-semibold transition-all shadow-md cursor-pointer"
          >
            3. Run Test Harness
          </button>
        </div>

        {/* Live SSE Console Output Window */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2 font-mono text-xs shadow-inner">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2 text-slate-400">
            <span>Console Output & Streaming Test Results</span>
            {streamStatus && (
              <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                streamStatus === 'SUCCESS' ? 'bg-emerald-500/20 text-emerald-400' :
                streamStatus === 'FAILED' ? 'bg-rose-500/20 text-rose-400' : 'bg-sky-500/20 text-sky-400 animate-pulse'
              }`}>
                {streamStatus}
              </span>
            )}
          </div>
          <div className="h-40 overflow-y-auto space-y-1 text-slate-300">
            {terminalLogs.length === 0 ? (
              <span className="text-slate-600 italic">Click Lint, Convert, or Run Test Harness to stream output here...</span>
            ) : (
              terminalLogs.map((log, idx) => (
                <div key={idx} className={log.includes('FAIL') || log.includes('Error') ? 'text-rose-400' : log.includes('PASS') || log.includes('[+]') ? 'text-emerald-400' : ''}>
                  {log}
                </div>
              ))
            )}
            <div ref={consoleEndRef} />
          </div>
        </div>
      </div>

      {/* SECTION C: Ship It */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-6 shadow-lg">
        <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-indigo-400"></span>
          Section C — Ship It (Git Branch, PR & Gated Merge)
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1">
            <label className="text-xs font-mono text-slate-400">Feature Branch Name</label>
            <input
              type="text"
              value={branchName}
              onChange={(e) => setBranchName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs font-mono text-slate-400">Commit Message</label>
            <input
              type="text"
              value={commitMsg}
              onChange={(e) => setCommitMsg(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs font-mono text-slate-400">PR Title</label>
            <input
              type="text"
              value={prTitle}
              onChange={(e) => setPrTitle(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs font-mono text-slate-400">PR Description</label>
            <input
              type="text"
              value={prDesc}
              onChange={(e) => setPrDesc(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-4 pt-2">
          <button
            onClick={handleCreatePR}
            disabled={loadingAction !== null}
            className="px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-slate-100 font-semibold text-xs transition-all shadow-md cursor-pointer disabled:opacity-50"
          >
            {loadingAction === 'create-pr' ? 'Opening PR...' : '1. Push Branch & Create PR'}
          </button>

          {createdPrUrl && (
            <div className="flex items-center gap-3">
              <a
                href={createdPrUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs font-mono text-sky-400 hover:underline flex items-center gap-1"
              >
                View PR on GitHub ↗
              </a>

              <button
                onClick={handleMergePR}
                disabled={loadingAction !== null || isPrMerged}
                className={`px-5 py-2.5 rounded-xl text-xs font-semibold transition-all shadow-md cursor-pointer ${
                  isPrMerged
                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    : 'bg-emerald-600 hover:bg-emerald-500 text-slate-950'
                }`}
              >
                {isPrMerged ? 'Merged to Main (CD Deploying)' : '2. Merge PR (Gated by CI Pass)'}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* SECTION D: Rollback */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-6 shadow-lg">
        <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-400"></span>
          Section D — Production Emergency Rollback
        </h3>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4 max-w-xl">
          <select
            value={selectedRuleId}
            onChange={(e) => setSelectedRuleId(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-100 flex-1 focus:outline-none focus:ring-1 focus:ring-rose-500"
          >
            <option value="c8b31a89-2917-4d92-93d3-0570b5550a18">
              c8b31a89-2917-4d92-93d3-0570b5550a18 (PowerShell Encoded Command)
            </option>
          </select>

          <button
            onClick={handleRollback}
            disabled={loadingAction !== null}
            className="px-5 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-slate-100 font-semibold text-xs transition-all shadow-md cursor-pointer disabled:opacity-50 whitespace-nowrap"
          >
            {loadingAction === 'rollback' ? 'Rolling back...' : 'Rollback Rule'}
          </button>
        </div>
      </div>
    </div>
  );
}
