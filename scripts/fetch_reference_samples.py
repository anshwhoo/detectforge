#!/usr/bin/env python3
"""
DetectForge Reference Sample Fetcher & Curator
Pulls true-positive security event samples from OTRF Security Datasets (Mordor)
or EVTX-ATTACK-SAMPLES based on MITRE ATT&CK technique ID, and normalizes them
into JSON format for the test corpus under tests/true_positive/<rule_slug>/.
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any, Optional

# Curated, technique-accurate samples. OTRF Security-Datasets stopped publishing
# per-technique raw JSON files (their repo now ships mixed-event-type .zip archives
# instead), so live fetching against them is no longer reliable - these entries are
# pre-extracted/hand-built from real, cited sources instead of fetched at runtime.
# "otrf_url" is kept only for techniques where a working raw-file endpoint is known;
# it's None where there isn't one, which skips the network attempt entirely.
KNOWN_TECHNIQUE_MAP = {
    "T1059.001": {
        "slug": "powershell_encoded_command",
        "display_name": "PowerShell Encoded Command",
        "tactic": "execution",
        "otrf_url": None,
        "source_ref": "DetectForge curated sample (OTRF Security-Datasets raw-file endpoints are no longer available)",
        "fallback_sample": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-07-22T00:15:30.123456Z",
            "Computer": "WORKSTATION01.CORP.LOCAL",
            "Security": {"UserID": "S-1-5-21-123456789-987654321-1001"},
            "EventData": {
                "UtcTime": "2026-07-22 00:15:30.123",
                "ProcessGuid": "{A1234567-89AB-CDEF-0000-001000000000}",
                "ProcessId": 4820,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -NoProfile -NonInteractive -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFNAdAByAGUAYQBtAA==",
                "CurrentDirectory": "C:\\Users\\victim\\",
                "User": "CORP\\victim",
                "LogonGuid": "{A1234567-89AB-CDEF-0000-002000000000}",
                "LogonId": "0x3e7",
                "TerminalSessionId": 1,
                "IntegrityLevel": "Medium",
                "Hashes": "SHA256=9DB6D0A9491F79A5E81A4384B6F77B08B81559C3C240E8A3EA532C6E87560B0E",
                "ParentProcessGuid": "{A1234567-89AB-CDEF-0000-001000000001}",
                "ParentProcessId": 3104,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe /c start_payload.bat"
            }
        }
    },
    "T1053.005": {
        "slug": "scheduled_task_creation",
        "display_name": "Scheduled Task Creation",
        "tactic": "persistence",
        "otrf_url": None,
        "source_ref": "Atomic Red Team T1053.005 test 'Scheduled task Local' "
                       "(GUID 42f53695-ad4a-4546-abb6-7d837f644a71) - "
                       "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md",
        "fallback_sample": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-08-12T20:10:04.418000Z",
            "Computer": "WORKSTATION03.CORP.LOCAL",
            "Security": {"UserID": "S-1-5-21-123456789-987654321-1002"},
            "EventData": {
                "UtcTime": "2026-08-12 20:10:04.418",
                "ProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000010}",
                "ProcessId": 5896,
                "Image": "C:\\Windows\\System32\\schtasks.exe",
                "CommandLine": "schtasks.exe /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10",
                "CurrentDirectory": "C:\\Users\\victim\\",
                "User": "CORP\\victim",
                "LogonGuid": "{B2345678-9ABC-DEF0-0000-002000000010}",
                "LogonId": "0x3e7",
                "TerminalSessionId": 1,
                "IntegrityLevel": "Medium",
                "ParentProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000009}",
                "ParentProcessId": 4412,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe"
            }
        }
    },
    "T1059.003": {
        "slug": "windows_command_shell",
        "display_name": "Windows Command Shell",
        "tactic": "execution",
        "otrf_url": None,
        "source_ref": "Atomic Red Team T1059.003 test 'Writes text to a file and displays it.' "
                       "(GUID 127b4afe-2346-4192-815c-69042bec570e) - "
                       "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md",
        "fallback_sample": {
            "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-08-12T20:11:12.201000Z", "Computer": "WORKSTATION03.CORP.LOCAL",
            "Security": {"UserID": "S-1-5-21-123456789-987654321-1002"},
            "EventData": {
                "UtcTime": "2026-08-12 20:11:12.201", "ProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000011}", "ProcessId": 5910,
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c echo \"Hello from the Windows Command Prompt!\" > \"%TEMP%\\test.bin\" & type \"%TEMP%\\test.bin\"",
                "CurrentDirectory": "C:\\Users\\victim\\", "User": "CORP\\victim", "LogonGuid": "{B2345678-9ABC-DEF0-0000-002000000010}",
                "LogonId": "0x3e7", "TerminalSessionId": 1, "IntegrityLevel": "Medium",
                "ParentProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000009}", "ParentProcessId": 4412,
                "ParentImage": "C:\\Windows\\System32\\explorer.exe", "ParentCommandLine": "explorer.exe"
            }
        }
    },
    "T1204.002": {
        "slug": "malicious_file",
        "display_name": "Malicious File (Macro Execution)",
        "tactic": "execution",
        "otrf_url": None,
        "source_ref": "Atomic Red Team T1204.002 test 'OSTap Style Macro Execution' "
                       "(GUID 8bebc690-18c7-4549-bc98-210f7019efff, TrickBot OSTap downloader chain) - "
                       "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md",
        "fallback_sample": {
            "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-08-12T20:12:03.884000Z", "Computer": "WORKSTATION04.CORP.LOCAL",
            "Security": {"UserID": "S-1-5-21-123456789-987654321-1003"},
            "EventData": {
                "UtcTime": "2026-08-12 20:12:03.884", "ProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000012}", "ProcessId": 6102,
                "Image": "C:\\Windows\\System32\\wscript.exe",
                "CommandLine": "wscript.exe C:\\Users\\Public\\art.jse",
                "CurrentDirectory": "C:\\Users\\Public\\", "User": "CORP\\victim2", "LogonGuid": "{B2345678-9ABC-DEF0-0000-002000000011}",
                "LogonId": "0x4a1", "TerminalSessionId": 1, "IntegrityLevel": "Medium",
                "ParentProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000008}", "ParentProcessId": 3388,
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "ParentCommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" invoice.docm"
            }
        }
    },
    "T1547.001": {
        "slug": "registry_run_keys",
        "display_name": "Registry Run Keys",
        "tactic": "persistence",
        "otrf_url": None,
        "source_ref": "Atomic Red Team T1547.001 test 'Reg Key Run' "
                       "(GUID e55be3fd-3521-4610-9d1a-e210e42dcf05) - "
                       "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md",
        "fallback_sample": {
            "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-08-12T20:13:45.552000Z", "Computer": "WORKSTATION03.CORP.LOCAL",
            "Security": {"UserID": "S-1-5-21-123456789-987654321-1002"},
            "EventData": {
                "UtcTime": "2026-08-12 20:13:45.552", "ProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000013}", "ProcessId": 5934,
                "Image": "C:\\Windows\\System32\\reg.exe",
                "CommandLine": "REG ADD \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /V \"Atomic Red Team\" /t REG_SZ /F /D \"C:\\Path\\AtomicRedTeam.exe\"",
                "CurrentDirectory": "C:\\Users\\victim\\", "User": "CORP\\victim", "LogonGuid": "{B2345678-9ABC-DEF0-0000-002000000010}",
                "LogonId": "0x3e7", "TerminalSessionId": 1, "IntegrityLevel": "Medium",
                "ParentProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000009}", "ParentProcessId": 4412,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentCommandLine": "cmd.exe"
            }
        }
    },
    "T1548.002": {
        "slug": "bypass_uac",
        "display_name": "Bypass UAC",
        "tactic": "privilege-escalation",
        "otrf_url": None,
        "source_ref": "Atomic Red Team T1548.002 test 'Bypass UAC using Event Viewer (cmd)' "
                       "(GUID 5073adf8-9a50-4bd9-b298-a9bd2ead8af9) - "
                       "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md",
        "fallback_sample": {
            "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-08-12T20:14:22.117000Z", "Computer": "WORKSTATION05.CORP.LOCAL",
            "Security": {"UserID": "S-1-5-21-123456789-987654321-1004"},
            "EventData": {
                "UtcTime": "2026-08-12 20:14:22.117", "ProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000014}", "ProcessId": 6220,
                "Image": "C:\\Windows\\System32\\reg.exe",
                "CommandLine": "reg.exe add hkcu\\software\\classes\\mscfile\\shell\\open\\command /ve /d \"C:\\Windows\\System32\\cmd.exe\" /f",
                "CurrentDirectory": "C:\\Users\\victim3\\", "User": "CORP\\victim3", "LogonGuid": "{B2345678-9ABC-DEF0-0000-002000000012}",
                "LogonId": "0x5b2", "TerminalSessionId": 1, "IntegrityLevel": "Medium",
                "ParentProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000007}", "ParentProcessId": 3120,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentCommandLine": "cmd.exe"
            }
        }
    },
    "T1027": {
        "slug": "obfuscated_files",
        "display_name": "Obfuscated Files (Certutil Decode)",
        "tactic": "defense-evasion",
        "otrf_url": None,
        "source_ref": "MITRE ATT&CK T1027 documented example - certutil.exe base64 -decode LOLBin pattern "
                       "(same technique family as Atomic Red Team T1027 GUID e68b945c-52d0-4dd9-a5e8-d173d70c448f) - "
                       "https://attack.mitre.org/techniques/T1027/",
        "fallback_sample": {
            "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-08-12T20:15:09.663000Z", "Computer": "WORKSTATION03.CORP.LOCAL",
            "Security": {"UserID": "S-1-5-21-123456789-987654321-1002"},
            "EventData": {
                "UtcTime": "2026-08-12 20:15:09.663", "ProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000015}", "ProcessId": 5978,
                "Image": "C:\\Windows\\System32\\certutil.exe",
                "CommandLine": "certutil.exe -decode C:\\Users\\Public\\payload.b64 C:\\Users\\Public\\payload.exe",
                "CurrentDirectory": "C:\\Users\\Public\\", "User": "CORP\\victim", "LogonGuid": "{B2345678-9ABC-DEF0-0000-002000000010}",
                "LogonId": "0x3e7", "TerminalSessionId": 1, "IntegrityLevel": "Medium",
                "ParentProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000009}", "ParentProcessId": 4412,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentCommandLine": "cmd.exe"
            }
        }
    },
    "T1112": {
        "slug": "modify_registry",
        "display_name": "Modify Registry (SecurityHealth)",
        "tactic": "defense-evasion",
        "otrf_url": None,
        "source_ref": "Atomic Red Team T1112 test 'Modify Registry of Local Machine - cmd' "
                       "(GUID 282f929a-6bc5-42b8-bd93-960c3ba35afe) - "
                       "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md",
        "fallback_sample": {
            "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-08-12T20:16:30.442000Z", "Computer": "WORKSTATION05.CORP.LOCAL",
            "Security": {"UserID": "S-1-5-21-123456789-987654321-1004"},
            "EventData": {
                "UtcTime": "2026-08-12 20:16:30.442", "ProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000016}", "ProcessId": 6244,
                "Image": "C:\\Windows\\System32\\reg.exe",
                "CommandLine": "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /t REG_EXPAND_SZ /v SecurityHealth /d calc.exe /f",
                "CurrentDirectory": "C:\\Users\\victim3\\", "User": "CORP\\victim3", "LogonGuid": "{B2345678-9ABC-DEF0-0000-002000000012}",
                "LogonId": "0x5b2", "TerminalSessionId": 1, "IntegrityLevel": "High",
                "ParentProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000007}", "ParentProcessId": 3120,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentCommandLine": "cmd.exe"
            }
        }
    },
    "T1003.001": {
        "slug": "lsass_memory_dump",
        "display_name": "LSASS Memory Dump",
        "tactic": "credential-access",
        "otrf_url": None,
        "source_ref": "Atomic Red Team T1003.001 test 'Dump LSASS.exe Memory using ProcDump' "
                       "(GUID 0be2230c-9ab3-4ac2-8826-3199b9a0ebf8) - "
                       "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md",
        "fallback_sample": {
            "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-08-12T20:17:51.229000Z", "Computer": "WORKSTATION04.CORP.LOCAL",
            "Security": {"UserID": "S-1-5-21-123456789-987654321-1003"},
            "EventData": {
                "UtcTime": "2026-08-12 20:17:51.229", "ProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000017}", "ProcessId": 6318,
                "Image": "C:\\Users\\Public\\procdump64.exe",
                "CommandLine": "procdump64.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass_dump.dmp",
                "CurrentDirectory": "C:\\Users\\Public\\", "User": "CORP\\victim2", "LogonGuid": "{B2345678-9ABC-DEF0-0000-002000000011}",
                "LogonId": "0x4a1", "TerminalSessionId": 1, "IntegrityLevel": "High",
                "ParentProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000008}", "ParentProcessId": 3388,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentCommandLine": "cmd.exe"
            }
        }
    },
    "T1082": {
        "slug": "system_information_discovery",
        "display_name": "System Information Discovery",
        "tactic": "discovery",
        "otrf_url": None,
        "source_ref": "Atomic Red Team T1082 test 'System Information Discovery' "
                       "(GUID 66703791-c902-4560-8770-42b8a91f7667) - "
                       "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md",
        "fallback_sample": {
            "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-08-12T20:18:14.017000Z", "Computer": "WORKSTATION03.CORP.LOCAL",
            "Security": {"UserID": "S-1-5-21-123456789-987654321-1002"},
            "EventData": {
                "UtcTime": "2026-08-12 20:18:14.017", "ProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000018}", "ProcessId": 5996,
                "Image": "C:\\Windows\\System32\\systeminfo.exe",
                "CommandLine": "systeminfo.exe",
                "CurrentDirectory": "C:\\Users\\victim\\", "User": "CORP\\victim", "LogonGuid": "{B2345678-9ABC-DEF0-0000-002000000010}",
                "LogonId": "0x3e7", "TerminalSessionId": 1, "IntegrityLevel": "Medium",
                "ParentProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000009}", "ParentProcessId": 4412,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentCommandLine": "cmd.exe"
            }
        }
    },
    "T1021.001": {
        "slug": "remote_desktop_protocol",
        "display_name": "RDP to Domain Controller",
        "tactic": "lateral-movement",
        "otrf_url": None,
        "source_ref": "Atomic Red Team T1021.001 test 'RDP to DomainController' "
                       "(GUID 355d4632-8cb9-449d-91ce-b566d0253d3e) - "
                       "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md",
        "fallback_sample": {
            "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-08-12T20:19:37.905000Z", "Computer": "WORKSTATION04.CORP.LOCAL",
            "Security": {"UserID": "S-1-5-21-123456789-987654321-1003"},
            "EventData": {
                "UtcTime": "2026-08-12 20:19:37.905", "ProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000019}", "ProcessId": 6402,
                "Image": "C:\\Windows\\System32\\mstsc.exe",
                "CommandLine": "mstsc.exe /v:dc01.corp.local",
                "CurrentDirectory": "C:\\Users\\victim2\\", "User": "CORP\\victim2", "LogonGuid": "{B2345678-9ABC-DEF0-0000-002000000011}",
                "LogonId": "0x4a1", "TerminalSessionId": 1, "IntegrityLevel": "Medium",
                "ParentProcessGuid": "{B2345678-9ABC-DEF0-0000-001000000008}", "ParentProcessId": 3388,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentCommandLine": "cmd.exe"
            }
        }
    }
}

def fetch_json_from_url(url: str) -> Optional[List[Dict[str, Any]]]:
    """Fetch and parse JSON lines or array from HTTP URL."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'DetectForge-Fetcher/1.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
            events = []
            for line in content.splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return events if events else None
    except Exception as e:
        print(f"[*] Note: HTTP fetch from {url} failed: {e}", file=sys.stderr)
        return None

def normalize_event(event: Dict[str, Any], technique_id: str, source: str, is_placeholder: bool = False, source_ref: str = None) -> Dict[str, Any]:
    """Normalize raw event into standardized DetectForge test corpus format."""
    metadata = {
        "source": source,
        "technique_id": technique_id,
        "normalized_by": "DetectForge-FetchReferenceSamples",
        "placeholder": is_placeholder
    }
    if source_ref:
        metadata["source_ref"] = source_ref
    if is_placeholder:
        metadata["warning"] = (
            "This is NOT real reference telemetry - the technique has no pre-mapped "
            "sample. Replace this with a hand-crafted or captured event before trusting "
            "it in the test harness."
        )
    normalized = {
        "metadata": metadata,
        "event": event
    }
    return normalized

def main():
    parser = argparse.ArgumentParser(description="Fetch and normalize true-positive samples for Sigma rules.")
    parser.add_argument("--technique", required=True, help="MITRE ATT&CK technique ID (e.g., T1059.001)")
    parser.add_argument("--rule-slug", required=True, help="Rule slug name for folder organization")
    parser.add_argument("--output-dir", default="tests/true_positive", help="Output directory root")
    parser.add_argument("--list-available", action="store_true", help="List available pre-configured techniques")

    args = parser.parse_args()

    if args.list_available:
        print("Available pre-mapped techniques:")
        for tech, data in KNOWN_TECHNIQUE_MAP.items():
            print(f"  - {tech} ({data['slug']})")
        return

    tech_id = args.technique.upper()
    rule_dir = Path(args.output_dir) / args.rule_slug
    rule_dir.mkdir(parents=True, exist_ok=True)

    events = None
    source = "OTRF-Security-Datasets"
    is_placeholder = False
    source_ref = None
    if tech_id in KNOWN_TECHNIQUE_MAP:
        tech_data = KNOWN_TECHNIQUE_MAP[tech_id]
        source_ref = tech_data.get("source_ref")
        if tech_data.get("otrf_url"):
            print(f"[*] Fetching sample for technique {tech_id}...")
            events = fetch_json_from_url(tech_data["otrf_url"])
        if not events:
            print(f"[*] Using curated sample for {tech_id} ({source_ref})")
            events = [tech_data["fallback_sample"]]
            source = "DetectForge-Curated-Sample"
    else:
        print(f"[!] WARNING: Technique {tech_id} is not in the pre-mapped table.")
        print(f"[!] Generating a generic PLACEHOLDER event - this is NOT real reference data.")
        print(f"[!] Replace it with a hand-crafted or captured sample before trusting test results.")
        events = [{
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventData": {
                "CommandLine": f"sample_cmd.exe --technique={tech_id}",
                "Image": "C:\\Windows\\System32\\sample_cmd.exe"
            }
        }]
        source = "DetectForge-Generic-Placeholder"
        is_placeholder = True

    output_file = rule_dir / f"{tech_id.lower().replace('.', '_')}_sample_1.json"
    normalized_data = [normalize_event(ev, tech_id, source, is_placeholder, source_ref) for ev in events[:5]]

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(normalized_data[0] if len(normalized_data) == 1 else normalized_data, f, indent=2)

    print(f"[+] Successfully saved sample to {output_file}")

if __name__ == "__main__":
    main()
