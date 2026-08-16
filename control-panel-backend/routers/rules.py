import subprocess
import os
import sys
import json
import yaml
from pathlib import Path
from typing import AsyncGenerator
from fastapi import APIRouter, Depends, HTTPException, Header, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from security import verify_token, read_token

router = APIRouter(prefix="/api/rules", tags=["rules"])

BASE_DIR = Path(__file__).resolve().parent.parent.parent
RULES_DIR = BASE_DIR / "rules"
TESTS_DIR = BASE_DIR / "tests"
MANIFEST_FILE = TESTS_DIR / "manifest.yml"

SCRIPTS_DIR = BASE_DIR / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
from fetch_reference_samples import KNOWN_TECHNIQUE_MAP

class SaveRuleRequest(BaseModel):
    title: str
    technique_id: str
    rule_slug: str
    rule_yaml: str
    tp_json: str
    fp_json: str

class FetchSamplesRequest(BaseModel):
    technique_id: str
    rule_slug: str

class RollbackRequest(BaseModel):
    rule_id: str

class CaptureStopRequest(BaseModel):
    start_time: str

class BoundaryVariantRequest(BaseModel):
    rule_slug: str
    rule_yaml: str
    tp_json: str

def get_python_bin() -> str:
    venv_py = BASE_DIR / "venv" / "Scripts" / "python.exe"
    if venv_py.exists():
        return str(venv_py)
    return sys.executable

def stream_script_output(script_path: str, extra_args: list = None) -> AsyncGenerator[str, None]:
    """Runs a python script and yields lines in Server-Sent Events (SSE) format."""
    python_bin = get_python_bin()
    cmd = [python_bin, str(script_path)] + (extra_args or [])
    
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=str(BASE_DIR)
    )

    for line in iter(process.stdout.readline, ''):
        if line:
            yield f"data: {json.dumps({'line': line.strip()})}\n\n"
    
    process.stdout.close()
    return_code = process.wait()
    status = "SUCCESS" if return_code == 0 else "FAILED"
    yield f"data: {json.dumps({'status': status, 'exit_code': return_code})}\n\n"

def check_token_query_or_header(x_detectforge_token: str = Header(None, alias="X-DetectForge-Token"), token: str = Query(None)):
    expected = read_token()
    provided = x_detectforge_token or token
    if not provided or provided != expected:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid or missing security token")

@router.get("/lint/stream")
async def lint_rules_stream(auth: None = Depends(check_token_query_or_header)):
    """Runs lint_rules.py and streams live console output via SSE."""
    script = BASE_DIR / "scripts" / "lint_rules.py"
    return StreamingResponse(stream_script_output(script), media_type="text/event-stream")

@router.get("/convert/stream")
async def convert_rules_stream(auth: None = Depends(check_token_query_or_header)):
    """Runs convert_rules.py and streams live console output via SSE."""
    script = BASE_DIR / "scripts" / "convert_rules.py"
    return StreamingResponse(stream_script_output(script), media_type="text/event-stream")

@router.get("/test/stream")
async def test_rules_stream(auth: None = Depends(check_token_query_or_header)):
    """Runs test_harness.py and streams live console output via SSE.

    --es-url is required by the script (no fake local fallback, on purpose - see the
    fix history on test_harness.py), but was never actually being passed here, so this
    button always failed with an argparse error rather than running any real test.
    """
    script = BASE_DIR / "scripts" / "test_harness.py"
    return StreamingResponse(
        stream_script_output(script, extra_args=["--es-url", "https://localhost:9200"]),
        media_type="text/event-stream"
    )

@router.get("/known-techniques")
def known_techniques():
    """Lists techniques with a real curated reference sample, so the UI can offer a
    picker instead of a blind free-text field that silently falls back to a placeholder
    for anything not actually supported.

    Also surfaces the curated sample's Image path, so the frontend can regenerate a
    starter Sigma rule matching whatever technique was actually picked. Previously
    selecting a technique only updated the rule slug and fetched a TP sample, leaving
    the Sigma YAML editor showing whatever rule was last loaded (often the unrelated
    default template) - so the saved rule's title/tags/detection logic could describe
    a completely different technique than the TP/FP samples next to it.
    """
    result = []
    for tid, data in KNOWN_TECHNIQUE_MAP.items():
        sample_image = data.get("fallback_sample", {}).get("EventData", {}).get("Image", "")
        result.append({
            "technique_id": tid,
            "slug": data["slug"],
            "display_name": data.get("display_name", tid),
            "tactic": data.get("tactic", ""),
            "sample_image": sample_image
        })
    return result

@router.post("/fetch-samples", dependencies=[Depends(verify_token)])
def fetch_samples(req: FetchSamplesRequest):
    """Executes fetch_reference_samples.py to pull reference telemetry samples.

    This script only ever produces a true-positive sample - it has no false-positive
    logic at all - so the response intentionally omits fp_json rather than returning a
    placeholder that would silently overwrite whatever the user already has in the FP
    editor.
    """
    script = BASE_DIR / "scripts" / "fetch_reference_samples.py"
    cmd = [get_python_bin(), str(script), "--technique", req.technique_id, "--rule-slug", req.rule_slug]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(BASE_DIR), timeout=30)

        tp_path = TESTS_DIR / "true_positive" / req.rule_slug / f"{req.technique_id.lower().replace('.','_')}_sample_1.json"
        tp_content = tp_path.read_text(encoding="utf-8") if tp_path.exists() else None
        if tp_content is None:
            raise HTTPException(status_code=500, detail=f"Fetch script did not produce a sample file. Output:\n{res.stdout}\n{res.stderr}")

        is_placeholder = '"placeholder": true' in tp_content

        return {
            "status": "success",
            "message": res.stdout,
            "tp_json": tp_content,
            "is_placeholder": is_placeholder
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/save", dependencies=[Depends(verify_token)])
def save_rule(req: SaveRuleRequest):
    """Saves rule YAML, TP/FP JSONs, and updates tests/manifest.yml without corruption."""
    try:
        # 1. Parse and validate YAML structure
        parsed_rule = yaml.safe_load(req.rule_yaml)
        if not isinstance(parsed_rule, dict) or "title" not in parsed_rule or "id" not in parsed_rule:
            raise HTTPException(status_code=400, detail="Invalid Sigma YAML: title and id required")
        
        rule_slug = req.rule_slug.strip().lower().replace(" ", "_")
        
        # Determine category / subfolder
        logsource = parsed_rule.get("logsource", {})
        category = logsource.get("category", "process_creation")
        product = logsource.get("product", "windows")
        
        rule_rel_path = f"rules/{product}/{category}/proc_{rule_slug}.yml"
        rule_full_path = BASE_DIR / rule_rel_path
        rule_full_path.parent.mkdir(parents=True, exist_ok=True)
        rule_full_path.write_text(req.rule_yaml, encoding="utf-8")

        # 2. Save True Positive & False Positive JSONs
        tp_dir = TESTS_DIR / "true_positive" / rule_slug
        fp_dir = TESTS_DIR / "false_positive" / rule_slug
        tp_dir.mkdir(parents=True, exist_ok=True)
        fp_dir.mkdir(parents=True, exist_ok=True)

        tech_clean = req.technique_id.lower().replace(".", "_")
        tp_rel_path = f"tests/true_positive/{rule_slug}/{tech_clean}_sample_1.json"
        fp_rel_path = f"tests/false_positive/{rule_slug}/legitimate_sample.json"

        (BASE_DIR / tp_rel_path).write_text(req.tp_json, encoding="utf-8")
        (BASE_DIR / fp_rel_path).write_text(req.fp_json, encoding="utf-8")

        # 3. Update tests/manifest.yml safely
        manifest_data = {"rules": []}
        if MANIFEST_FILE.exists():
            try:
                parsed_m = yaml.safe_load(MANIFEST_FILE.read_text(encoding="utf-8"))
                if isinstance(parsed_m, dict) and "rules" in parsed_m:
                    manifest_data = parsed_m
            except Exception:
                pass
        
        # Check if entry already exists in manifest
        existing_index = -1
        for i, entry in enumerate(manifest_data.get("rules", [])):
            if entry.get("slug") == rule_slug or entry.get("rule") == rule_rel_path:
                existing_index = i
                break

        new_entry = {
            "rule": rule_rel_path,
            "slug": rule_slug,
            "true_positive": [tp_rel_path],
            "false_positive": [fp_rel_path]
        }

        if existing_index >= 0:
            manifest_data["rules"][existing_index] = new_entry
        else:
            manifest_data.setdefault("rules", []).append(new_entry)

        MANIFEST_FILE.write_text(yaml.dump(manifest_data, sort_keys=False), encoding="utf-8")

        # 4. Perform real-time policy warning check for missing FP sample
        fp_warning = None
        has_real_fp = False
        try:
            parsed_fp = json.loads(req.fp_json)
            if isinstance(parsed_fp, dict) and "event" in parsed_fp and parsed_fp.get("event", {}).get("EventData"):
                has_real_fp = True
        except Exception:
            pass

        if not has_real_fp:
            fp_warning = "This rule has no real false-positive sample yet — boundary tests alone won't pass CI."

        return {
            "status": "success",
            "message": f"Rule '{parsed_rule.get('title')}' saved and registered in manifest.yml",
            "rule_path": rule_rel_path,
            "warning": fp_warning
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/capture/start", dependencies=[Depends(verify_token)])
def capture_start():
    """Starts live telemetry capture window and returns start timestamp."""
    from datetime import datetime
    start_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    return {"status": "success", "start_time": start_iso}

@router.post("/capture/stop", dependencies=[Depends(verify_token)])
def capture_stop(req: CaptureStopRequest):
    """Queries Sysmon Event 1 logs from start_time to present and formats all matching events."""
    from datetime import datetime
    if sys.platform != "win32":
        # Mock telemetry for non-Windows testing environments
        mock_event = {
            "metadata": {
                "source": "Local-Sysmon-Live-Capture",
                "captured_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            },
            "event": {
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "EventData": {
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "cmd.exe /c echo benign administrative task",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "ParentImage": "C:\\Windows\\explorer.exe"
                }
            }
        }
        return {"status": "success", "events": [mock_event]}

    ps_cmd = f"""
    try {{
        $startTime = [DateTime]::Parse('{req.start_time}')
        $events = Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$startTime}} -ErrorAction SilentlyContinue
        $results = @()
        foreach ($evt in $events) {{
            $xml = [xml]$evt.ToXml()
            $eventData = @{{}}
            foreach ($data in $xml.Event.EventData.Data) {{
                if ($data.Name) {{
                    $eventData[$data.Name] = $data.'#text'
                }}
            }}
            $results += @{{
                metadata = @{{
                    source = "Local-Sysmon-Live-Capture"
                    captured_at = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                }}
                event = @{{
                    EventID = [int]$evt.Id
                    Channel = $evt.LogName
                    EventData = $eventData
                }}
            }}
        }}
        $results | ConvertTo-Json -Depth 5
    }} catch {{
        Write-Output "[]"
    }}
    """
    try:
        res = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, timeout=15)
        raw_out = res.stdout.strip()
        parsed = json.loads(raw_out) if raw_out else []
        if isinstance(parsed, dict):
            parsed = [parsed]
        return {"status": "success", "events": parsed}
    except Exception as e:
        return {"status": "error", "message": str(e), "events": []}

@router.post("/generate-boundary-variant", dependencies=[Depends(verify_token)])
def generate_boundary_variant(req: BoundaryVariantRequest):
    """
    Generates a Boundary Test (Rule Line Check) variant from True Positive sample.
    Saves to tests/boundary_variants/<rule_slug>/ boundary_sample_1.json and registers
    under boundary_variants in manifest.yml (STRICTLY ISOLATED from false_positive).
    """
    try:
        tp_data = json.loads(req.tp_json) if req.tp_json else {}
        
        boundary_event = json.loads(json.dumps(tp_data))
        if "metadata" not in boundary_event:
            boundary_event["metadata"] = {}
        
        boundary_event["metadata"]["sample_type"] = "boundary_variant"
        boundary_event["metadata"]["note"] = "Boundary test — checks where the rule's line is drawn, does not replace a real false positive."

        event_data = boundary_event.get("event", {}).get("EventData", {})
        cleared_field = None
        for field in ["CommandLine", "Image", "ScriptBlockText"]:
            if field in event_data:
                cleared_field = field
                original_val = event_data[field]
                event_data[field] = f"{original_val} --benign-boundary-test"
                break
        
        if cleared_field:
            boundary_event["metadata"]["cleared_field"] = cleared_field

        rule_slug = req.rule_slug.strip().lower().replace(" ", "_")
        boundary_dir = TESTS_DIR / "boundary_variants" / rule_slug
        boundary_dir.mkdir(parents=True, exist_ok=True)

        boundary_file = boundary_dir / "boundary_sample_1.json"
        boundary_rel_path = f"tests/boundary_variants/{rule_slug}/boundary_sample_1.json"
        boundary_file.write_text(json.dumps(boundary_event, indent=2), encoding="utf-8")

        # Register in manifest.yml strictly under boundary_variants (NEVER under false_positive)
        manifest_data = {"rules": []}
        if MANIFEST_FILE.exists():
            try:
                parsed_m = yaml.safe_load(MANIFEST_FILE.read_text(encoding="utf-8"))
                if isinstance(parsed_m, dict) and "rules" in parsed_m:
                    manifest_data = parsed_m
            except Exception:
                pass

        found = False
        for entry in manifest_data.get("rules", []):
            if entry.get("slug") == rule_slug:
                b_list = entry.setdefault("boundary_variants", [])
                if boundary_rel_path not in b_list:
                    b_list.append(boundary_rel_path)
                found = True
                break

        if not found:
            manifest_data.setdefault("rules", []).append({
                "slug": rule_slug,
                "boundary_variants": [boundary_rel_path]
            })

        MANIFEST_FILE.write_text(yaml.dump(manifest_data, sort_keys=False), encoding="utf-8")

        return {
            "status": "success",
            "message": f"Boundary variant saved to {boundary_rel_path}",
            "boundary_json": json.dumps(boundary_event, indent=2),
            "boundary_path": boundary_rel_path
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/rollback", dependencies=[Depends(verify_token)])
def rollback_rule(req: RollbackRequest):
    """Executes rollback_rule.py to deactivate/delete a deployed monitor in Wazuh."""
    script = BASE_DIR / "scripts" / "rollback_rule.py"
    try:
        res = subprocess.run(
            [get_python_bin(), str(script), "--rule-id", req.rule_id],
            capture_output=True, text=True, cwd=str(BASE_DIR), timeout=30
        )
        if res.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Rollback failed: {res.stderr or res.stdout}")
        return {"status": "success", "message": res.stdout}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
