import subprocess
import urllib.request
import ssl
import json
import os
import sys
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from security import verify_token

router = APIRouter(prefix="/api", tags=["status"])

BASE_DIR = Path(__file__).resolve().parent.parent.parent
LAB_COMPOSE_FILE = BASE_DIR / "lab" / "docker-compose.yml"

@router.get("/status")
def get_system_status():
    """Checks SIEM container status, Indexer API, and GitHub Actions runner status."""
    containers = {"indexer": "offline", "manager": "offline", "dashboard": "offline"}
    
    # 1. Check Docker container state via docker ps
    try:
        res = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        if res.returncode == 0:
            running = res.stdout.strip().split("\n")
            for name in running:
                if "indexer" in name.lower():
                    containers["indexer"] = "online"
                elif "manager" in name.lower():
                    containers["manager"] = "online"
                elif "dashboard" in name.lower():
                    containers["dashboard"] = "online"
    except Exception as e:
        pass

    # 2. Check Indexer API direct connectivity on 9200
    indexer_api = False
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            "https://localhost:9200",
            headers={"Authorization": "Basic YWRtaW46U2VjcmV0UGFzc3dvcmQ="}
        )
        with urllib.request.urlopen(req, context=ctx, timeout=3) as resp:
            if resp.status == 200:
                indexer_api = True
    except Exception:
        pass

    # 3. Check Self-Hosted Runner Status via GitHub API
    runner_status = "offline"
    token = os.environ.get("GITHUB_TOKEN")
    try:
        # Check running runner process locally or gh CLI
        res = subprocess.run(
            ["gh", "api", "repos/anshwhoo/detectforge/actions/runners"],
            capture_output=True, text=True, timeout=5
        )
        if res.returncode == 0:
            data = json.loads(res.stdout)
            for r in data.get("runners", []):
                if r.get("status") == "online":
                    runner_status = "online"
                    break
    except Exception:
        pass

    # 4. Check Sysmon Service Status
    sysmon_status = "not_installed"
    try:
        if sys.platform == "win32":
            svc_res = subprocess.run(
                ["powershell", "-Command", "Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running'"],
                capture_output=True, text=True, timeout=5
            )
            # Note: PowerShell sets returncode=1 whenever one of the two service
            # names doesn't exist, even with -ErrorAction SilentlyContinue - so the
            # exit code can't be trusted here. Matching stdout content is reliable
            # because the pipeline already filters to Status -eq 'Running'.
            if "Running" in svc_res.stdout:
                sysmon_status = "installed"
    except Exception:
        pass

    return {
        "containers": containers,
        "indexer_api": "online" if indexer_api else "offline",
        "runner": runner_status,
        "sysmon": sysmon_status
    }

@router.post("/sysmon/install", dependencies=[Depends(verify_token)])
def sysmon_install():
    """Installs Sysmon with SwiftOnSecurity configuration if not present."""
    if sys.platform != "win32":
        raise HTTPException(status_code=400, detail="Sysmon installation is only supported on Windows host environments")

    ps_script = """
    $ErrorActionPreference = 'Stop'
    $existing = Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running'
    if ($existing) {
        Write-Output "Sysmon is already installed and running."
        exit 0
    }
    $workDir = Join-Path $env:TEMP 'sysmon_installer'
    New-Item -ItemType Directory -Force -Path $workDir | Out-Null
    
    # Download SwiftOnSecurity config
    $configPath = Join-Path $workDir 'sysmonconfig-export.xml'
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile $configPath
    
    # Check for local Sysmon64.exe or download zip
    $sysmonExe = Join-Path $workDir 'Sysmon64.exe'
    if (-not (Test-Path $sysmonExe)) {
        $zipPath = Join-Path $workDir 'Sysmon.zip'
        Invoke-WebRequest -Uri 'https://live.sysinternals.com/files/Sysmon.zip' -OutFile $zipPath
        Expand-Archive -Path $zipPath -DestinationPath $workDir -Force
    }
    
    Start-Process -FilePath (Join-Path $workDir 'Sysmon64.exe') -ArgumentList "-i `"$configPath`" -accepteula" -Wait -Verb RunAs
    Write-Output "Sysmon installation complete."
    """
    try:
        res = subprocess.run(["powershell", "-Command", ps_script], capture_output=True, text=True, timeout=60)
        if res.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Sysmon install script failed: {res.stderr or res.stdout}")
        return {"status": "success", "message": res.stdout.strip() or "Sysmon successfully installed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/docker/up", dependencies=[Depends(verify_token)])
def docker_up():
    """Starts the Wazuh Docker stack."""
    try:
        res = subprocess.run(
            ["docker", "compose", "-f", str(LAB_COMPOSE_FILE), "up", "-d"],
            capture_output=True, text=True, timeout=60, cwd=str(BASE_DIR)
        )
        if res.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Docker Compose failed: {res.stderr}")
        return {"status": "success", "message": "Docker containers started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/docker/down", dependencies=[Depends(verify_token)])
def docker_down():
    """Stops the Wazuh Docker stack."""
    try:
        res = subprocess.run(
            ["docker", "compose", "-f", str(LAB_COMPOSE_FILE), "down"],
            capture_output=True, text=True, timeout=60, cwd=str(BASE_DIR)
        )
        if res.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Docker Compose down failed: {res.stderr}")
        return {"status": "success", "message": "Docker containers stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/runner/start", dependencies=[Depends(verify_token)])
def runner_start():
    """Starts the local GitHub Actions runner."""
    runner_dir = Path(r"C:\actions-runner")
    if not runner_dir.exists():
        raise HTTPException(status_code=404, detail="Runner directory C:\\actions-runner not found")
    
    # Try net start if service installed, else start run.cmd in background
    try:
        svc_res = subprocess.run(["net", "start", "actions.runner.anshwhoo-detectforge.detectforge-local-runner"], capture_output=True, text=True)
        if svc_res.returncode == 0:
            return {"status": "success", "message": "Runner service started via net start"}
    except Exception:
        pass

    try:
        # Launch run.cmd in an elevated window (triggers a UAC prompt). This runner isn't
        # installed as a Windows service (svc.cmd isn't present in this install), so it only
        # ever runs as a plain interactive process - and CI steps that need to write to
        # HKEY_LOCAL_MACHINE (e.g. actions/setup-python's cleanup step) fail with
        # "Requested registry access is not allowed" unless the runner itself is elevated.
        subprocess.Popen([
            "powershell", "-Command",
            "Start-Process powershell -Verb RunAs -ArgumentList "
            "'-NoExit','-Command','Set-Location C:\\actions-runner; .\\run.cmd'"
        ])
        return {"status": "success", "message": "Runner process launched"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/runner/stop", dependencies=[Depends(verify_token)])
def runner_stop():
    """Stops the local GitHub Actions runner."""
    try:
        # Try service stop
        subprocess.run(["net", "stop", "actions.runner.anshwhoo-detectforge.detectforge-local-runner"], capture_output=True, text=True)
        # Kill runner process if running as task
        subprocess.run(["taskkill", "/F", "/IM", "Runner.Listener.exe"], capture_output=True, text=True)
        return {"status": "success", "message": "Runner stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
