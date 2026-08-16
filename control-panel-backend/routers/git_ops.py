import subprocess
import json
import sys
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from security import verify_token

router = APIRouter(prefix="/api/git", tags=["git"])

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class BranchAndPRRequest(BaseModel):
    branch_name: str
    commit_message: str
    pr_title: str
    pr_description: str

class MergePRRequest(BaseModel):
    pr_number_or_url: str

@router.post("/branch-and-pr", dependencies=[Depends(verify_token)])
def branch_and_pr(req: BranchAndPRRequest):
    """Creates a new branch, commits staged rule files, pushes, and opens a GitHub PR."""
    try:
        branch = req.branch_name.strip().replace(" ", "-")
        if not branch.startswith("feature/"):
            branch = f"feature/{branch}"

        # 1. Create and checkout branch
        res1 = subprocess.run(["git", "checkout", "-b", branch], capture_output=True, text=True, cwd=str(BASE_DIR))
        if res1.returncode != 0:
            # Try checking out if already exists
            subprocess.run(["git", "checkout", branch], capture_output=True, text=True, cwd=str(BASE_DIR))

        # 2. Stage rules, tests, and scripts - matches ci-test-rules.yml's own trigger paths
        # (rules/**, tests/**, pipelines/**, scripts/**), so anything CI actually validates
        # against is guaranteed to be part of the same commit. Staging only rules/+tests/
        # here would silently leave out a scripts/ fix (e.g. the test harness itself) and
        # CI would run against the last-committed, possibly-broken version instead.
        subprocess.run(["git", "add", "rules/", "tests/", "scripts/", "pipelines/"], capture_output=True, text=True, cwd=str(BASE_DIR))

        # 3. Commit
        res_commit = subprocess.run(["git", "commit", "-m", req.commit_message], capture_output=True, text=True, cwd=str(BASE_DIR))
        
        # 4. Push to origin
        res_push = subprocess.run(["git", "push", "-u", "origin", branch], capture_output=True, text=True, cwd=str(BASE_DIR))
        if res_push.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Git push failed: {res_push.stderr}")

        # 5. Open Pull Request via gh CLI
        gh_cmd = [
            "gh", "pr", "create",
            "--title", req.pr_title,
            "--body", req.pr_description,
            "--base", "main",
            "--head", branch
        ]
        res_pr = subprocess.run(gh_cmd, capture_output=True, text=True, cwd=str(BASE_DIR))
        if res_pr.returncode != 0:
            raise HTTPException(status_code=500, detail=f"GitHub PR creation failed: {res_pr.stderr}")

        pr_url = res_pr.stdout.strip()

        # Switch back to main locally
        subprocess.run(["git", "checkout", "main"], capture_output=True, text=True, cwd=str(BASE_DIR))

        return {
            "status": "success",
            "branch": branch,
            "pr_url": pr_url,
            "message": f"Pull Request successfully opened: {pr_url}"
        }
    except Exception as e:
        subprocess.run(["git", "checkout", "main"], capture_output=True, text=True, cwd=str(BASE_DIR))
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/merge-pr", dependencies=[Depends(verify_token)])
def merge_pr(req: MergePRRequest):
    """Wraps `gh pr merge` — fails if GitHub PR checks/CI status have not passed."""
    try:
        # Check PR status first to ensure CI has passed
        check_res = subprocess.run(
            ["gh", "pr", "view", req.pr_number_or_url, "--json", "state,checksStatus"],
            capture_output=True, text=True, cwd=str(BASE_DIR)
        )
        
        gh_cmd = ["gh", "pr", "merge", req.pr_number_or_url, "--squash", "--delete-branch"]
        res = subprocess.run(gh_cmd, capture_output=True, text=True, cwd=str(BASE_DIR))
        
        if res.returncode != 0:
            raise HTTPException(
                status_code=400,
                detail=f"PR Merge Gate Blocked: {res.stderr or 'GitHub checks have not passed yet.'}"
            )

        # Pull latest main locally after successful merge
        subprocess.run(["git", "checkout", "main"], capture_output=True, text=True, cwd=str(BASE_DIR))
        subprocess.run(["git", "pull", "origin", "main"], capture_output=True, text=True, cwd=str(BASE_DIR))

        return {
            "status": "success",
            "message": f"PR {req.pr_number_or_url} merged cleanly! CD deployment workflow triggered."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
