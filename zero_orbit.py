#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZERO-ORBIT — Autonomous Web Attack-Surface & Resilience Analyzer
Main CLI / Orchestration layer.

Authorized testing only. Scope enforcement is mandatory.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

VERSION = "1.0.0"
BASE = Path(__file__).resolve().parent
CONFIG_DIR = BASE / "config"
RULES_DIR = BASE / "rules"
REPORTS_DIR = BASE / "reports"
BACKUPS_DIR = BASE / "backups"
MODULES_DIR = BASE / "modules"

ORBIT_BIN = BASE / "orbit"
ENGINE_BIN = BASE / "engine"
SHIELD_BIN = BASE / "shield"

RISK_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

BANNER = r"""
   ______          ____       __     _ __
  /__  /  ___     / __ \___  / /_   (_) /_
    / /  / _ \   / / / / _ \/ __/  / / __/
   / /__/  __/  / /_/ /  __/ /_   / / /
  /____/\___/   \____/\___/\__/  /_/\__/

  ZERO-ORBIT v{ver}   —   Map. Test. Repair. Verify.
"""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    id: str
    title: str
    risk: str          # INFO / LOW / MEDIUM / HIGH / CRITICAL
    url: str
    evidence: str = ""
    fix: str = ""
    category: str = "general"
    fixed: bool = False

    @property
    def risk_num(self) -> int:
        try:
            return RISK_LEVELS.index(self.risk) + 1
        except ValueError:
            return 1


@dataclass
class ScanResult:
    target: str
    started: str = ""
    finished: str = ""
    scope: List[str] = field(default_factory=list)
    assets: Dict[str, Any] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    pressure: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def log(msg: str, tag: str = "*") -> None:
    print(f"[{tag}] {msg}")


def ensure_dirs() -> None:
    for d in (CONFIG_DIR, RULES_DIR, REPORTS_DIR, BACKUPS_DIR, MODULES_DIR):
        d.mkdir(parents=True, exist_ok=True)


def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def load_scope() -> List[str]:
    scope_file = CONFIG_DIR / "scope.txt"
    if not scope_file.exists():
        scope_file.write_text(
            "# ZERO-ORBIT scope file\n"
            "# One entry per line. Use *.example.com for wildcards.\n"
            "# Lines starting with # are ignored.\n"
        )
        return []
    entries: List[str] = []
    for line in scope_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line)
    return entries


def save_scope(entries: List[str]) -> None:
    scope_file = CONFIG_DIR / "scope.txt"
    scope_file.write_text("\n".join(entries) + "\n")


def load_settings() -> Dict[str, Any]:
    f = CONFIG_DIR / "settings.json"
    if not f.exists():
        default = {
            "timeout_seconds": 10,
            "max_requests": 200,
            "max_rps": 5,
            "max_concurrency": 4,
            "max_duration": 30,
            "user_agent": f"ZERO-ORBIT/{VERSION} (authorized-testing)",
        }
        f.write_text(json.dumps(default, indent=2))
        return default
    return json.loads(f.read_text())


def save_settings(s: Dict[str, Any]) -> None:
    (CONFIG_DIR / "settings.json").write_text(json.dumps(s, indent=2))


# ---------------------------------------------------------------------------
# Shield (Rust) — scope + rate-limit checks
# ---------------------------------------------------------------------------
def shield_check(target: str, scope: List[str]) -> bool:
    """Call the Rust shield binary to validate target against scope."""
    if not SHIELD_BIN.exists():
        # Fallback pure-python check
        return _py_scope_check(target, scope)
    try:
        proc = subprocess.run(
            [str(SHIELD_BIN), "check", "--target", target],
            input="\n".join(scope),
            text=True, capture_output=True, timeout=5,
        )
        if proc.returncode != 0:
            log(f"SCOPE BLOCKED → {target}", "!")
            if proc.stderr.strip():
                log(proc.stderr.strip(), "!")
            return False
        return True
    except Exception as e:
        log(f"shield error: {e}; falling back to python check", "!")
        return _py_scope_check(target, scope)


def _py_scope_check(target: str, scope: List[str]) -> bool:
    host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    for entry in scope:
        e = entry.lower().strip()
        if not e:
            continue
        if e == host:
            return True
        if e.startswith("*."):
            suffix = e[2:]
            if host == suffix or host.endswith("." + suffix):
                return True
    return False


# ---------------------------------------------------------------------------
# Go engine (orbit) — discovery / scan / pressure
# ---------------------------------------------------------------------------
def call_orbit(mode: str, **kwargs) -> Dict[str, Any]:
    if not ORBIT_BIN.exists():
        return {"error": f"orbit binary not found at {ORBIT_BIN}. Run install.sh"}

    args = [str(ORBIT_BIN), "--mode", mode]
    for k, v in kwargs.items():
        if v is None:
            continue
        args += [f"--{k.replace('_', '-')}", str(v)]

    log(f"orbit {mode}: {' '.join(args[1:])}", ">")
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "orbit timeout"}
    if proc.returncode != 0 and not proc.stdout.strip():
        return {"error": proc.stderr.strip() or "orbit failed"}
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {"error": "invalid JSON from orbit", "raw": proc.stdout[:500]}


# ---------------------------------------------------------------------------
# C++ engine — header / technology analysis
# ---------------------------------------------------------------------------
def call_engine(headers: Dict[str, str], body: str = "") -> Dict[str, Any]:
    if not ENGINE_BIN.exists():
        return {}
    payload = json.dumps({"headers": headers, "body": body[:8192]})
    try:
        proc = subprocess.run(
            [str(ENGINE_BIN), "analyze"],
            input=payload, text=True, capture_output=True, timeout=10,
        )
        return json.loads(proc.stdout or "{}")
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Scanner modules
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("MEDIUM", "Add HSTS header with max-age >= 31536000."),
    "Content-Security-Policy":   ("MEDIUM", "Define a strict Content-Security-Policy."),
    "X-Content-Type-Options":    ("LOW",    "Add 'X-Content-Type-Options: nosniff'."),
    "X-Frame-Options":           ("LOW",    "Add 'X-Frame-Options: DENY' or use CSP frame-ancestors."),
    "Referrer-Policy":           ("LOW",    "Add a Referrer-Policy header."),
    "Permissions-Policy":        ("INFO",   "Add a Permissions-Policy header."),
}

ADMIN_PATHS = ["/admin", "/administrator", "/dashboard", "/manage", "/control", "/login"]


def analyze_headers(target: str, headers: Dict[str, str]) -> List[Finding]:
    findings: List[Finding] = []
    lower = {k.lower(): v for k, v in headers.items()}

    for h, (risk, fix) in SECURITY_HEADERS.items():
        if h.lower() not in lower:
            findings.append(Finding(
                id=f"HDR-{h}",
                title=f"Missing security header: {h}",
                risk=risk, url=target, fix=fix, category="headers",
            ))

    # Cookie analysis
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            vlow = v.lower()
            if "secure" not in vlow:
                findings.append(Finding(
                    "COOKIE-SECURE", "Cookie without Secure flag",
                    "MEDIUM", target, evidence=v[:120],
                    fix="Set Secure flag on cookies.", category="cookies"))
            if "httponly" not in vlow:
                findings.append(Finding(
                    "COOKIE-HTTPONLY", "Cookie without HttpOnly flag",
                    "MEDIUM", target, evidence=v[:120],
                    fix="Set HttpOnly flag on cookies.", category="cookies"))
            if "samesite" not in vlow:
                findings.append(Finding(
                    "COOKIE-SAMESITE", "Cookie without SameSite attribute",
                    "LOW", target, evidence=v[:120],
                    fix="Set SameSite=Lax or Strict.", category="cookies"))

    # Server banner disclosure
    if "server" in lower and any(c.isdigit() for c in lower["server"]):
        findings.append(Finding(
            "INFO-SERVER", "Server banner discloses version",
            "INFO", target, evidence=lower["server"],
            fix="Minimize/omit Server header.", category="info"))

    return findings


def check_https(target: str, result: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    if target.startswith("http://"):
        findings.append(Finding(
            "TLS-MISSING", "Site served over plain HTTP", "HIGH", target,
            fix="Enforce HTTPS and redirect HTTP → HTTPS.", category="tls"))
    return findings


def admin_exposure_findings(base: str, discovered: List[Dict[str, Any]]) -> List[Finding]:
    out: List[Finding] = []
    for ep in discovered:
        url = ep.get("url", "")
        status = ep.get("status", 0)
        if any(url.rstrip("/").endswith(p) for p in ADMIN_PATHS) and status in (200, 401, 403):
            risk = "HIGH" if status == 200 else "MEDIUM"
            out.append(Finding(
                id=f"ADMIN-{url}",
                title=f"Administrative surface exposed ({status})",
                risk=risk, url=url,
                evidence=f"HTTP {status}",
                fix="Restrict admin interfaces to trusted networks and enforce MFA.",
                category="admin",
            ))
    return out


# ---------------------------------------------------------------------------
# Auto-Fix engine
# ---------------------------------------------------------------------------
def backup_file(path: Path) -> Path:
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    backup = BACKUPS_DIR / f"{path.name}.{ts}.bak"
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, backup)
    return backup


def generate_fix_snippets(findings: List[Finding]) -> Dict[str, str]:
    """Return a mapping of {filename: content} describing suggested fixes."""
    snippets: Dict[str, str] = {}

    hdrs = [f for f in findings if f.category == "headers" and not f.fixed]
    if hdrs:
        snippets["nginx-security-headers.conf"] = textwrap.dedent("""\
            # ZERO-ORBIT suggested Nginx security headers
            add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
            add_header X-Content-Type-Options "nosniff" always;
            add_header X-Frame-Options "DENY" always;
            add_header Referrer-Policy "strict-origin-when-cross-origin" always;
            add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
            add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none';" always;
            """)

    cookie_fix = [f for f in findings if f.category == "cookies"]
    if cookie_fix:
        snippets["cookies-hardening.txt"] = (
            "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/\n"
        )

    return snippets


def apply_fix(findings: List[Finding], interactive: bool = True) -> Dict[str, Any]:
    snippets = generate_fix_snippets(findings)
    if not snippets:
        return {"applied": 0, "files": []}

    applied_files: List[str] = []
    for name, content in snippets.items():
        dest = BACKUPS_DIR.parent / "patches" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            backup_file(dest)
        if interactive:
            print(f"\n--- Proposed patch: {name} ---\n{content}")
            ans = input("Apply this patch? [y/N] ").strip().lower()
            if ans != "y":
                continue
        dest.write_text(content)
        applied_files.append(str(dest))

    for f in findings:
        if f.category in ("headers", "cookies"):
            f.fixed = True

    return {"applied": len(applied_files), "files": applied_files}


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
def _risk_summary(findings: List[Finding]) -> Dict[str, int]:
    s = {r: 0 for r in RISK_LEVELS}
    for f in findings:
        s[f.risk] = s.get(f.risk, 0) + 1
    return s


def _overall_risk(findings: List[Finding]) -> int:
    if not findings:
        return 1
    return max(f.risk_num for f in findings)


def write_reports(result: ScanResult) -> Dict[str, str]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    base = REPORTS_DIR / f"zero-orbit-{ts}"

    summary = _risk_summary(result.findings)
    risk = _overall_risk(result.findings)

    data = {
        "tool": "ZERO-ORBIT",
        "version": VERSION,
        "target": result.target,
        "started": result.started,
        "finished": result.finished,
        "scope": result.scope,
        "assets": result.assets,
        "technologies": result.technologies,
        "endpoints": result.endpoints,
        "findings": [asdict(f) for f in result.findings],
        "pressure": result.pressure,
        "risk_summary": summary,
        "overall_risk": f"{risk:02d}/05",
    }

    json_path = base.with_suffix(".json")
    json_path.write_text(json.dumps(data, indent=2))

    txt_path = base.with_suffix(".txt")
    lines = [
        "=" * 60,
        "ZERO-ORBIT SECURITY REPORT",
        "=" * 60,
        f"Target    : {result.target}",
        f"Started   : {result.started}",
        f"Finished  : {result.finished}",
        f"Scope     : {', '.join(result.scope) or '-'}",
        f"Endpoints : {len(result.endpoints)}",
        f"Techs     : {', '.join(result.technologies) or '-'}",
        "-" * 60,
        "FINDINGS",
        "-" * 60,
    ]
    for f in result.findings:
        lines.append(f"[{f.risk:8}] {f.title}  ({f.url})")
        if f.evidence:
            lines.append(f"           evidence: {f.evidence[:140]}")
        if f.fix:
            lines.append(f"           fix: {f.fix}")
    lines += [
        "-" * 60,
        "RISK SUMMARY",
        "-" * 60,
    ]
    for r in RISK_LEVELS:
        lines.append(f"{r:8}: {summary.get(r, 0):02d}")
    lines.append(f"OVERALL RISK SCORE: {risk:02d}/05")
    txt_path.write_text("\n".join(lines))

    html_path = base.with_suffix(".html")
    html_path.write_text(_render_html(data))

    return {"json": str(json_path), "txt": str(txt_path), "html": str(html_path)}


def _render_html(data: Dict[str, Any]) -> str:
    rows = "".join(
        f"<tr class='risk-{f['risk'].lower()}'>"
        f"<td>{f['risk']}</td><td>{f['title']}</td>"
        f"<td>{f['url']}</td><td>{f.get('evidence','')[:80]}</td>"
        f"<td>{f.get('fix','')}</td></tr>"
        for f in data["findings"]
    )
    summary_rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in data["risk_summary"].items()
    )
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>ZERO-ORBIT Report</title>
<style>
 body{{font-family:system-ui,Segoe UI,sans-serif;background:#0a0e1a;color:#dbe6ff;padding:24px}}
 h1{{color:#4da3ff}} table{{border-collapse:collapse;width:100%;margin:12px 0}}
 th,td{{border:1px solid #1e2a44;padding:8px;font-size:13px;text-align:left}}
 th{{background:#111a2e;color:#8fb3ff}}
 .risk-info{{color:#8fa}} .risk-low{{color:#7fd1ff}} .risk-medium{{color:#ffcc55}}
 .risk-high{{color:#ff8844}} .risk-critical{{color:#ff4d4d;font-weight:bold}}
 pre{{background:#101828;padding:12px;border-radius:6px;overflow:auto}}
</style></head><body>
<h1>ZERO-ORBIT — Security Report</h1>
<p><b>Target:</b> {data['target']}<br>
<b>Started:</b> {data['started']} &nbsp; <b>Finished:</b> {data['finished']}<br>
<b>Scope:</b> {', '.join(data['scope']) or '-'}</p>
<h2>Assets &amp; Technologies</h2>
<pre>{json.dumps({'technologies': data['technologies'], 'endpoints': data['endpoints']}, indent=2)}</pre>
<h2>Findings</h2>
<table><tr><th>Risk</th><th>Title</th><th>URL</th><th>Evidence</th><th>Recommended Fix</th></tr>
{rows or '<tr><td colspan=5>No findings</td></tr>'}</table>
<h2>Risk Summary</h2>
<table><tr><th>Level</th><th>Count</th></tr>{summary_rows}
<tr><th>Overall</th><th>{data['overall_risk']}</th></tr></table>
</body></html>"""


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run_scan(target: str, settings: Dict[str, Any], scope: List[str],
             do_pressure: bool = False, do_fix: bool = False) -> ScanResult:
    result = ScanResult(target=target, started=now_iso(), scope=scope)

    if not shield_check(target, scope):
        result.notes.append("Target is OUT OF SCOPE — aborting.")
        return result

    # 1. Discovery via Go
    disc = call_orbit("discover", target=target,
                      timeout=settings.get("timeout_seconds", 10))
    result.assets = disc.get("assets", {}) or {}
    result.technologies = disc.get("technologies", []) or []

    # 2. Scan via Go
    scan = call_orbit("scan", target=target,
                      timeout=settings.get("timeout_seconds", 10),
                      max_requests=settings.get("max_requests", 200))
    headers = scan.get("headers", {}) or {}
    result.endpoints = scan.get("endpoints", []) or []

    # 3. Local analysis
    result.findings += analyze_headers(target, headers)
    result.findings += check_https(target, scan)
    result.findings += admin_exposure_findings(target, scan.get("endpoint_results", []))

    # 4. C++ fingerprinting
    fp = call_engine(headers, scan.get("body_snippet", ""))
    for tech in fp.get("technologies", []):
        if tech not in result.technologies:
            result.technologies.append(tech)

    # 5. Pressure Lab (optional)
    if do_pressure:
        pressure = call_orbit(
            "pressure", target=target,
            rps=settings.get("max_rps", 5),
            duration=settings.get("max_duration", 30),
            concurrency=settings.get("max_concurrency", 4),
            max_requests=settings.get("max_requests", 200),
        )
        result.pressure = pressure

    # 6. Auto-Fix (optional)
    if do_fix:
        applied = apply_fix(result.findings, interactive=True)
        result.notes.append(f"Auto-fix applied: {applied}")

    result.finished = now_iso()
    return result


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------
def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause() -> None:
    input("\nPress Enter to continue...")


def menu() -> None:
    ensure_dirs()
    settings = load_settings()
    scope = load_scope()
    last: Optional[ScanResult] = None

    while True:
        clear()
        print(BANNER.format(ver=VERSION))
        print("=" * 55)
        print("[01] TARGET          [02] DISCOVERY       [03] WEB SCANNER")
        print("[04] API SCANNER     [05] AUTH SECURITY   [06] ADMIN EXPOSURE")
        print("[07] CONFIG AUDIT    [08] PRESSURE LAB    [09] AUTO FIX")
        print("[10] RESCAN          [11] REPORTS         [12] BACKUPS")
        print("[13] SCOPE           [14] SETTINGS        [15] EXIT")
        print("=" * 55)
        choice = input("Select >> ").strip()

        if choice in ("15", "q", "exit"):
            print("Goodbye.")
            return

        elif choice == "01":
            t = input("[01] Enter authorized target: ").strip()
            if t:
                if shield_check(t, scope):
                    print(f"[OK] {t} is within scope.")
                else:
                    print(f"[BLOCKED] {t} is NOT in scope. Add it under [13].")

        elif choice == "02":
            t = input("[02] Target for discovery: ").strip()
            if not shield_check(t, scope):
                print("[BLOCKED] out of scope."); pause(); continue
            out = call_orbit("discover", target=t,
                             timeout=settings.get("timeout_seconds", 10))
            print(json.dumps(out, indent=2)[:4000]); pause()

        elif choice == "03":
            t = input("[03] Target for web scan: ").strip()
            if not shield_check(t, scope):
                print("[BLOCKED] out of scope."); pause(); continue
            last = run_scan(t, settings, scope, do_pressure=False, do_fix=False)
            _print_findings(last); pause()

        elif choice == "04":
            print("[04] API Scanner (reuses web scan for now).")
            t = input("Target: ").strip()
            if not shield_check(t, scope):
                print("[BLOCKED]"); pause(); continue
            last = run_scan(t, settings, scope)
            _print_findings(last); pause()

        elif choice == "05":
            print("[05] Auth Security — safe indicators only.")
            t = input("Target (login page URL): ").strip()
            if not shield_check(t, scope):
                print("[BLOCKED]"); pause(); continue
            last = run_scan(t, settings, scope)
            auth = [f for f in last.findings if f.category in ("cookies", "tls")]
            if not auth:
                print("[OK] No obvious auth-surface indicators.")
            for f in auth:
                print(f"  [{f.risk}] {f.title} — {f.fix}")
            pause()

        elif choice == "06":
            print("[06] Admin Exposure Detector.")
            t = input("Target base URL: ").strip()
            if not shield_check(t, scope):
                print("[BLOCKED]"); pause(); continue
            last = run_scan(t, settings, scope)
            admin = [f for f in last.findings if f.category == "admin"]
            for f in admin:
                print(f"  [{f.risk}] {f.title} — {f.url}")
            if not admin:
                print("[OK] No admin panels detected on common paths.")
            pause()

        elif choice == "07":
            print("[07] Config Audit — uses latest scan.")
            if not last:
                print("Run a scan first ([03])."); pause(); continue
            hdr = [f for f in last.findings if f.category == "headers"]
            print(f"Missing security headers: {len(hdr)}")
            for f in hdr:
                print(f"  - {f.title}")
            pause()

        elif choice == "08":
            print("[08] PRESSURE LAB")
            t = input("Target: ").strip()
            if not shield_check(t, scope):
                print("[BLOCKED]"); pause(); continue
            print(f"Limits: rps={settings['max_rps']} "
                  f"duration={settings['max_duration']}s "
                  f"concurrency={settings['max_concurrency']} "
                  f"max_requests={settings['max_requests']}")
            last = run_scan(t, settings, scope, do_pressure=True)
            print(json.dumps(last.pressure, indent=2)[:3000]); pause()

        elif choice == "09":
            print("[09] AUTO FIX")
            if not last:
                print("Run a scan first."); pause(); continue
            print(f"Proposed fixes for {len(last.findings)} findings.")
            res = apply_fix(last.findings, interactive=True)
            print(json.dumps(res, indent=2)); pause()

        elif choice == "10":
            if not last:
                print("No previous target."); pause(); continue
            print(f"[10] Rescanning {last.target}...")
            last = run_scan(last.target, settings, scope)
            _print_findings(last); pause()

        elif choice == "11":
            if not last:
                print("No scan to report."); pause(); continue
            paths = write_reports(last)
            print(json.dumps(paths, indent=2)); pause()

        elif choice == "12":
            print("[12] BACKUPS")
            for p in sorted(BACKUPS_DIR.rglob("*")) if BACKUPS_DIR.exists() else []:
                if p.is_file():
                    print(f"  {p}")
            pause()

        elif choice == "13":
            print("[13] SCOPE — current entries:")
            for s in scope:
                print(f"  - {s}")
            print("\n[a]dd / [r]emove / [c]lear / [b]ack")
            sub = input(">> ").strip().lower()
            if sub == "a":
                v = input("New scope entry (e.g. *.example.com): ").strip()
                if v:
                    scope.append(v); save_scope(scope)
            elif sub == "r":
                v = input("Entry to remove: ").strip()
                if v in scope:
                    scope.remove(v); save_scope(scope)
            elif sub == "c":
                scope.clear(); save_scope(scope)
            pause()

        elif choice == "14":
            print("[14] SETTINGS")
            print(json.dumps(settings, indent=2))
            k = input("Key to change (or Enter): ").strip()
            if k and k in settings:
                v = input(f"New value for {k}: ").strip()
                try:
                    settings[k] = type(settings[k])(v)
                    save_settings(settings)
                    print("[OK] saved.")
                except Exception as e:
                    print(f"[ERR] {e}")
            pause()

        else:
            print("Unknown option.")
            pause()


def _print_findings(res: ScanResult) -> None:
    print("\n" + "=" * 55)
    print(f"TARGET: {res.target}")
    print(f"Endpoints: {len(res.endpoints)}  Techs: {', '.join(res.technologies) or '-'}")
    summary = _risk_summary(res.findings)
    print("-" * 55)
    for r in RISK_LEVELS:
        print(f"{r:8}: {summary.get(r,0):02d}")
    print(f"RISK SCORE: {_overall_risk(res.findings):02d}/05")
    print("-" * 55)
    for f in res.findings:
        print(f"[{f.risk:8}] {f.title}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    ensure_dirs()
    parser = argparse.ArgumentParser(
        prog="zero-orbit",
        description="ZERO-ORBIT — authorized web attack-surface & resilience analyzer.",
    )
    parser.add_argument("command", nargs="?", help="numeric command or 'menu'")
    parser.add_argument("target", nargs="?", help="authorized target")
    parser.add_argument("--pressure", action="store_true", help="run pressure lab")
    parser.add_argument("--fix", action="store_true", help="apply safe auto-fixes")
    parser.add_argument("--report", action="store_true", help="write reports")
    parser.add_argument("--version", action="version", version=f"ZERO-ORBIT {VERSION}")
    args = parser.parse_args()

    if args.command == "menu" or (args.command is None and args.target is None):
        menu()
        return 0

    if args.command and args.command.isdigit() and args.target is None:
        # e.g. zero-orbit 01  → prompt for target
        if args.command == "01":
            args.target = input("[01] Enter authorized target: ").strip()

    if args.target is None:
        parser.print_help()
        return 1

    settings = load_settings()
    scope = load_scope()
    res = run_scan(args.target, settings, scope,
                   do_pressure=args.pressure, do_fix=args.fix)
    _print_findings(res)
    if args.report:
        paths = write_reports(res)
        print("\nReports written:")
        for k, v in paths.items():
            print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())