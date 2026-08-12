import json
import os
from rules import evaluate_process
from datetime import datetime, timezone

try:
    import psutil
except ImportError:
    print("Missing dependency: psutil")
    print("Install it with: pip install psutil")
    raise SystemExit(1)


SUSPICIOUS_PATHS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
)


def is_suspicious_path(path):
    """Check whether an executable is located in a commonly abused path."""
    if not path:
        return False

    normalized = path.replace("/", "\\").lower()

    return any(
        suspicious in normalized
        for suspicious in SUSPICIOUS_PATHS
    )


def analyze_process(process):
    """Collect defensive information about one running process."""
    try:
        pid = process.pid
        name = process.name()

        try:
            executable = process.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            executable = None

        try:
            username = process.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            username = None

   score, reasons = evaluate_process(executable) 

        risk_level = (
            "HIGH" if score >= 70
            else "MEDIUM" if score >= 40
            else "LOW"
        )

        return {
            "pid": pid,
            "name": name,
            "username": username,
            "executable": executable,
            "risk_score": score,
            "risk_level": risk_level,
            "reasons": reasons,
        }

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
    ):
        return None


def scan_processes():
    """Scan currently running processes."""
    results = []

    for process in psutil.process_iter():
        result = analyze_process(process)

        if result:
            results.append(result)

    return sorted(
        results,
        key=lambda item: item["risk_score"],
        reverse=True,
    )


def build_report(processes):
    """Build a structured security report."""
    return {
        "tool": "Endpoint Threat Detector",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": {
            "platform": platform.platform(),
            "hostname": platform.node(),
            "architecture": platform.machine(),
        },
        "summary": {
            "processes_analyzed": len(processes),
            "medium_or_higher": sum(
                p["risk_score"] >= 40 for p in processes
            ),
            "high_risk": sum(
                p["risk_score"] >= 70 for p in processes
            ),
        },
        "processes": processes,
    }


def main():
    print("=" * 60)
    print("ENDPOINT THREAT DETECTOR v0.1")
    print("=" * 60)
    print("[*] Starting defensive process analysis...")

    processes = scan_processes()
    report = build_report(processes)

    with open(
        "endpoint_threat_report.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(report, file, indent=4)

    print(f"[+] Processes analyzed: {len(processes)}")
    print(
        f"[+] Medium or higher: "
        f"{report['summary']['medium_or_higher']}"
    )
    print(
        f"[+] High risk: "
        f"{report['summary']['high_risk']}"
    )
    print("[+] Report: endpoint_threat_report.json")


if __name__ == "__main__":
    main()
