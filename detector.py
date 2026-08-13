import json
import platform
from datetime import datetime, timezone

try:
    import psutil
except ImportError:
    print("Missing dependency: psutil")
    print("Install it with: pip install psutil")
    raise SystemExit(1)

from network_monitor import get_network_connections
from persistence_scanner import scan_persistence
from rules import evaluate_process


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
            "HIGH"
            if score >= 70
            else "MEDIUM"
            if score >= 40
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
    network_connections = get_network_connections()
    persistence_findings = scan_persistence()

    return {
        "tool": "Endpoint Threat Detector",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),

        "system": {
            "platform": platform.platform(),
            "hostname": platform.node(),
            "architecture": platform.machine(),
        },

        "network": {
            "total_connections": len(network_connections),
            "connections": network_connections,
        },

        "persistence": persistence_findings,

        "summary": {
            "processes_analyzed": len(processes),
            "medium_or_higher": sum(
                process["risk_score"] >= 40
                for process in processes
            ),
            "high_risk": sum(
                process["risk_score"] >= 70
                for process in processes
            ),
        },

        "processes": processes,
    }


def main():
    print("=" * 60)
    print("ENDPOINT THREAT DETECTOR v0.1")
    print("=" * 60)

    print("[*] Starting defensive endpoint analysis...")

    processes = scan_processes()
    report = build_report(processes)

    with open(
        "endpoint_threat_report.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
        )

    print()
    print(f"[+] Processes analyzed: {len(processes)}")
    print(
        "[+] Medium or higher: "
        f"{report['summary']['medium_or_higher']}"
    )
    print(
        "[+] High risk: "
        f"{report['summary']['high_risk']}"
    )
    print(
        "[+] Network connections: "
        f"{report['network']['total_connections']}"
    )
    print(
        "[+] Persistence findings: "
        f"{len(report['persistence']['startup_directories'])}"
    )
    print("[+] Report: endpoint_threat_report.json")
    print("[+] Analysis completed.")


if __name__ == "__main__":
    main()
