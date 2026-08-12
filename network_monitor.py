"""
Network monitoring module for Endpoint Threat Detector.

Collects active network connections for defensive analysis.
"""

import psutil


def get_network_connections():
    """Collect active network connections."""
    connections = []

    for connection in psutil.net_connections(kind="inet"):
        local_address = None
        remote_address = None

        if connection.laddr:
            local_address = {
                "ip": connection.laddr.ip,
                "port": connection.laddr.port,
            }

        if connection.raddr:
            remote_address = {
                "ip": connection.raddr.ip,
                "port": connection.raddr.port,
            }

        connections.append({
            "pid": connection.pid,
            "status": connection.status,
            "local_address": local_address,
            "remote_address": remote_address,
        })

    return connections


def summarize_connections(connections):
    """Create a simple connection summary."""
    summary = {
        "total": len(connections),
        "established": 0,
        "listening": 0,
        "other": 0,
    }

    for connection in connections:
        status = connection["status"]

        if status == "ESTABLISHED":
            summary["established"] += 1
        elif status == "LISTEN":
            summary["listening"] += 1
        else:
            summary["other"] += 1

    return summary
