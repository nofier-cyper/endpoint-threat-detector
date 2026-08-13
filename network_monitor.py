"""
Network monitoring module for Endpoint Threat Detector.

Collects available network connection information.
If the operating system restricts access, the scanner
reports the limitation instead of crashing.
"""

import psutil


def get_network_connections():
    """Collect available network connections safely."""
    connections = []

    try:
        raw_connections = psutil.net_connections(kind="inet")
    except (PermissionError, OSError) as error:
        return {
            "available": False,
            "error": type(error).__name__,
            "message": (
                "Network connection inspection is unavailable "
                "under the current operating-system permissions."
            ),
            "connections": [],
        }

    for connection in raw_connections:
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

    return {
        "available": True,
        "error": None,
        "message": None,
        "connections": connections,
    }


def summarize_connections(result):
    """Create a simple connection summary."""
    if not result["available"]:
        return {
            "available": False,
            "total": 0,
            "established": 0,
            "listening": 0,
            "other": 0,
        }

    summary = {
        "available": True,
        "total": len(result["connections"]),
        "established": 0,
        "listening": 0,
        "other": 0,
    }

    for connection in result["connections"]:
        status = connection["status"]

        if status == "ESTABLISHED":
            summary["established"] += 1
        elif status == "LISTEN":
            summary["listening"] += 1
        else:
            summary["other"] += 1

    return summary
