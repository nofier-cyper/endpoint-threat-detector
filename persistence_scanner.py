"""
Persistence Scanner
Endpoint Threat Detector v0.1

Defensive scanner for common Windows startup locations.
This module only reads information; it does not modify the system.
"""

import os


def get_startup_locations():
    """Return common Windows startup locations."""
    locations = []

    appdata = os.environ.get("APPDATA")
    program_data = os.environ.get("PROGRAMDATA")

    if appdata:
        locations.append(
            os.path.join(
                appdata,
                "Microsoft",
                "Windows",
                "Start Menu",
                "Programs",
                "Startup",
            )
        )

    if program_data:
        locations.append(
            os.path.join(
                program_data,
                "Microsoft",
                "Windows",
                "Start Menu",
                "Programs",
                "StartUp",
            )
        )

    return locations


def scan_startup_directories():
    """Scan startup directories for files."""
    findings = []

    for directory in get_startup_locations():
        if not os.path.isdir(directory):
            continue

        try:
            for filename in os.listdir(directory):
                full_path = os.path.join(directory, filename)

                if os.path.isfile(full_path):
                    findings.append(
                        {
                            "type": "startup_file",
                            "name": filename,
                            "path": full_path,
                        }
                    )

        except PermissionError:
            findings.append(
                {
                    "type": "access_denied",
                    "path": directory,
                }
            )

    return findings


def scan_persistence():
    """Run all persistence checks."""
    return {
        "startup_directories": scan_startup_directories(),
    }
