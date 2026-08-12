"""
Detection rules for Endpoint Threat Detector.

These rules are heuristic indicators, not proof of malware.
"""

SUSPICIOUS_PATHS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
)

SUSPICIOUS_EXTENSIONS = (
    ".scr",
    ".pif",
    ".hta",
)


def normalize_path(path):
    """Normalize a path for consistent comparison."""
    if not path:
        return ""

    return path.replace("/", "\\").lower()


def check_suspicious_path(executable):
    """Detect executables launched from commonly abused locations."""
    path = normalize_path(executable)

    if not path:
        return False, None

    for suspicious_path in SUSPICIOUS_PATHS:
        if suspicious_path.lower() in path:
            return True, (
                "Executable is located in a commonly abused "
                "temporary or public directory"
            )

    return False, None


def check_suspicious_extension(executable):
    """Detect unusual executable extensions."""
    path = normalize_path(executable)

    if not path:
        return False, None

    for extension in SUSPICIOUS_EXTENSIONS:
        if path.endswith(extension):
            return True, (
                f"Executable uses a potentially suspicious "
                f"extension: {extension}"
            )

    return False, None


def evaluate_process(executable):
    """
    Run all process detection rules.

    Returns:
        score: integer risk score
        reasons: list of detection explanations
    """
    score = 0
    reasons = []

    suspicious, reason = check_suspicious_path(executable)

    if suspicious:
        score += 30
        reasons.append(reason)

    suspicious, reason = check_suspicious_extension(executable)

    if suspicious:
        score += 25
        reasons.append(reason)

    return min(score, 100), reasons
