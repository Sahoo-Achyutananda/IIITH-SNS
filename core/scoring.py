EVENT_WEIGHTS = {
    "failed_login": 2,
    "success_login": 1,
    "port_access": 1,
    "connection_attempt": 1,
    "process_start": 3,
}

RULE_BONUS = {
    "bruteforce": 4,
    "port_scan_fast": 4,
    "port_scan_slow": 5,
    "success_after_failures": 4,
    "suspicious_process": 5,
    "replay_pattern": 3,
    "scan_then_bruteforce": 8,
    "statistical_anomaly": 3,
}


def compute_score(evidence_events, rule_name=None):
    score = sum(EVENT_WEIGHTS.get(event["event_type"], 1) for event in evidence_events)
    if rule_name:
        score += RULE_BONUS.get(rule_name, 0)
    return score


def get_severity(score, multi_source, strong_pattern):
    # Core assignment rule: CRITICAL only when multi-source evidence agrees
    # or when deterministic multi-step strong pattern is found.
    if score >= 12 and (multi_source or strong_pattern):
        return "CRITICAL"
    if score >= 9:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    if score >= 3:
        return "LOW"
    return "INFO"


def enforce_single_source_cap(severity, multi_source):
    if multi_source:
        return severity
    if severity == "CRITICAL":
        return "HIGH"
    return severity