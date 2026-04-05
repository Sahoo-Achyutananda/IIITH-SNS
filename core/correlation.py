from collections import defaultdict


SUSPICIOUS_PROCESSES = {"nc", "ncat", "hydra", "sqlmap", "masscan"}


def _group_by_key(events, key_fn):
    grouped = defaultdict(list)
    for event in events:
        grouped[key_fn(event)].append(event)
    return grouped


def _detection(rule_name, evidence, strong_pattern=False):
    if not evidence:
        return None
    sources = sorted({e["source"] for e in evidence})
    entity = "unknown"
    details = evidence[0]["details"]
    for candidate in ("src_ip", "user", "host"):
        if candidate in details:
            entity = str(details[candidate])
            break
    return {
        "rule": rule_name,
        "evidence": evidence,
        "entity": entity,
        "evidence_count": len(evidence),
        "sources": sources,
        "multi_source": len(sources) >= 2,
        "strong_pattern": strong_pattern,
    }


def detect_bruteforce(events, threshold=5):
    failed = [e for e in events if e["event_type"] == "failed_login"]
    by_user_ip = _group_by_key(
        failed,
        lambda e: (e["details"].get("user", "unknown"), e["details"].get("src_ip", "unknown")),
    )
    detections = []
    for key, grouped in by_user_ip.items():
        if len(grouped) >= threshold:
            detection = _detection("bruteforce", grouped)
            detection["entity"] = f"{key[0]}@{key[1]}"
            detections.append(detection)
    return detections


def detect_fast_port_scan(events, threshold=6):
    net_events = [e for e in events if e["event_type"] in {"port_access", "connection_attempt"}]
    by_ip = _group_by_key(net_events, lambda e: e["details"].get("src_ip", "unknown"))
    detections = []
    for src_ip, grouped in by_ip.items():
        ports = {e["details"].get("port") for e in grouped if "port" in e["details"]}
        if len(ports) >= threshold:
            detection = _detection("port_scan_fast", grouped)
            detection["entity"] = src_ip
            detections.append(detection)
    return detections


def detect_slow_port_scan(events, threshold=8):
    net_events = [e for e in events if e["event_type"] in {"port_access", "connection_attempt"}]
    by_ip = _group_by_key(net_events, lambda e: e["details"].get("src_ip", "unknown"))
    detections = []
    for src_ip, grouped in by_ip.items():
        ports = {e["details"].get("port") for e in grouped if "port" in e["details"]}
        if len(ports) >= threshold and len(grouped) >= threshold:
            detection = _detection("port_scan_slow", grouped)
            detection["entity"] = src_ip
            detections.append(detection)
    return detections


def detect_login_after_failures(events, fail_threshold=5, lookback_seconds=8):
    host_events = [e for e in events if e["event_type"] in {"failed_login", "success_login"}]
    by_user = _group_by_key(host_events, lambda e: e["details"].get("user", "unknown"))
    detections = []
    for user, grouped in by_user.items():
        grouped_sorted = sorted(grouped, key=lambda e: e["timestamp"])
        failures = []
        for event in grouped_sorted:
            if event["event_type"] == "failed_login":
                failures.append(event)
            elif event["event_type"] == "success_login":
                same_ip_failures = [
                    failure
                    for failure in failures
                    if failure["details"].get("src_ip") == event["details"].get("src_ip")
                    and event["timestamp"] - failure["timestamp"] <= lookback_seconds
                ]
                if len(same_ip_failures) >= fail_threshold:
                    detection = _detection(
                        "success_after_failures",
                        same_ip_failures[-fail_threshold:] + [event],
                    )
                    detection["entity"] = f"{user}@{event['details'].get('src_ip', 'unknown')}"
                    detections.append(detection)
                    break
    return detections


def detect_suspicious_process(events):
    suspicious = [
        e
        for e in events
        if e["event_type"] == "process_start" and e["details"].get("process") in SUSPICIOUS_PROCESSES
    ]
    return [_detection("suspicious_process", suspicious)] if suspicious else []


def detect_replay_attack(events, threshold=4):
    signatures = defaultdict(list)
    for event in events:
        details = event["details"]
        signature = (
            event["source"],
            event["event_type"],
            tuple(sorted(details.items())),
        )
        signatures[signature].append(event)
    detections = []
    for grouped in signatures.values():
        if len(grouped) >= threshold:
            detections.append(_detection("replay_pattern", grouped))
    return detections


def detect_scan_then_bruteforce(events):
    scans = detect_fast_port_scan(events, threshold=5)
    brute = detect_bruteforce(events, threshold=4)
    detections = []
    for scan in scans:
        for brute_force in brute:
            scan_ip = scan["entity"]
            brute_ip = brute_force["entity"].split("@")[-1]
            if scan_ip == brute_ip:
                evidence = scan["evidence"] + brute_force["evidence"]
                detection = _detection("scan_then_bruteforce", evidence, strong_pattern=True)
                detection["entity"] = scan_ip
                detections.append(detection)
    return detections


def multi_source(events):
    sources = set(e["source"] for e in events)
    return len(sources) >= 2


def run_all_rules(events):
    detections = []
    for detector in (
        detect_bruteforce,
        detect_fast_port_scan,
        detect_slow_port_scan,
        detect_login_after_failures,
        detect_suspicious_process,
        detect_replay_attack,
        detect_scan_then_bruteforce,
    ):
        detections.extend(detector(events))
    return detections