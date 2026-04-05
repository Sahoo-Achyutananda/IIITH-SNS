# Detectors Explained (SNS IDS)

This document explains all detector types used in this IDS project.

## What is a detector?

A detector is a rule or statistical check that looks at events inside the current sliding time window and decides whether behavior looks suspicious.

In this project, detectors return a structured detection object with fields like:

- rule: detector name
- evidence: matching events
- entity: who/what is suspicious (IP, user, or host)
- evidence_count: number of matching events
- sources: which sensors contributed (host/network)
- multi_source: true if evidence comes from 2+ sources
- strong_pattern: true for deterministic multi-step attacks

All rule-based detectors are in core/correlation.py, and anomaly detection is in core/anomaly.py.

---

## Rule-Based Detectors

### 1) detect_bruteforce

- File: core/correlation.py
- Goal: detect repeated failed logins from the same user and source IP.
- Logic:
  - take all failed_login events
  - group by (user, src_ip)
  - if count >= threshold (default 5), raise detection
- Entity format: user@src_ip (example: admin@10.10.10.66)
- Why useful: catches classic password brute-force attempts.

### 2) detect_fast_port_scan

- File: core/correlation.py
- Goal: detect quick scanning of many ports by one source IP.
- Logic:
  - use network events (port_access, connection_attempt)
  - group by src_ip
  - count unique ports
  - if unique ports >= threshold (default 6), raise detection
- Entity: src_ip
- Why useful: catches active reconnaissance before exploitation.

### 3) detect_slow_port_scan

- File: core/correlation.py
- Goal: detect slower scan behavior that may try to evade basic thresholds.
- Logic:
  - same event set as fast scan
  - group by src_ip
  - require unique ports >= threshold (default 8)
  - also require total grouped events >= threshold
- Entity: src_ip
- Why useful: catches low-and-slow scanning over the correlation window.

### 4) detect_login_after_failures

- File: core/correlation.py
- Goal: detect suspicious success login after many failures from same IP.
- Logic:
  - use failed_login + success_login events
  - group by user
  - maintain failed attempts timeline
  - when success_login appears, check same src_ip failures within lookback window
  - if same-IP failures >= fail_threshold (default 5, lookback 8 seconds), raise detection
- Entity: user@src_ip
- Why useful: indicates possible credential stuffing or guessed credentials.

### 5) detect_suspicious_process

- File: core/correlation.py
- Goal: detect execution of known offensive tools.
- Logic:
  - use process_start events
  - if process name is in suspicious set {nc, ncat, hydra, sqlmap, masscan}, raise detection
- Entity: inferred from event details (src_ip/user/host)
- Why useful: catches host-side indicators of attacker tooling.

### 6) detect_replay_attack

- File: core/correlation.py
- Goal: detect repeated replay-like identical events.
- Logic:
  - build signature from (source, event_type, sorted(details))
  - count repeated signatures
  - if same signature appears >= threshold (default 4), raise detection
- Entity: inferred from first matching event
- Why useful: catches repeated traffic/log replays used to hide or probe behavior.

### 7) detect_scan_then_bruteforce (Multi-step deterministic)

- File: core/correlation.py
- Goal: detect a stronger attack chain using two stages.
- Logic:
  - run fast port scan detector (threshold 5)
  - run bruteforce detector (threshold 4)
  - if both happen from same attacker IP, combine evidence
  - mark strong_pattern = True
- Entity: attacker IP
- Why useful: this is stronger than isolated signals and supports high-confidence alerting.

### 8) run_all_rules

- File: core/correlation.py
- Goal: orchestrate all rule-based detectors.
- Logic:
  - calls all 7 rule detectors
  - merges all detections into one list
- Why useful: single entry point for correlation engine in main.py.

---

## Statistical Detector

### 9) StatisticalAnomalyDetector.update_and_detect

- File: core/anomaly.py
- Goal: detect unusual behavior statistically, not only via fixed rules.
- Feature set per window:
  - failed_login_count
  - unique_port_count
  - event_count
- Logic:
  - keep historical baseline per feature
  - after min_samples (default 5), compute
    - mean
    - standard deviation
    - z-score: (current - mean) / (std + epsilon)
  - if z-score >= threshold (default 2.5), raise statistical_anomaly
- Entity: window (not specific user/IP)
- Why useful: catches unusual bursts or deviations that hard-coded rules may miss.

---

## How detector output is used

- Rule detections + anomaly detections are combined in main.py.
- Each detection is scored and mapped to severity.
- Critical severity is constrained by assignment policy:
  - only allowed for multi-source evidence OR strong multi-step deterministic pattern.
- Alerts are deduplicated by rule:entity key and logged in scenario JSONL files.

---

## Quick Summary Table

- bruteforce: repeated failed logins per user+IP
- port_scan_fast: many unique ports quickly per IP
- port_scan_slow: broader/slower scan pattern per IP
- success_after_failures: successful login after same-IP failures
- suspicious_process: offensive tool process execution
- replay_pattern: repeated identical event signatures
- scan_then_bruteforce: scan + bruteforce chain by same IP
- statistical_anomaly: z-score deviation on login/port/event rates
