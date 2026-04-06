# Security Design Notes

## 1. Security Objectives

This IDS is designed with four primary security objectives:

1. Detect common network and host attack patterns with explainable logic.
2. Improve confidence by correlating evidence across multiple sources.
3. Control alert quality through severity policy and deduplication.
4. Remain operational under noisy input and partial sensor visibility.

The implementation is intentionally lightweight and flow-oriented for lab constraints.

## 2. Threat Model and Scope

The system is expected to detect the following behaviors:

1. Brute-force login attempts.
2. Fast and slow port scanning.
3. Replay-like repeated behavior patterns.
4. Suspicious attacker-tool process launches.
5. Attacks hidden in benign background noise.
6. Degraded observability during partial sensor failure.

Out of scope:

1. Deep packet inspection.
2. Signature engines such as Snort/Suricata.
3. Full endpoint forensics and malware classification.
4. Prevention or active blocking (this project is detection-focused).

## 3. Trust Boundaries and Data Flow

Security-relevant data flow:

1. Sensors produce normalized events.
2. Events enter the sliding correlation window.
3. Rule-based and anomaly detectors evaluate the current window.
4. Detections are scored and mapped to severity.
5. Alert manager deduplicates and logs alerts.
6. Metrics consume labels and predictions for evaluation.

Trust boundaries:

1. Sensor output is treated as untrusted input until schema validation passes.
2. Correlation and scoring are trusted control logic.
3. Logged alerts are immutable append-only records for audit analysis.

## 4. Event Schema Integrity and Validation

All modules consume a shared JSON event schema from `core/event_schema.py`.

Required fields:

1. `event_id`
2. `source` (`host` or `network`)
3. `event_type`
4. `timestamp`
5. `details` (dict)
6. `label` (`benign` or `malicious`)
7. `scenario`

Security rationale:

1. Prevents parser drift and inconsistent assumptions across modules.
2. Enforces source and label constraints before correlation.
3. Ensures audit records are structurally consistent for replay/debugging.

## 5. Detection Architecture

### 5.1 Rule-Based Correlation

Implemented in `core/correlation.py`, this layer detects explicit attack patterns with interpretable logic.

Detectors include:

1. `bruteforce`
2. `port_scan_fast`
3. `port_scan_slow`
4. `success_after_failures`
5. `suspicious_process`
6. `replay_pattern`
7. `scan_then_bruteforce` (deterministic multi-step)

Security value:

1. High explainability.
2. Good precision for known tactics.
3. Multi-step correlation strengthens evidence quality.

### 5.2 Statistical Anomaly Detection

Implemented in `core/anomaly.py` with online feature baselining and z-score checks.

Tracked features:

1. Failed login count.
2. Unique port count.
3. Total event count.

Security value:

1. Detects unusual bursts not explicitly covered by static rules.
2. Complements rule logic during evolving or blended behavior.

## 6. Severity and Scoring Policy

Scoring is implemented in `core/scoring.py`:

1. Evidence events contribute weighted points by event type.
2. Rule bonus adds confidence based on detector semantics.
3. Final score maps to `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

Critical policy constraint:

1. `CRITICAL` requires multi-source agreement or strong deterministic pattern.
2. Single-source evidence is capped to `HIGH`.

Security rationale:

1. Reduces high-severity escalation from weak isolated signals.
2. Aligns with assignment requirement for stronger critical confidence.

## 7. Alert Robustness and Flood Control

`alert/alert_manager.py` provides:

1. Deduplication using `rule:entity` key.
2. Cooldown gating for repeated identical alerts.
3. Persistent JSONL logging (`alerts_<scenario>.jsonl`).

Security rationale:

1. Prevents operator overload from repetitive alert storms.
2. Preserves incident traceability with durable append-only logs.
3. Separates detection from alert emission policy.

## 8. Sliding Window Security Rationale

The window in `core/window.py` restricts evidence to recent events.

Benefits:

1. Limits stale context influence.
2. Supports temporal attack chains.
3. Provides bounded memory footprint for runtime stability.

Tradeoff:

1. Window size tuning affects responsiveness vs context depth.

## 9. Metrics Integrity and Interpretation

`core/metrics.py` tracks:

1. TP, FP, TN, FN
2. Precision, recall, F1, FPR, FNR
3. Alert latency
4. CPU time, wall time, memory peak

Current evaluation style:

1. Ground truth is step-level (`malicious_present` from current step events).
2. Prediction positivity uses detector presence in that step cycle.

Security interpretation note:

1. These metrics are strict and can expose tradeoffs quickly.
2. Lower FN can increase FP depending on prediction/ground-truth alignment.

## 10. Noise and Sensor-Failure Resilience

Simulator scenarios intentionally test robustness against:

1. Heavy benign noise (`noise_injection`).
2. Partial visibility (`sensor_failure`).

Security rationale:

1. Validates that the IDS does not assume perfect telemetry.
2. Demonstrates behavior under realistic degraded conditions.

## 11. Known Limitations

1. No packet payload inspection.
2. No active response or blocking.
3. Threshold/rule tuning remains heuristic.
4. Statistical baseline can be sensitive to traffic distribution changes.
5. Correlation quality depends on event fidelity and schema correctness.

## 12. Operational Recommendations

1. Tune window size and thresholds per deployment context.
2. Review cooldown to balance spam control and visibility.
3. Track confusion matrix per scenario, not only global averages.
4. Preserve JSONL logs for replay and post-incident analysis.
5. Re-evaluate severity bonuses when adding new detectors.

## 13. Summary

This IDS uses layered detection, constrained critical escalation, and robust alert handling to provide practical, explainable security monitoring within lab constraints. It prioritizes correlation quality and operational signal-to-noise control while remaining reproducible and measurable.
