# Security Design Notes

## 1. Threat Model Coverage

The IDS is designed to detect:

- brute-force login attempts
- fast/slow port scans
- replay-like repeated patterns
- suspicious process launches
- attack behavior under noisy traffic
- partial visibility when one sensor fails

## 2. Event Schema Integrity

All modules use a common JSON schema from `core/event_schema.py`:

- `event_id`
- `source` (`host` or `network`)
- `event_type`
- `timestamp`
- `details`
- `label` (`benign`/`malicious`)
- `scenario`

`validate_event` enforces schema consistency and helps avoid parser/correlation drift.

## 3. Correlation and Detection Strategy

Detection combines:

- Rule-based correlation (`core/correlation.py`)
- Statistical anomaly detection (`core/anomaly.py`)

The system supports deterministic multi-step correlation (`scan_then_bruteforce`) to strengthen evidence quality.

## 4. Alert Scoring and False Positive Control

Severity is computed using event weights plus rule bonuses (`core/scoring.py`).

Critical severity policy is constrained:

- `CRITICAL` is allowed only when either:
  - evidence spans at least two independent sources, or
  - a deterministic strong multi-step pattern is detected.

If evidence is single-source, severity is capped to `HIGH`.

## 5. Alert Robustness

`alert/alert_manager.py` includes:

- cooldown-based deduplication using `rule:entity` keys
- persistent JSONL logging for post-analysis

This reduces alert flooding and preserves auditability.

## 6. Operational Robustness

- Sliding window limits stale evidence impact.
- Scenario-based simulation includes sensor-failure conditions to test degraded operation.
- Metrics module tracks quality and performance to detect regressions.
