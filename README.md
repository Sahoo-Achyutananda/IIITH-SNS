# Multi-Source IDS (SNS Lab 4)

This project implements a lightweight Intrusion Detection System (IDS) with correlation-based detection across host and network sensors.

## Features

- Unified JSON event schema with validation
- Sliding time-window correlation
- 7 rule-based detectors:
  - `bruteforce`
  - `port_scan_fast`
  - `port_scan_slow`
  - `success_after_failures`
  - `suspicious_process`
  - `replay_pattern`
  - `scan_then_bruteforce` (deterministic multi-step)
- Statistical anomaly detector (z-score based)
- Severity levels: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- Deduplication/cooldown with alert logging (`alerts_<scenario>.jsonl`)
- Reproducible attack simulation scenarios:
  - benign baseline
  - brute force
  - port scan
  - noise injection
  - replay attack
  - sensor failure
- Experiment metrics:
  - Precision, Recall, F1
  - FPR/FNR
  - Alert latency
  - CPU and memory usage

## Project Structure

- `main.py`: experiment runner
- `core/`: schema, window, correlation, scoring, anomaly, metrics
- `sensors/`: host and network event generators
- `simulator/attack_simulator.py`: scenario generation
- `alert/alert_manager.py`: deduplication and alert output

## Requirements

- Python 3.9+

## Run

```bash
python3 main.py
```

Run only one scenario:

```bash
python3 main.py --scenario port_scan
```

The program runs all required scenarios and prints per-scenario metrics and overall averages.

## Workflow

If you are new to IDS projects, think of this system as a pipeline that repeats many small simulation steps.

1. The simulator generates activity.
  - For each step, it creates host events and network events.
  - Depending on the scenario, these events can be benign or malicious.

2. Events are normalized into one common format.
  - Every event follows the same schema (`event_id`, `source`, `event_type`, `timestamp`, `details`, `label`, `scenario`).
  - This keeps all modules consistent.

3. Events are stored in a sliding time window.
  - The window keeps only recent events (last N seconds).
  - Detection logic uses this recent context instead of full history.

4. Rule-based detectors run on the window.
  - These check patterns such as brute force, port scanning, replay behavior, and suspicious process execution.

5. Statistical anomaly detection runs on the same window.
  - It compares current feature values with historical baseline using z-score.

6. Detections are scored and assigned severity.
  - Score is computed from event weights plus rule bonus.
  - Severity is mapped to INFO/LOW/MEDIUM/HIGH/CRITICAL.
  - Critical severity is constrained by assignment policy (multi-source agreement or strong deterministic pattern).

7. Alert manager handles output.
  - It deduplicates repeated alerts using `rule:entity` keys and cooldown.
  - Allowed alerts are printed and appended to `alerts_<scenario>.jsonl`.

8. Metrics are updated every step.
  - Counts TP/FP/TN/FN and computes precision, recall, F1, FPR/FNR, latency, CPU, and memory.
  - Confusion matrix is printed for each scenario and overall.

In short: generate events -> correlate/detect -> score/severity -> deduplicate/log alerts -> compute metrics.

## How TP/FP/TN/FN Are Calculated

Metrics are calculated at each simulation step using two booleans:

1. `malicious_present`
- True if any event in `step_events` has label `malicious`.

2. `prediction_positive`
- True if at least one detection is produced in that step (`len(detections) > 0`).

Per-step confusion logic:

1. TP (True Positive)
- `malicious_present = True` and `prediction_positive = True`
- Meaning: malicious step and detector fired.

2. FN (False Negative)
- `malicious_present = True` and `prediction_positive = False`
- Meaning: malicious step but detector did not fire.

3. FP (False Positive)
- `malicious_present = False` and `prediction_positive = True`
- Meaning: benign step but detector fired.

4. TN (True Negative)
- `malicious_present = False` and `prediction_positive = False`
- Meaning: benign step and detector did not fire.

Simple examples:

1. Example TP
- Step has 2 malicious events, and one rule detects brute-force.
- Count update: `TP +1`.

2. Example FN
- Step has malicious events, but no rule/anomaly triggers.
- Count update: `FN +1`.

3. Example FP
- Step has only benign events, but a detector still triggers (for example due to sliding-window context).
- Count update: `FP +1`.

4. Example TN
- Step has only benign events and no detection.
- Count update: `TN +1`.

After all steps in a scenario, totals are used for precision/recall/F1/FPR/FNR and printed as the confusion matrix.

## Rule-Based vs Anomaly Detection

Both detection styles are used together, but they are different in how they decide something is suspicious.

### 1) Rule-Based Detection

- Rule-based detection checks fixed patterns with explicit conditions.
- Example patterns: repeated failed logins, many ports scanned, suspicious process names.
- If a rule condition matches, it creates a detection deterministically.

Where it is implemented:

- Rule detectors: `core/correlation.py`
- Rule orchestrator: `run_all_rules(...)` in `core/correlation.py`
- Called from experiment loop: `main.py`

### 2) Anomaly Detection

- Anomaly detection checks whether current behavior is statistically unusual compared to baseline history.
- It computes features from the current window, then checks z-score against a threshold.
- This is useful for unusual bursts that may not match any predefined rule.

Where it is implemented:

- Statistical detector: `core/anomaly.py`
- Main method: `StatisticalAnomalyDetector.update_and_detect(...)`
- Called from experiment loop: `main.py` and merged with rule detections.

### 3) Key Difference in One Line

- Rule-based: "known attack pattern matched."
- Anomaly-based: "behavior is unusually different from normal baseline."

### 4) Why both are used

- Rule-based gives precise known-pattern detection.
- Anomaly detection can catch unexpected or evolving behavior.
- Combining both improves coverage and robustness.

## Deduplication and cooldown 

This system avoids alert spam using two ideas:

1. Deduplication
- Deduplication means: do not raise the exact same alert repeatedly.
- The alert identity key is `rule:entity`.
- Example key: `bruteforce:admin@10.10.10.66`.

2. Cooldown
- Cooldown means: after raising an alert for a key, wait for a fixed time before allowing the same key again.
- In this project, cooldown is checked in the alert manager path before writing logs.

How it works in practice:

1. First time a key appears, alert is raised and logged.
2. If the same key appears again too soon, it is suppressed.
3. After cooldown time passes, that key can be raised again.

Example timeline (cooldown = 8 seconds):

1. `t=0s`: `bruteforce:admin@10.10.10.66` -> raised
2. `t=2s`: same key -> suppressed
3. `t=5s`: same key -> suppressed
4. `t=9s`: same key -> raised again

Why this is useful:

1. Prevents repeated alert flooding.
2. Keeps `alerts_<scenario>.jsonl` readable.
3. Helps analysts focus on new incidents instead of duplicates.

## Detailed Guide: `simulator/attack_simulator.py`

This file is the synthetic traffic engine for the IDS. It does not perform detection itself. Its job is to generate realistic event streams (benign + malicious) so the rest of the pipeline can be tested and measured.

### Purpose in the pipeline

1. Produce deterministic, scenario-specific event data.
2. Mix host and network activity so correlation rules have meaningful evidence.
3. Mark events with `label=benign` or `label=malicious` for metric ground truth.
4. Provide multiple attack styles required by the assignment.

### Imports and startup behavior

The simulator imports event-builder helpers from:

1. `sensors/host_sensor.py`
2. `sensors/network_sensor.py`

It also includes an import fallback: if the file is executed directly from the `simulator/` folder, it adds project root to `sys.path` and retries imports. This is why `python attack_simulator.py` can run from that folder.

### Class overview

`AttackSimulator` has two pieces of internal state:

1. `seed`: base seed for reproducibility.
2. `replay_buffer`: stores earlier events used later by replay scenario logic.

### Reproducible randomness design

The `_rng(...)` helper creates a deterministic RNG from a string like `seed:scenario:step`.

Why this matters:

1. Same code + same seed gives same generated events.
2. Experiments are repeatable for debugging and grading.
3. Scenario comparisons are fair across runs.

### Core generation pattern

Most scenario methods follow the same pattern:

1. Start with `benign_events(...)` as background traffic.
2. Inject malicious events only in specific step ranges.
3. Return one list of events for the current step.

This creates realistic mixed traffic rather than fully malicious traffic, which better tests false-positive behavior.

### Function-by-function explanation

1. `benign_events(step, scenario, rng)`
- Generates baseline host + network activity.
- Chooses random internal source IP and user.
- Emits one network connection attempt and one login event.
- Every 10 steps, adds a benign process event (`bash`) to diversify host telemetry.

2. `scenario_benign(step, rng)`
- Returns only baseline benign traffic.
- Used as control/baseline scenario.

3. `scenario_bruteforce(step, rng)`
- Starts with benign traffic.
- During a bounded step range, injects repeated `failed_login` events for the same user/IP attacker.
- Designed to trigger brute-force style rules.

4. `scenario_port_scan(step, rng)`
- Starts with benign traffic.
- During attack range, injects multiple `port_access` events across changing ports from one scanner IP.
- Designed to trigger fast/slow port-scan rules.

5. `scenario_noise_injection(step, rng)`
- Starts with benign traffic.
- Adds high volume random benign network noise each step.
- During attack range, injects targeted malicious login + port events from one attacker.
- Designed to test detector robustness under noisy conditions.

6. `scenario_replay_attack(step, rng)`
- Starts with benign traffic.
- Early steps populate `replay_buffer` with real generated events.
- Later steps replay sampled patterns (network or host-like) with malicious label.
- Designed to create repeated-signature behavior for replay detection.

7. `scenario_sensor_failure(step, rng)`
- Simulates partial observability.
- Early phase: normal mixed activity.
- Later phase: host-like visibility drops while network activity continues (including malicious traffic).
- Designed to test IDS behavior when one source is effectively degraded.

8. `generate_step(scenario, step)`
- Main dispatch method used by `main.py`.
- Chooses the correct scenario function and returns step events.
- Raises `ValueError` for unknown scenario names.

### Why step ranges are used

Attack injections are bounded to specific step intervals instead of being active forever.

Benefits:

1. Creates clear pre-attack, attack, and post-attack phases.
2. Lets sliding-window logic be meaningfully exercised.
3. Enables latency and confusion-matrix behavior to be observed.

### Event labeling strategy

Every event generated by the simulator carries:

1. `scenario` name
2. `label` (`benign` or `malicious`)

These labels are critical for metric computation (`malicious_present` at step level).

### Important practical note

Running `attack_simulator.py` directly only defines/loads simulator logic; it does not run full IDS detection or print metrics by itself. Full experiment outputs (alerts, metrics, confusion matrix) come from running `main.py`.

## Reproducibility

- Scenario generation is deterministic using a fixed seed in `main.py`.
- To change seed, edit `AttackSimulator(seed=1337)`.

## Notes

- This implementation performs flow-level analysis and does not use deep packet inspection.
- Snort/Suricata are not used.

## Challenges

#### High FN Count -

The current evaluation pipeline can report high false negatives (FN) even when detections are firing. This is mainly due to how windows and cooldown interact:

- Window-level labeling inflates malicious windows:
  - Metrics use `malicious_present = any(event["label"] == "malicious" for event in events)` over the full sliding window.
  - Once malicious events enter the window, multiple subsequent steps can still be counted as malicious windows.

- Alert counting is step-based but deduplicated with cooldown:
  - `alert_raised` is true only when an alert is emitted in that step.
  - Alerts are deduplicated by `rule:entity` key with cooldown, so repeated malicious steps may be suppressed.
  - Suppressed steps with `malicious_present=True` are counted as FN by the current metric logic.

- Statistical detector warm-up delays early detections:
  - The anomaly module waits for `min_samples` baseline windows before z-score checks begin.
  - Early malicious activity can occur before anomaly detections are active.

- Rule thresholds require evidence accumulation:
  - Several rule detectors trigger only after enough evidence is accumulated in the window.
  - Malicious windows before threshold crossing contribute to FN.

These effects are expected under the current design and are documented here before any tuning changes.

#### Changes Applied to Reduce FN Inflation

The following changes were applied to make evaluation fairer without weakening alert deduplication:

- Ground truth for metrics now uses the current simulation step events (`step_events`) instead of the full sliding window.
  - This avoids repeatedly counting stale malicious history as fresh positives.

- Metric positive prediction now uses detector presence (`len(detections) > 0`) instead of emitted-alert presence.
  - Cooldown suppression still controls alert logging/output, but no longer penalizes detection quality metrics.

- Cooldown behavior is unchanged for alert logs.
  - Alerts are still deduplicated by `rule:entity` to prevent flooding in `alerts_<scenario>.jsonl`.

Net effect: FN/recall now better reflect detection behavior rather than log deduplication side effects.
