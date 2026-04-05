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

## Reproducibility

- Scenario generation is deterministic using a fixed seed in `main.py`.
- To change seed, edit `AttackSimulator(seed=1337)`.

## Notes

- This implementation performs flow-level analysis and does not use deep packet inspection.
- Snort/Suricata are not used.
