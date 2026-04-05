import argparse
import time

from core.window import SlidingWindow
from core.correlation import run_all_rules
from core.anomaly import StatisticalAnomalyDetector
from core.metrics import MetricsTracker
from core.scoring import compute_score, enforce_single_source_cap, get_severity
from alert.alert_manager import AlertManager
from simulator.attack_simulator import AttackSimulator

WINDOW_SIZE_SECONDS = 10
TICKS_PER_SCENARIO = 30
SCENARIOS = [
    "benign",
    "bruteforce",
    "port_scan",
    "noise_injection",
    "replay_attack",
    "sensor_failure",
]


def parse_args():
    parser = argparse.ArgumentParser(description="Run Multi-Source IDS experiments")
    parser.add_argument(
        "--scenario",
        "-s",
        default="all",
        choices=["all", *SCENARIOS],
        help="Run one scenario or all scenarios (default: all)",
    )
    return parser.parse_args()


def build_alert(detection, severity, score, scenario):
    return {
        "timestamp": time.time(),
        "scenario": scenario,
        "rule": detection["rule"],
        "entity": detection["entity"],
        "severity": severity,
        "score": score,
        "sources": detection["sources"],
        "evidence_count": detection["evidence_count"],
        "message": f"{detection['rule']} detected for {detection['entity']} (evidence={detection['evidence_count']})",
    }


def run_scenario(simulator, scenario):
    window = SlidingWindow(WINDOW_SIZE_SECONDS)
    anomaly_detector = StatisticalAnomalyDetector()
    metrics = MetricsTracker()
    alert_manager = AlertManager(log_path=f"alerts_{scenario}.jsonl")

    print(f"\n=== Scenario: {scenario} ===")
    metrics.start()

    for tick in range(TICKS_PER_SCENARIO):
        tick_events = simulator.generate_tick(scenario, tick)
        for event in tick_events:
            window.add_event(event)

        events = window.get_events()
        detections = run_all_rules(events)
        detections.extend(anomaly_detector.update_and_detect(events))

        alert_raised = False
        for detection in detections:
            score = compute_score(detection["evidence"], rule_name=detection["rule"])
            severity = get_severity(score, detection["multi_source"], detection["strong_pattern"])
            severity = enforce_single_source_cap(severity, detection["multi_source"])
            alert_key = f"{detection['rule']}:{detection['entity']}"

            if alert_manager.should_alert(alert_key, cooldown=8):
                alert = build_alert(detection, severity, score, scenario)
                alert_manager.raise_alert(alert)
                alert_raised = True

        malicious_present = any(event["label"] == "malicious" for event in events)
        metrics.record_window(malicious_present, alert_raised, time.time())
        time.sleep(0.05)

    scenario_result = metrics.finish()
    print(f"Scenario metrics: {scenario_result}")
    return scenario_result


def aggregate_results(results):
    avg = {
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
        "fpr": 0.0,
        "fnr": 0.0,
        "avg_alert_latency_sec": 0.0,
        "cpu_time_sec": 0.0,
        "memory_kb_peak": 0.0,
        "wall_time_sec": 0.0,
    }
    latency_count = 0
    count = len(results)

    for result in results:
        for key in ("precision", "recall", "f1", "fpr", "fnr", "cpu_time_sec", "memory_kb_peak", "wall_time_sec"):
            avg[key] += result[key]
        if result["avg_alert_latency_sec"] is not None:
            avg["avg_alert_latency_sec"] += result["avg_alert_latency_sec"]
            latency_count += 1

    for key in ("precision", "recall", "f1", "fpr", "fnr", "cpu_time_sec", "memory_kb_peak", "wall_time_sec"):
        avg[key] = round(avg[key] / max(count, 1), 4)

    avg["avg_alert_latency_sec"] = (
        round(avg["avg_alert_latency_sec"] / latency_count, 4) if latency_count else None
    )
    return avg


def main():
    args = parse_args()
    selected_scenarios = SCENARIOS if args.scenario == "all" else [args.scenario]

    simulator = AttackSimulator(seed=1337)
    results = []
    for scenario in selected_scenarios:
        results.append(run_scenario(simulator, scenario))

    print("\n=== Overall Metrics (Average Across Scenarios) ===")
    print(aggregate_results(results))


if __name__ == "__main__":
    main()