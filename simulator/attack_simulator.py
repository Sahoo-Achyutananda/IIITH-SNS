import random
import sys
from pathlib import Path

try:
    from sensors.host_sensor import make_login_event, make_process_event
    from sensors.network_sensor import make_connection_event, make_port_access_event
except ModuleNotFoundError:
    # Allow direct execution from simulator/ where project root is not on sys.path.
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from sensors.host_sensor import make_login_event, make_process_event
    from sensors.network_sensor import make_connection_event, make_port_access_event


class AttackSimulator:
    def __init__(self, seed=42):
        self.seed = seed
        self.replay_buffer = []

    def _rng(self, scenario):
        return random.Random(f"{self.seed}:{scenario}")

    def benign_events(self, step, scenario, rng):
        src_ip = f"192.168.1.{rng.randint(2, 20)}"
        user = rng.choice(["admin", "alice", "bob", "charlie"])
        net = make_connection_event(src_ip, rng.choice([22, 80, 443, 8080]), scenario)
        host = make_login_event(rng.choice(["success_login", "failed_login", "success_login"]), user, src_ip, scenario)
        events = [net, host]
        if step % 10 == 0:
            events.append(make_process_event("bash", user, scenario))
        return events

    def scenario_benign(self, step, rng):
        events = self.benign_events(step, "benign", rng)
        return events

    def scenario_bruteforce(self, step, rng):
        events = self.benign_events(step, "bruteforce", rng)
        attacker_ip = "10.10.10.66"
        if 4 <= step <= 14:
            for _ in range(2):
                events.append(make_login_event("failed_login", "admin", attacker_ip, "bruteforce", label="malicious"))
        return events

    def scenario_port_scan(self, step, rng):
        events = self.benign_events(step, "port_scan", rng)
        scanner_ip = "10.10.10.77"
        if 4 <= step <= 16:
            start_port = 20 + step
            for offset in range(3):
                events.append(
                    make_port_access_event(scanner_ip, start_port + offset, "port_scan", label="malicious")
                )
        return events

    def scenario_noise_injection(self, step, rng):
        events = self.benign_events(step, "noise_injection", rng)
        for _ in range(5):
            events.append(
                make_connection_event(
                    f"172.16.0.{rng.randint(2, 30)}",
                    rng.choice([22, 80, 443, 3306, 5432]),
                    "noise_injection",
                )
            )
        if 8 <= step <= 18:
            events.append(
                make_login_event(
                    "failed_login",
                    "admin",
                    "10.10.10.88",
                    "noise_injection",
                    label="malicious",
                )
            )
            events.append(
                make_port_access_event(
                    "10.10.10.88",
                    rng.choice([21, 22, 23, 25, 80, 443, 3389]),
                    "noise_injection",
                    label="malicious",
                )
            )
        return events

    def scenario_replay_attack(self, step, rng):
        events = self.benign_events(step, "replay_attack", rng)
        if step < 5:
            self.replay_buffer.extend(events[:2])
        if 8 <= step <= 14 and self.replay_buffer:
            replay_sample = rng.choice(self.replay_buffer)
            if replay_sample["source"] == "network":
                events.append(
                    make_connection_event(
                        replay_sample["details"]["src_ip"],
                        replay_sample["details"]["port"],
                        "replay_attack",
                        label="malicious",
                    )
                )
            else:
                events.append(
                    make_login_event(
                        replay_sample["event_type"],
                        replay_sample["details"]["user"],
                        replay_sample["details"].get("src_ip", "192.168.1.10"),
                        "replay_attack",
                        label="malicious",
                    )
                )
        return events

    def scenario_sensor_failure(self, step, rng):
        # Simulates temporary host-sensor outage.
        events = []
        if step < 10:
            events.extend(self.benign_events(step, "sensor_failure", rng))
        else:
            events.append(make_connection_event("10.10.10.99", 22 + step % 10, "sensor_failure"))
            events.append(
                make_port_access_event("10.10.10.99", 30 + step, "sensor_failure", label="malicious")
            )
        return events

    def generate_step(self, scenario, step):
        rng = self._rng(f"{scenario}:{step}")
        if scenario == "benign":
            return self.scenario_benign(step, rng)
        if scenario == "bruteforce":
            return self.scenario_bruteforce(step, rng)
        if scenario == "port_scan":
            return self.scenario_port_scan(step, rng)
        if scenario == "noise_injection":
            return self.scenario_noise_injection(step, rng)
        if scenario == "replay_attack":
            return self.scenario_replay_attack(step, rng)
        if scenario == "sensor_failure":
            return self.scenario_sensor_failure(step, rng)
        raise ValueError(f"Unknown scenario: {scenario}")