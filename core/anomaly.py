from collections import defaultdict


class StatisticalAnomalyDetector:
    def __init__(self, min_samples=5, z_threshold=2.5, max_history=100):
        self.min_samples = min_samples
        self.z_threshold = z_threshold
        self.max_history = max_history
        self.history = defaultdict(list)

    @staticmethod
    def _mean(values):
        if not values:
            return 0.0
        return sum(values) / len(values)

    @staticmethod
    def _std(values, mean):
        if len(values) < 2:
            return 0.0
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5

    def _current_features(self, events):
        failed_logins = sum(1 for e in events if e["event_type"] == "failed_login")
        unique_ports = {
            e["details"].get("port")
            for e in events
            if e["event_type"] in {"port_access", "connection_attempt"} and "port" in e["details"]
        }
        total_events = len(events)
        return {
            "failed_login_count": float(failed_logins),
            "unique_port_count": float(len(unique_ports)),
            "event_count": float(total_events),
        }

    def update_and_detect(self, events):
        features = self._current_features(events)
        anomalies = []

        for feature_name, value in features.items():
            baseline = self.history[feature_name]
            if len(baseline) >= self.min_samples:
                mean = self._mean(baseline)
                std = self._std(baseline, mean)
                z_score = (value - mean) / (std + 1e-6)
                if z_score >= self.z_threshold:
                    anomalies.append(
                        {
                            "rule": "statistical_anomaly",
                            "feature": feature_name,
                            "value": value,
                            "mean": round(mean, 3),
                            "std": round(std, 3),
                            "z_score": round(z_score, 3),
                            "evidence": events,
                            "evidence_count": len(events),
                            "entity": "window",
                            "sources": sorted({e["source"] for e in events}),
                            "multi_source": len({e["source"] for e in events}) >= 2,
                            "strong_pattern": False,
                        }
                    )

            baseline.append(value)
            if len(baseline) > self.max_history:
                baseline.pop(0)

        return anomalies
