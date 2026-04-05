import resource
import time


class MetricsTracker:
    def __init__(self):
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0
        self.latencies = []
        self.first_malicious_ts = None
        self.first_alert_ts = None
        self._start_wall = None
        self._start_cpu = None
        self._start_mem = None

    def start(self):
        self._start_wall = time.time()
        usage = resource.getrusage(resource.RUSAGE_SELF)
        self._start_cpu = usage.ru_utime + usage.ru_stime
        self._start_mem = usage.ru_maxrss

    def record_window(self, malicious_present, alert_raised, timestamp):
        if malicious_present and not alert_raised:
            self.fn += 1
        elif malicious_present and alert_raised:
            self.tp += 1
        elif (not malicious_present) and alert_raised:
            self.fp += 1
        else:
            self.tn += 1

        if malicious_present and self.first_malicious_ts is None:
            self.first_malicious_ts = timestamp
        if alert_raised and self.first_alert_ts is None:
            self.first_alert_ts = timestamp

    def finish(self):
        usage = resource.getrusage(resource.RUSAGE_SELF)
        end_cpu = usage.ru_utime + usage.ru_stime
        end_mem = usage.ru_maxrss
        end_wall = time.time()

        if self.first_malicious_ts is not None and self.first_alert_ts is not None:
            self.latencies.append(max(0.0, self.first_alert_ts - self.first_malicious_ts))

        precision = self.tp / (self.tp + self.fp + 1e-9)
        recall = self.tp / (self.tp + self.fn + 1e-9)
        f1 = 2 * precision * recall / (precision + recall + 1e-9)
        fpr = self.fp / (self.fp + self.tn + 1e-9)
        fnr = self.fn / (self.fn + self.tp + 1e-9)

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
            "avg_alert_latency_sec": round(sum(self.latencies) / len(self.latencies), 4)
            if self.latencies
            else None,
            "cpu_time_sec": round(end_cpu - self._start_cpu, 4),
            "memory_kb_peak": int(end_mem),
            "wall_time_sec": round(end_wall - self._start_wall, 4),
            "counts": {
                "tp": self.tp,
                "fp": self.fp,
                "tn": self.tn,
                "fn": self.fn,
            },
        }
