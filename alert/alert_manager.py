import time
import json


class AlertManager:
    def __init__(self, log_path="alerts.jsonl"):
        self.last_alert = {}
        self.log_path = log_path

    def should_alert(self, key, cooldown=5):
        now = time.time()
        if key not in self.last_alert or now - self.last_alert[key] > cooldown:
            self.last_alert[key] = now
            return True
        return False

    def raise_alert(self, alert):
        print(f"[{alert['severity']}] {alert['message']}")
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert) + "\n")