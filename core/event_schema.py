import time
import uuid


REQUIRED_FIELDS = {"event_id", "source", "event_type", "timestamp", "details", "label", "scenario"}
ALLOWED_SOURCES = {"network", "host"}


def create_event(source, event_type, details, label="benign", scenario="unspecified"):
    event = {
        "event_id": str(uuid.uuid4()),
        "source": source,
        "event_type": event_type,
        "timestamp": time.time(),
        "details": details,
        "label": label,
        "scenario": scenario,
    }
    validate_event(event)
    return event

# a validator - just checks if the events are of the specific format as they were mentioned !
def validate_event(event):
    missing = REQUIRED_FIELDS - set(event.keys())
    if missing:
        raise ValueError(f"Event missing required keys: {sorted(missing)}")

    if event["source"] not in ALLOWED_SOURCES:
        raise ValueError(f"Invalid source: {event['source']}")

    if not isinstance(event["details"], dict):
        raise ValueError("details must be a dict")

    if event["label"] not in {"benign", "malicious"}:
        raise ValueError("label must be either 'benign' or 'malicious'")

    return True