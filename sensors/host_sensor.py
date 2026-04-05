from core.event_schema import create_event
import random


def generate_host_event():
    events = ["failed_login", "failed_login", "failed_login", "success_login"]

    return create_event(
        "host",
        random.choice(events),
        {
            "user": "admin",
            "src_ip": "192.168.1.10",
            "host": "localhost",
        },
    )


def make_login_event(event_type, user, src_ip, scenario, label="benign"):
    return create_event(
        "host",
        event_type,
        {
            "user": user,
            "src_ip": src_ip,
            "host": "localhost",
        },
        label=label,
        scenario=scenario,
    )


def make_process_event(process_name, user, scenario, label="benign"):
    return create_event(
        "host",
        "process_start",
        {
            "process": process_name,
            "user": user,
            "host": "localhost",
        },
        label=label,
        scenario=scenario,
    )