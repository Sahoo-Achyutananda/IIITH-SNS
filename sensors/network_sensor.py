from core.event_schema import create_event
import random


def generate_network_event():
    ports = [22, 80, 443, 8080, 21]
    return create_event(
        "network",
        "port_access",
        {
            "src_ip": "192.168.1.10",
            "dst_ip": "127.0.0.1",
            "port": random.choice(ports),
            "protocol": "tcp",
            "packets": random.randint(2, 20),
        },
    )


def make_port_access_event(src_ip, port, scenario, label="benign"):
    return create_event(
        "network",
        "port_access",
        {
            "src_ip": src_ip,
            "dst_ip": "127.0.0.1",
            "port": port,
            "protocol": "tcp",
            "packets": random.randint(1, 12),
        },
        label=label,
        scenario=scenario,
    )


def make_connection_event(src_ip, dst_port, scenario, label="benign"):
    return create_event(
        "network",
        "connection_attempt",
        {
            "src_ip": src_ip,
            "dst_ip": "127.0.0.1",
            "port": dst_port,
            "protocol": "tcp",
            "packets": random.randint(1, 8),
        },
        label=label,
        scenario=scenario,
    )