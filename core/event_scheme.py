import time

def create_event(source, event_type, details):
    return{
        "source": source,
        "event_type": event_type,
        "timestamp": time.time(),
        "details": details # this is also a json like structure
    }