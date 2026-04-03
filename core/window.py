import time

class SlidingWindow:
    def __init__(self, size):
        self.size = size
        self.events = []
    
    def cleanup(self):
        current = time.time()
        self.events = [
            e for e in self.events
            if current - e["timestamp"] <= self.size
        ]

    def add_event(self, event):
        self.events.append(event)
        self.cleanup()

    def get_events(self):
        return self.events