class ProtocolError(Exception):
    # Custom error used when protocol rules are broken
    pass

class ProtocolFSM:
    def __init__(self, client_id):
        self.client_id = client_id
        
        # Current stage of the protocol (start, normal, end)
        self.phase = "INIT" 
        
        # Which message round number we are expecting next
        self.expected_round = 0 

    def validate_and_update(self, opcode, round_no):
        # Check if message round number is correct
        if round_no != self.expected_round:
            raise ProtocolError(f"Round mismatch: expected {self.expected_round}, got {round_no}")

        # If protocol is just starting
        if self.phase == "INIT":
            # First message must be CLIENT_HELLO (opcode 10)
            if opcode != 10: 
                raise ProtocolError("Must start with CLIENT_HELLO (10)")
            # Move to normal communication phase
            self.phase = "ACTIVE"
        
        # If protocol is in normal data transfer phase
        elif self.phase == "ACTIVE":
            # Only DATA (30) or CLOSE (60) messages are allowed now
            if opcode not in [30, 60]: 
                raise ProtocolError(f"Invalid opcode {opcode} for ACTIVE phase")
            # If client sends CLOSE, end the protocol
            if opcode == 60:
                self.phase = "TERMINATED"
        
        # If all checks passed, message is valid
        return True

    def increment_round(self):
        # After each successful message, move to next round number
        self.expected_round += 1
