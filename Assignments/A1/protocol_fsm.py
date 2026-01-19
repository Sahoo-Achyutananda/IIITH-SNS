class ProtocolError(Exception):
    pass


class ProtocolFSM:
    def __init__(self, client_id):
        self.client_id = client_id
        self.phase = "INIT"
        self.expected_round = 0

    def validate_and_update(self, opcode, round_no, direction):
        # ---------------- ROUND CHECK ----------------
        if round_no != self.expected_round:
            raise ProtocolError(
                f"Round mismatch: expected {self.expected_round}, got {round_no}"
            )

        # ---------------- PHASE + OPCODE CHECK ----------------
        if self.phase == "INIT":
            if direction != 0:
                raise ProtocolError("Invalid direction in INIT phase")

            if opcode != 10:
                raise ProtocolError("INIT phase must start with CLIENT_HELLO (10)")

            self.phase = "ACTIVE"

        elif self.phase == "ACTIVE":
            if direction != 0:
                raise ProtocolError("Client must not send server-direction message")

            if opcode not in [30, 60]:
                raise ProtocolError("Only DATA (30) or CLOSE (60) allowed in ACTIVE")

            if opcode == 60:
                self.phase = "TERMINATED"

        elif self.phase == "TERMINATED":
            raise ProtocolError("Message received after termination")

        return True

    def increment_round(self):
        self.expected_round += 1
