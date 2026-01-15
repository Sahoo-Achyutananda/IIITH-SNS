class ProtocolError(Exception):
    pass

class ProtocolFSM:
    """
    Based on what i understood from the doc
    There are three phases - INIT, ACTIVE and TERMINATED
    INIT allows only HELLO opcode
    ACTIVE allows only DATA opcode
    TERMINATED -> none
    """

    def __init__(self):
        self.phase = "INIT"
        self.expected_round = 0
    
    def process(self, message : dict) -> str:
        opcode = message["opcode"]
        round_no = message["round"]
        payload = message["payload"]

        
        if round_no != self.expected_round:
            raise ProtocolError(f"Round Mismatch, expected - {self.expected_round}, got - {round_no}")
        
        if self.phase == "INIT":
            if opcode != "HELLO":
                raise ProtocolError("Invalid opcode in INIT phase")
            
            self.phase = "ACTIVE"
            response = "HELLO_ACCEPTED"

        elif self.phase == "ACTIVE":
            if opcode == "DATA":
                response = f"DATA_OK:{payload}"

            elif opcode == "EXIT":
                self.phase = "TERMINATED"
                response = "SESSION_TERMINATED"

            else:
                raise ProtocolError("Invalid opcode in ACTIVE phase")

        else:
            raise ProtocolError("Session already terminated")
        
        self.expected_round += 1
        return response