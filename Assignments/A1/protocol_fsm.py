from crypto_utils import evolve_key

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

    # defining phases -
    INIT = "INIT"
    ACTIVE = "ACTIVE"
    TERMINATED = "TERMINATED"

    # defining opcodes
    CLIENT_HELLO = 10
    CLIENT_DATA = 30
    TERMINATE = 60

    def __init__(self, client_id : int, master_key : bytes):
        self.client_id = client_id
        self.phase = self.INIT
        self.round = 0

        # initializing initial keys -
        self.c2s_enc = evolve_key(master_key, b"Apple")
        self.c2s_mac = evolve_key(master_key, b"Banana")
        self.s2c_enc = evolve_key(master_key, b"Carrot")
        self.s2c_mac = evolve_key(master_key, b"Dragonfruit")
    
    def validate_message(self, opcode : int, msg_round : int, direction : int):
        if msg_round != self.round:
            raise ProtocolError(f"Round Mismatch, expected - {self.round}, got - {msg_round}")

        if direction not in (0,1):
            raise ProtocolError("Invalid direction field")
        
        if direction == 0 and opcode not in (self.CLIENT_HELLO, self.CLIENT_DATA, self.TERMINATE):
            raise ProtocolError("Invalid client-to-server opcode")

        if direction == 1 and opcode in (self.CLIENT_HELLO, self.CLIENT_DATA):
            raise ProtocolError("Client opcode seen in server direction")


        if self.phase == self.INIT:
            if opcode != self.CLIENT_HELLO:
                raise ProtocolError("INIT phase expects CLIENT_HELLO")
            self.phase = self.ACTIVE

        elif self.phase == self.ACTIVE:
            if opcode not in (self.CLIENT_DATA, self.TERMINATE):
                raise ProtocolError("Invalid opcode in ACTIVE phase")
            if opcode == self.TERMINATE:
                self.phase = self.TERMINATED

        else:
            raise ProtocolError("Session already terminated")
    
    def update_keys_after_c2s(self, ciphertext: bytes):

        self.c2s_enc = evolve_key(self.c2s_enc, ciphertext)
        self.c2s_mac = evolve_key(self.c2s_mac, b"ACHYUTANANDA-SAHOO")

    def update_keys_after_s2c(self, ciphertext: bytes):

        self.s2c_enc = evolve_key(self.s2c_enc, ciphertext)
        self.s2c_mac = evolve_key(self.s2c_mac, b"SATYAJIT-PRIYADARSHI")
    
    def advance_round(self):
        if self.phase != self.TERMINATED:
            self.round += 1