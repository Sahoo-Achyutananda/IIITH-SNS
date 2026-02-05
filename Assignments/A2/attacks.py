class AttackConfig:
    ATTACK_NONE = 0
    ATTACK_REPLAY = 1
    ATTACK_TAMPER_PARAM = 2
    ATTACK_DROP = 3
    ATTACK_DELAY = 4
    ATTACK_UNAUTHORIZED = 5


class AttackLogger:

    def log(message: str):
        """ Koi bhi ek message print kare ke liye yeh function """
        pass

    def log_packet(direction: str, opcode: int, size: int):
        """To print information of the messages it receives/sends"""
        pass


class MITMProxy:

    def __init__(self, attack_mode: int):
        pass

    def start(self):
        """Start MITM proxy and accept drone connection"""
        pass

    def connect_to_mcc(self):
        pass

    def accept_drone(self):
        pass

    def forward_drone_to_mcc(self):
        pass

    def forward_mcc_to_drone(self):
        pass

    def forward_packet(self, src, dst, direction: str):
        pass

    def apply_attack(self, opcode: int, data: bytes, direction: str):
        pass


# Individual attack modules -

class ReplayAttack:

    def handle(self, opcode: int, data: bytes, direction: str):
        pass


class ParameterTamperingAttack:

    def handle(self, opcode: int, data: bytes, direction: str):
        pass


class DropAttack:

    def handle(self, opcode: int, data: bytes, direction: str):
        pass


class DelayAttack:

    def handle(self, opcode: int, data: bytes, direction: str):
        pass


class UnauthorizedDroneAttack:

    def launch(self):
        pass

class AttackController:

    def __init__(self, attack_mode: int):
        pass

    def dispatch(self, opcode: int, data: bytes, direction: str):
        pass

def main():
    pass

if __name__ == "__main__":
    main()
