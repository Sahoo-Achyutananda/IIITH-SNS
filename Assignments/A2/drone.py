class Opcode:
    PARAM_INIT = 10
    AUTH_REQ = 20
    AUTH_RES = 30
    SK_CONFIRM = 40
    SUCCESS = 50
    ERR = 60
    GROUP_KEY = 70
    GROUP_CMD = 80
    SHUTDOWN = 90


class DroneConfig:
    MCC_IP = "127.0.0.1"
    MCC_PORT = 8000  # attacker se connect hoga yeh
    HARD_MIN_SL = 2048


class DroneClient:

    def __init__(self, drone_id):
        pass

    def connect(self):
        pass

    def phase0_receive_params(self):
        pass

    def phase1_auth_request(self):
        pass

    def phase1_verify_mcc(self):
        pass

    def phase2_session_confirm(self):
        pass

    def receive_group_key(self):
        pass

    def receive_command(self):
        pass
