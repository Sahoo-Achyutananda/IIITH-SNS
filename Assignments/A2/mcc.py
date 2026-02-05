from drone import Opcode

class MCCConfig:
    PORT = 9000
    SECURITY_LEVEL = 2048
    HARD_MIN_SL = 2048


class FleetRegistry:
    def __init__(self):
        self.drones = {}
        # maybe we have to use some other data structure


class MCCServer:

    def __init__(self):
        pass

    def start_server(self):
        pass

    def handle_drone(self, conn, addr):
        pass

    def phase0_send_params(self, conn):
        pass

    def phase1_auth(self, conn):
        pass

    def phase2_confirm(self, conn):
        pass

    def register_drone(self, drone_id, conn, session_key):
        pass


class MCCCLI:

    def __init__(self, mcc_server):
        pass

    def run(self):
        pass

    def cmd_list(self):
        pass

    def cmd_broadcast(self, command: str):
        pass

    def cmd_shutdown(self):
        pass
