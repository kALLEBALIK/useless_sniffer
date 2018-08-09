import socket

class Network:

    def __init__(self, local_ip, port, limit=6500):
        # Create raw s ocket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW)

        # Bind socket
        s.bind((local_ip, port))

        # Include ip headers
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Enable promiscuous mode
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        self.socket = s
        self.limit = limit



    def get_raw_data(self, override_limit = 0):
        if override_limit == 0:
            raw_data = self.socket.recvfrom(self.limit)[0]
        else:
            raw_data = self.socket.recvfrom(override_limit)[0]

        return raw_data

    def close(self):
        self.socket.close()
