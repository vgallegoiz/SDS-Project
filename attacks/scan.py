import socket
from pathlib import Path
from argparse import ArgumentParser


class Scan:
    def __init__(self, fileName):
        self.portData = {}
        with open(fileName, 'r') as d_scan:
            for line in d_scan:
                server, ports = line.split()
                self.portData[server] = [int(p) for p in ports.split(',')]

    def _testPort(self, server, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex((server, port)) == 0:
                    s.close()
                    return True
            return False
        except (OSError, ValueError):
            return False

    def run(self):
        for server in self.portData:
            for port in self.portData[server]:
                try:
                    result = self._testPort(server, port)
                except (OSError, ValueError):
                    result = False
                if result:
                    print(f"{server}:{port}: OK")
                else:
                    print(f"{server}:{port}: ERROR")


if __name__ == "__main__":
    PARSER = ArgumentParser(description=__doc__)
    PARSER.add_argument("scan_file", type=Path, help="Scan file with list of hosts and ports")
    ARGS = PARSER.parse_args()
    scan = Scan(ARGS.scan_file)
    scan.run()
