"""Restart readiness must distinguish listeners from reusable TCP TIME_WAIT."""
import socket
import unittest
from start import check_ports


class PortTests(unittest.TestCase):
    def test_rejects_existing_tcp_listener(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('127.0.0.1', 0)); listener.listen(1)
            with self.assertRaises(OSError):
                check_ports([(listener.getsockname()[1], socket.SOCK_STREAM)])

    def test_rejects_existing_udp_socket(self):
        with socket.socket(type=socket.SOCK_DGRAM) as listener:
            listener.bind(('127.0.0.1', 0))
            with self.assertRaises(OSError):
                check_ports([(listener.getsockname()[1], socket.SOCK_DGRAM)])

    def test_reuses_closed_tcp_connection(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('127.0.0.1', 0)); listener.listen(1)
            port = listener.getsockname()[1]
            with socket.create_connection(('127.0.0.1', port)) as client:
                accepted, _ = listener.accept()
                accepted.close()  # Server actively closes, creating TIME_WAIT.
                self.assertEqual(client.recv(1), b'')
        check_ports([(port, socket.SOCK_STREAM)])


if __name__ == '__main__': unittest.main()
