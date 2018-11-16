#!/bin/env python
# -*- coding: utf-8 -*-


import socket
import sys


def send(target, port, data):
    """send(target, port, data) sends data to target:port"""

    HOST = target
    PORT = port

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    s.send(bytearray(data, 'utf-8'))
    reply = s.recv(1024)

    if 'exit.' in data:
        s.close()
    print('Received: {}'.format(repr(reply)))


if __name__ == "__main__":

    if len(sys.argv) != 4:
        print("Usage: python script_name.py target ip data")
        sys.exit(1)

    send(sys.argv[1], int(sys.argv[2]), sys.argv[3] + '\n')
