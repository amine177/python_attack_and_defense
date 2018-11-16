#!/bin/env python
# -*- coding: utf-8 -*-


import socket
import sys


def bind(ip, port):
    """bind(ip, port) binds to ip:port"""

    HOST = ip
    PORT = int(port)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)

    print("Listening!")
    conn, addr = s.accept()
    print("Connected by {}".format(addr))

    while True:
        data = conn.recv(1024)
        print(repr(data))
        if not data:
            break
        print("received:{}".format(data))
        conn.send(data)

    conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script_name.py ip port")
        sys.exit(1)

    ip = sys.argv[1]
    p = sys.argv[2]
    bind(ip, p)
