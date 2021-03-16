from _thread import start_new_thread
import ssl
import time
from string import Template
from subprocess import Popen, PIPE
import os
from repository import *
import socket

try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

HOST = ''
PORT = 8080
BUF_SIZE = 4096

cert_dir = "certs/"
cert_key = "cert.key"
ca_cert = "ca.crt"
ca_key = "ca.key"


def generate_certificate(host, cert_path, conf_path):
    epoch = "%d" % (time.time() * 1000)
    p1 = Popen(["openssl", "req", "-new", "-key", cert_key, "-subj", "/CN=%s" % host, "-addext",
                "subjectAltName = DNS:" + host], stdout=PIPE)
    p2 = Popen(
        ["openssl", "x509", "-req", "-extfile", conf_path, "-days", "3650", "-CA", ca_cert, "-CAkey", ca_key,
         "-set_serial", epoch,
         "-out", cert_path], stdin=p1.stdout, stderr=PIPE)
    p2.communicate()


connection_established_msg = b'HTTP/1.1 200 Connection Established\r\n\r\n'


def generate_subj_altname_config(host) -> str:
    conf_template = Template("subjectAltName=DNS:${hostname}")
    conf_path = "%s/%s.cnf" % (cert_dir.rstrip('/'), host)
    with open(conf_path, 'w') as fp:
        fp.write(conf_template.substitute(hostname=host))
    return conf_path


def send_https_request(request: str, host: str, port: int = 443) -> socket.socket:
    tunn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tunn.connect((host, port))
    s_sock = ssl.wrap_socket(tunn)
    s_sock.send(request.encode())
    return s_sock


def proxy_https(client_conn: socket.socket, host: str, port: int = 443):
    host = host.split(":")[0].strip()

    cert_path = "%s/%s.crt" % (cert_dir.rstrip('/'), host)
    conf_path = generate_subj_altname_config(host)
    generate_certificate(host, cert_path, conf_path)
    os.unlink(conf_path)

    client_conn.sendall(connection_established_msg)
    client_conn_secure = ssl.wrap_socket(client_conn, keyfile=cert_key, certfile=cert_path, server_side=True)
    client_conn_secure.do_handshake()

    request, _ = receive_data_from_socket(client_conn_secure)
    reply = get_reply_from_host(request.decode(), host, port, 1)

    client_conn_secure.sendall(reply)
    client_conn_secure.close()

    rep.insert_request(request.decode(), host, 1)


def receive_data_from_socket(sock):
    parser = HttpParser()
    resp = b''
    while True:
        data = sock.recv(BUF_SIZE)
        if not data:
            break

        received = len(data)
        _ = parser.execute(data, received)
        resp += data

        if parser.is_message_complete():
            break
    return resp, parser


def build_http_request_to_host(parser: HttpParser, data: bytes):
    data_array = data.decode("utf-8").split("\n")

    url = ""

    if parser.is_headers_complete():
        url = parser.get_url()

    data_array[0] = data_array[0].replace(url, parser.get_path())

    host = parser.get_headers()['host']

    request_to_host = ""
    for line in data_array:
        if line.find("Proxy-Connection") >= 0:
            continue
        request_to_host += line + "\n"

    return request_to_host, host


def proxy_http(data: bytes, parser: HttpParser, con: socket.socket) -> bytes:
    request, host = build_http_request_to_host(parser, data)
    reply = get_reply_from_host(request, host, 80, 0)
    con.sendall(reply)
    con.close()
    rep.insert_request(request, host, 0)
    return reply


def send_http_request(request, host, port):
    req_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    req_socket.connect((host.strip(), port))
    req_socket.sendall(request.encode("utf-8"))
    return req_socket


def get_reply_from_host(request: str, host: str, port: int, tls: int) -> bytes:
    if tls == 1:
        req_socket = send_https_request(request, host, port)
    else:
        req_socket = send_http_request(request, host, port)
    reply, _ = receive_data_from_socket(req_socket)

    req_socket.close()
    return reply


rep = RequestRepository()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5)

    while True:
        try:
            con, addr = sock.accept()
            data, parser = receive_data_from_socket(con)

            if parser.get_method() == "CONNECT":
                start_new_thread(proxy_https, (con, parser.get_headers()['host'], 443))
            else:
                start_new_thread(proxy_http, (data, parser, con))

        except KeyboardInterrupt:
            sock.close()
            exit()

        except Exception as e:
            sock.close()
            print(e.args)
            exit()


if __name__ == '__main__':
    main()
