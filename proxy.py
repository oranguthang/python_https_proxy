import os
import ssl
import sys
import time
import argparse
import threading
from urllib import parse
from http.client import HTTPSConnection, HTTPConnection
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from subprocess import Popen, PIPE


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """ThreadingMixIn class allows to process each request in a separate thread"""
    daemon_threads = True


class HTTPSProxy(BaseHTTPRequestHandler):
    """Class than implements basic HTTP/HTTPS proxy"""
    timeout = 30
    cakey = 'ca.key'
    cacert = 'ca.crt'
    certkey = 'cert.key'
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.connections = []
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def generate_certificate(self, hostname=None):
        """Generates SSL certificates for each host"""
        if not os.path.exists("certs"):
            os.makedirs("certs")
        if not hostname:
            hostname = self.path.split(':')[0]
        site_certificate = os.path.join("certs", hostname + ".crt")

        with self.lock:
            if not os.path.isfile(site_certificate):
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=" + hostname], stdout=PIPE)
                p2 = Popen(
                    ["openssl", "x509", "-req", "-days", "7", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial",
                     epoch, "-out", site_certificate], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        return hostname, site_certificate

    def get_connection(self, scheme, netloc):
        """Return connection to given host"""
        if scheme == 'https':
            connection = HTTPSConnection(netloc, timeout=self.timeout)
        else:
            connection = HTTPConnection(netloc, timeout=self.timeout)
        return connection

    def close_connections(self):
        """Close all created connections. Called after processing the current request"""
        for connection in self.connections:
            connection.close()

    def recursive_request(self, connection, path, request_body, headers, depth=0, max_depth=10):
        """Handle HTTP/HTTPS request with resolving redirection"""
        if depth < max_depth:
            try:
                connection.request(self.command, path, request_body, headers)
            except ConnectionResetError:
                # Some hosts (for example, ad servers) may reject repeated requests from the client side,
                # which causes a ConnectionResetError error, and it must be suppressed
                return
            response = connection.getresponse()
            response_headers = dict(response.getheaders())
            if response_headers.get('Location'):
                redirect_location = response_headers.get('Location')
                u = parse.urlsplit(redirect_location)
                rscheme, rnetloc, rpath = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
                headers['Host'] = rnetloc
                rconnection = self.get_connection(rscheme, rnetloc)
                self.connections.append(rconnection)
                return self.recursive_request(rconnection, rpath, request_body, headers, depth + 1)
            else:
                return response

    def do_CONNECT(self):
        """Handle HTTPS CONNECT request"""
        self.send_response(200, 'Connection Established')
        self.end_headers()

        hostname, site_certificate = self.generate_certificate()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey,
                                          certfile=site_certificate, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        connection_type = self.headers.get('Proxy-Connection', '')
        if connection_type.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def do_GET(self):
        """Handle HTTP/HTTPS GET request"""
        content_length = int(self.headers.get('Content-Length', 0))
        request_body = self.rfile.read(content_length) if content_length else None

        if self.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                self.path = "https://" + self.headers['Host'] + self.path
            else:
                self.path = "http://" + self.headers['Host'] + self.path

        u = parse.urlsplit(self.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        if netloc:
            self.headers['Host'] = netloc
        if self.headers.get('Accept-Encoding'):
            # Cancel the use of compression
            del self.headers['Accept-Encoding']

        connection = self.get_connection(scheme, netloc)
        self.connections.append(connection)
        response = self.recursive_request(connection, path, request_body, dict(self.headers))

        if not response:
            self.close_connections()
            return

        response_body = response.read()
        response_body_new = self.response_handler(self, response_body, response, response_body)
        if response_body_new:
            response_body = response_body_new
            response.headers['Content-Length'] = str(len(response_body))

        self.send_response(response.status, response.reason)
        if response_body:
            try:
                self.wfile.write(response_body)
                self.wfile.flush()
            except BrokenPipeError:
                # If socket was closed by the browser before the request is completed
                # (for example, the user reloaded the page), this will cause a BrokenPipeError error
                pass

        self.close_connections()

    def response_handler(self, request, request_body, response, response_body):
        """This method can be used to implement mitm attack"""
        return None

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET


def run(server_class=ThreadingHTTPServer, handler_class=HTTPSProxy):
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', help='proxy server port', dest='port',
                        default=9090, type=int, metavar="{0..65535}")
    args = parser.parse_args()

    server_address = ('', args.port)
    server = server_class(server_address, handler_class)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    run()
