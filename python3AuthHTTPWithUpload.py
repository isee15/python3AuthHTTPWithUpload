#!/usr/bin/env python3

import argparse
import base64
import html
import http.server
import mimetypes
import os
import posixpath
import re
import shutil
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import HTTPServer
from io import BytesIO


class UploadHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTP request handler with GET/HEAD/POST commands.
    This serves files from the current directory and any of its
    subdirectories.  The MIME type for files is determined by
    calling the .guess_type() method. And can receive file uploaded
    by client.
    The GET/HEAD/POST requests are identical except that the HEAD
    request omits the actual contents of the file.
    """

    server_version = "AuthHTTPWithUpload/1.0"

    def do_GET(self):
        """Serve a GET request."""
        f = self.send_head()
        if f:
            self.copyfile(f, self.wfile)
            f.close()

    def do_HEAD(self):
        """Serve a HEAD request."""
        f = self.send_head()
        if f:
            f.close()

    def do_POST(self):
        """Serve a POST request."""
        r, info = self.deal_post_data()
        print((r, info, "by: ", self.client_address))
        f = BytesIO()
        f.write(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write(b"<html>\n<title>Upload Result Page</title>\n")
        f.write(b"<body>\n<h2>Upload Result Page</h2>\n")
        f.write(b"<hr>\n")
        if r:
            f.write(b"<strong>Success:</strong>")
        else:
            f.write(b"<strong>Failed:</strong>")
        f.write(info.encode())
        f.write(("<br><a href=\"%s\">back</a>" % self.headers['referer']).encode())
        f.write(b"</body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        if f:
            self.copyfile(f, self.wfile)
            f.close()

    def deal_post_data(self):
        content_type = self.headers['content-type']
        if not content_type:
            return False, "Content-Type header doesn't contain boundary"
        boundary = content_type.split("=")[1].encode()
        remain_bytes = int(self.headers['content-length'])
        line = self.rfile.readline()
        remain_bytes -= len(line)
        if boundary in line:
            line = self.rfile.readline()
            remain_bytes -= len(line)
            fn = re.findall(r'Content-Disposition.*name="file"; filename="(.*)"', line.decode())
            if not fn:
                return False, "Can't find out file name..."
            path = self.translate_path(self.path)
            fn = os.path.join(path, fn[0])
            line = self.rfile.readline()
            remain_bytes -= len(line)
            line = self.rfile.readline()
            remain_bytes -= len(line)
            try:
                out = open(fn, 'wb')
            except IOError:
                return False, "Can't create file to write, do you have permission to write?"

            preline = self.rfile.readline()
            remain_bytes -= len(preline)
            while remain_bytes > 0:
                line = self.rfile.readline()
                remain_bytes -= len(line)
                if boundary in line:
                    preline = preline[0:-1]
                    if preline.endswith(b'\r'):
                        preline = preline[0:-1]
                    out.write(preline)
                    out.close()
                    return True, "File '%s' upload success!" % fn
                else:
                    out.write(preline)
                    preline = line
            return False, "Unexpect Ends of data."
        return False, "Content NOT begin with boundary"

    def send_head(self):
        """Common code for GET and HEAD commands.
        This sends the response code and MIME headers.
        Return value is either a file object (which has to be copied
        to the outputfile by the caller unless the command was HEAD,
        and must be closed by the caller under all circumstances), or
        None, in which case the caller has nothing further to do.
        """
        path = self.translate_path(self.path)
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                # redirect browser - doing basically what apache does
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        ctype = self.guess_type(path)
        try:
            # Always read in binary mode. Opening files in text mode may cause
            # newline translations, making the actual size of the content
            # transmitted *less* than the content-length!
            f = open(path, 'rb')
        except IOError:
            self.send_error(404, "File not found")
            return None
        self.send_response(200)
        self.send_header("Content-type", ctype)
        fs = os.fstat(f.fileno())
        self.send_header("Content-Length", str(fs[6]))
        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f

    def list_directory(self, path):
        """Helper to produce a directory listing (absent index.html).
        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().
        """
        try:
            file_list = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        file_list.sort(key=lambda a: a.lower())
        f = BytesIO()
        file_path = html.escape(urllib.parse.unquote(self.path))
        f.write(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write(("<html>\n<title>Directory listing for %s</title>\n" % file_path).encode())
        f.write(("<body>\n<h2>Directory listing for %s</h2>\n" % file_path).encode())
        f.write(b"<hr>\n")
        f.write(b"<form ENCTYPE=\"multipart/form-data\" method=\"post\">")
        f.write(b"<input name=\"file\" type=\"file\"/>")
        f.write(b"<input type=\"submit\" value=\"upload\"/></form>\n")
        f.write(b"<hr>\n<ul>\n")
        for name in file_list:
            fullname = os.path.join(path, name)
            display_name = link_name = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                display_name = name + "/"
                link_name = name + "/"
            if os.path.islink(fullname):
                display_name = name + "@"
                # Note: a link to a directory displays with @ and links with /
            f.write(('<li><a href="%s">%s</a>\n'
                     % (urllib.parse.quote(link_name), html.escape(display_name))).encode())
        f.write(b"</ul>\n<hr>\n</body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        return f

    @staticmethod
    def translate_path(path):
        """Translate a /-separated PATH to the local filename syntax.
        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)
        """
        # abandon query parameters
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]
        path = posixpath.normpath(urllib.parse.unquote(path))
        words = path.split('/')
        words = [_f for _f in words if _f]
        path = os.getcwd()
        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir):
                continue
            path = os.path.join(path, word)
        return path

    @staticmethod
    def copyfile(source, output_file):
        """Copy all data between two file objects.
        The SOURCE argument is a file object open for reading
        (or anything with a read() method) and the DESTINATION
        argument is a file object open for writing (or
        anything with a write() method).
        The only reason for overriding this would be to change
        the block size or perhaps to replace newlines by CRLF
        -- note however that this the default server uses this
        to copy binary data as well.
        """
        shutil.copyfileobj(source, output_file)

    def guess_type(self, path):
        """Guess the type of a file.
        Argument is a PATH (a filename).
        Return value is a string of the form type/subtype,
        usable for a MIME Content-type header.
        The default implementation looks the file's extension
        up in the table self.extensions_map, using application/octet-stream
        as a default; however it would be permissible (if
        slow) to look inside the data to make a better guess.
        """

        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    if not mimetypes.inited:
        mimetypes.init()  # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream',  # Default
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
    })


NARGS = len(sys.argv)
ARGS = {}
temp_files = []


def get_args():
    parser = argparse.ArgumentParser(description="Python HTTPS Auth Server")
    parser.add_argument("-i", "--ip", help="Bind IP (Default all interfaces 0.0.0.0)", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", help="Bind port, default 8443", type=int, default=8000)
    parser.add_argument("-a", "--auth", help="HTTP BASIC auth  [username:password]", type=str, default='admin:admin')
    parser.add_argument("-s", "--https", help="Use HTTPS", action="store_true")
    parser.add_argument("-c", "--cert", help="If you brought your own CERT, then by all means... [fullpath]", type=str,
                        default=None)
    parser.add_argument("-k", "--privatekey",
                        help="If you brought your own PRIVATE_KEY, then by all means... [fullpath]",
                        type=str, default=None)
    ap, ap_garbage = parser.parse_known_args()
    ARGS = vars(ap)
    if (ARGS['cert'] and not ARGS['privatekey']) or (ARGS['privatekey'] and not ARGS['cert']):
        print(
            "[!] You can BYOC only when providing BOTH a certfile and matching private key! Else NEITHER, "
            "and generate a self-signed automatically")
        sys.exit()
    return ARGS


def gencert():
    # We're just going to generate self-signed certs...
    # https://www.linux.org/threads/creating-a-self-signed-certificate-with-python.9038/
    # https://markusholtermann.eu/2016/09/ssl-all-the-things-in-python/
    from OpenSSL import crypto
    from os.path import join
    from random import choice, randint
    from string import ascii_letters
    import tempfile
    import os.path
    CN = "SSLS"
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    cert = crypto.X509()
    cert.get_subject().C = "".join([choice(ascii_letters[:26]) for i in range(2)])
    cert.get_subject().ST = "".join([choice(ascii_letters[:26]) for i in range(2)])
    cert.get_subject().L = "".join([choice(ascii_letters[:26]) for i in range(0, randint(2, 32))])
    cert.get_subject().O = "".join([choice(ascii_letters[:26]) for i in range(0, randint(2, 32))])
    cert.get_subject().OU = "".join([choice(ascii_letters[:26]) for i in range(0, randint(2, 32))])
    cert.get_subject().CN = CN
    cert.set_serial_number(randint(1000, 9999))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(604800)  # 7 days...
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    CERT_FILE = "%s.crt" % CN
    PEM_FILE = "%s.pem" % CN
    PUBKEY_FILE = "%s.pub" % CN
    dirpath = tempfile.gettempdir()
    cert_dir = dirpath + os.path.sep
    C_F = join(cert_dir, CERT_FILE)
    K_F = join(cert_dir, PEM_FILE)
    P_F = join(cert_dir, PUBKEY_FILE)
    global temp_files
    temp_files.append(C_F)
    temp_files.append(K_F)
    temp_files.append(P_F)
    print("[#] Generating disposible, one-time-use, self-signed cert files in:  %s" % cert_dir)
    print("[.]%s\n[.]%s\n[.]%s" % (C_F, K_F, P_F))
    open(C_F, 'wt').write((crypto.dump_certificate(crypto.FILETYPE_PEM, cert)).decode("utf-8"))
    open(K_F, 'wt').write((crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey=k)).decode("utf-8"))
    open(P_F, 'wt').write((crypto.dump_publickey(crypto.FILETYPE_PEM, pkey=k)).decode("utf-8"))
    return C_F, K_F, P_F


class AuthHandler(UploadHTTPRequestHandler):
    def do_HEAD(self):
        print("send header")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        print("send header")
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"PROD\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        global ARGS
        key = base64.b64encode(bytes(ARGS['auth'].encode("utf-8")))
        ''' Present frontpage with user authentication. '''
        if self.headers.get('Authorization') is None:
            self.do_AUTHHEAD()
            self.wfile.write(bytes('no auth header received'.encode("utf-8")))
            pass
        elif self.headers.get('Authorization') == 'Basic ' + key.decode('utf-8'):
            UploadHTTPRequestHandler.do_GET(self)
            pass
        else:
            self.do_AUTHHEAD()
            self.wfile.write(bytes(self.headers.get('Authorization').encode("utf-8")))
            self.wfile.write(bytes('not authenticated'.encode("utf-8")))
            pass


def build_server(ARGS):
    if not ARGS['auth'] is None:
        httpd = HTTPServer((ARGS['ip'], ARGS['port']), AuthHandler)
    else:
        httpd = HTTPServer((ARGS['ip'], ARGS['port']), UploadHTTPRequestHandler)
    if ARGS['https']:
        if ARGS['cert'] and ARGS['privatekey']:
            CERT = ARGS['cert']
            PEM = ARGS['privatekey']
        else:
            global temp_files
            CERT, PEM, PUBKEY = gencert()
        httpd.socket = ssl.wrap_socket(httpd.socket, certfile=CERT, keyfile=PEM, server_side=True)
    try:
        print("[#] Now serving HTTP%s on %s:%s %s" % (
            "S" if ARGS['https'] else "",
            ARGS['ip'],
            ARGS['port'],
            "with AUTH " + ARGS['auth'] if ARGS['auth'] else ""
        ))
        print("[#] Ctrl+C to stop server\n")
        httpd.serve_forever()
    except TypeError:
        pass
    except KeyboardInterrupt:
        if len(temp_files) > 0:
            for item in temp_files:
                os.remove(item)
        sys.exit()


def main():
    global ARGS
    ARGS = get_args()
    build_server(ARGS)
    sys.exit()


if __name__ == "__main__":
    main()
