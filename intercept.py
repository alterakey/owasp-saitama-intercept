from __future__ import annotations
import asyncio
import datetime
import hashlib
import io
import os
import re
import ssl
import sys
import urllib.parse
from typing import TYPE_CHECKING

import httptools
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

if TYPE_CHECKING:
    from typing import Tuple, Optional, Any, List, Union
    from cryptography.hazmat.primitives.asymmetric.types import PRIVATE_KEY_TYPES

class ProxyProtocol(asyncio.Protocol):
    gen: CertGenerator
    _srsf: StrictRequestStreamFactory
    _loop: asyncio.AbstractEventLoop
    _transport: Optional[asyncio.Transport]
    _transport2: Optional[asyncio.Transport]
    _transport2p: Optional[asyncio.Transport]

    def __init__(self, gen: CertGenerator) -> None:
        self._loop = asyncio.get_running_loop()
        self.gen = gen
        self._srsf = StrictRequestStreamFactory()
        self._transport = None
        self._transport2 = None
        self._transport2p = None

    def connection_made(self, transport: Any) -> None:
        self._transport = transport

    def data_received(self, data: Any) -> None:
        assert self._transport
        if not self._transport2 and not self._transport2p:
            method, url = self._parse_req_method_url(data)
            if method.lower() == 'connect':
                t = urllib.parse.urlparse(f'//{url.decode()}/')
                assert t.hostname and t.port
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = ssl.TLSVersion.SSLv3
                context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
                context.options &= ~(ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.load_default_certs()
                self._loop.create_task(self._prepare_connection(lambda: ClientProtocol(self, t), t.hostname, t.port, ssl=context))
            else:
                t = urllib.parse.urlparse(url.decode())
                assert t.scheme.lower() == 'http' and t.hostname
                self._loop.create_task(self._prepare_connection(lambda: ClientProtocol0(self, data), t.hostname, 80 if t.port is None else t.port))
        elif self._transport2:
            assert not self._transport2p
            for r in self._srsf.feed_data(data):
                if not isinstance(r, Exception):
                    Printer.req(r.literal)
                    self._transport2.write(r.literal)
                else:
                    print(f'[-] cannot parse request, {str(r)}', file=sys.stderr)
                    self._transport2.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
        elif self._transport2p:
            assert not self._transport2
            data = re.sub(rb'^([A-Z]+) http://.+?/', rb'\1 /', data, count=1, flags=re.DOTALL)
            for r in self._srsf.feed_data(data):
                if not isinstance(r, Exception):
                    Printer.req(r.literal)
                    self._transport2p.write(r.literal)
                else:
                    print(f'[-] cannot parse request, {str(r)}', file=sys.stderr)
                    self._transport2p.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')

    def connection_lost(self, exc: Any) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None
        if self._transport2:
            self._transport2.close()
            self._transport2 = None
        if self._transport2p:
            self._transport2p.close()
            self._transport2p = None

    async def _prepare_connection(self, pf: Any, host: Any, port: Any, ssl: Any=None) -> None:
        try:
            await self._loop.create_connection(pf, host, port, ssl=ssl)
        except Exception as e:
            if ssl is not None:
                print(f"[-] cannot establish TLS connection to {host}:{port}: {str(e)}", file=sys.stderr)
            else:
                print(f'[-] cannot connect to {host}:{port}: {str(e)}', file=sys.stderr)
            if self._transport:
                self._transport.write(b'HTTP/1.1 503 Service Not Available\r\n\r\n')
                self._transport.close()
                self._transport = None

    def _parse_req_method_url(self, data: bytes) -> Tuple[str, bytes]:
        f: io.BytesIO = io.BytesIO(data)
        statusline = f.readline().rstrip(b'\r\n')
        meth, path, vers = statusline.split(b' ', maxsplit=2)
        return meth.decode(), path

class Printer:
    @staticmethod
    def req(data: bytes) -> None:
        if b'\x00' not in data:
            print('>>> {}'.format(data.decode('utf-8', errors='replace')))
        else:
            print('>>> (binary)')

    @staticmethod
    def resp(data: bytes) -> None:
        if b'\x00' not in data:
            print('<<< {}'.format(data.decode('utf-8', errors='replace')))
        else:
            print('<<< (binary)')

class ClientProtocol0(asyncio.Protocol):
    _proxy: ProxyProtocol
    _srsf: StrictResponseStreamFactory
    _initial_data: Any

    def __init__(self, proxy: ProxyProtocol, initial_data: Any) -> None:
        self._proxy = proxy
        self._srsf = StrictResponseStreamFactory()
        self._initial_data = initial_data

    def connection_made(self, transport: Any) -> None:
        self._proxy._transport2p = transport
        if self._initial_data:
            self._proxy.data_received(self._initial_data)

    def data_received(self, data: Any) -> None:
        if self._proxy._transport is None:
            if self._proxy._transport2p is not None:
                self._proxy._transport2p.close()
                self._proxy._transport2p = None
        else:
            for resp in self._srsf.feed_data(data):
                if not isinstance(resp, Exception):
                    Printer.resp(resp.literal)
                    self._proxy._transport.write(resp.literal)
                else:
                    print(f'[-] cannot parse response, {str(resp)}', file=sys.stderr)
                    self._proxy._transport.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')

    def connection_lost(self, exc: Any) -> None:
        self._proxy.connection_lost(exc)

class ClientProtocol(asyncio.Protocol):
    _proxy: ProxyProtocol
    _srsf: StrictResponseStreamFactory

    def __init__(self, proxy: ProxyProtocol, urlcomp: Any) -> None:
        self._proxy = proxy
        self._srsf = StrictResponseStreamFactory()
        self._urlcomp = urlcomp

    def connection_made(self, transport: Any) -> None:
        loop = asyncio.get_running_loop()
        loop.create_task(ClientProtocol.try_connect(loop, self, transport))

    @staticmethod
    async def try_connect(loop: Any, p: ClientProtocol, t: Any) -> None:
        assert p._proxy.gen is not None
        if p._proxy._transport is None:
            t.close()
        else:
            p._proxy._transport2 = t

            peercert = t.get_extra_info('peercert')
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            cert, key = p._proxy.gen.generate(peercert.get('subject', {}).get('commonName', p._urlcomp.hostname))
            context.load_cert_chain(cert, key)
            p._proxy._transport.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            p._proxy._transport = await loop.start_tls(p._proxy._transport, p._proxy, context, server_side=True)

    def data_received(self, data: Any) -> None:
        if self._proxy._transport is None:
            if self._proxy._transport2 is not None:
                self._proxy._transport2.close()
                self._proxy._transport2 = None
        else:
            for resp in self._srsf.feed_data(data):
                if not isinstance(resp, Exception):
                    Printer.resp(resp.literal)
                    self._proxy._transport.write(resp.literal)
                else:
                    print(f'[-] cannot parse response, {str(resp)}', file=sys.stderr)
                    self._proxy._transport.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')


    def connection_lost(self, exc: Any) -> None:
        self._proxy.connection_lost(exc)

class CertGenerator:
    _cacert: x509.Certificate
    _cakey: PRIVATE_KEY_TYPES
    _root: str
    _cacertpath: str
    _cakeypath: str
    def __init__(self, root: str) -> None:
        self._root = root
        self._cacertpath = os.path.join(root, 'ca.pem')
        self._cakeypath = os.path.join(root, 'ca.key')
        with open(self._cacertpath, 'rb') as f:
            self._cacert = x509.load_pem_x509_certificate(f.read())
        with open(self._cakeypath, 'rb') as f:
            self._cakey = serialization.load_pem_private_key(f.read(), None)

    def generate(self, cn: str) -> Tuple[str, str]:
        path = self._get_cert_path(cn)
        if os.path.exists(path):
            return path, self._cakeypath
        else:
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            builder = builder.issuer_name(self._cacert.subject)
            builder = builder.not_valid_before(datetime.datetime.today()-datetime.timedelta(days=1))
            builder = builder.not_valid_after(datetime.datetime.today()+datetime.timedelta(days=30))
            builder = builder.add_extension(x509.BasicConstraints(ca=False,path_length=None), critical=True)
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(self._cakey.public_key())
            cert = builder.sign(private_key=self._cakey, algorithm=hashes.SHA256())
            self._put_cert_data(cn, cert.public_bytes(serialization.Encoding.PEM))
            return path, self._cakeypath

    def _get_cert_path(self, cn: str) -> str:
        return os.path.join(self._root, hashlib.sha1(cn.encode()).hexdigest() + '.pem')

    def _put_cert_data(self, cn: str, data: bytes) -> None:
        with open(self._get_cert_path(cn), 'wb') as f:
            f.write(data)

class CAGenerator:
    _root: str
    _cacertpath: str
    _cakeypath: str
    def __init__(self, root: str) -> None:
        self._root = root
        self._cacertpath = os.path.join(root, 'ca.pem')
        self._cakeypath = os.path.join(root, 'ca.key')

    def generate(self) -> None:
        private_key: Optional[PRIVATE_KEY_TYPES] = None

        if not os.path.exists(self._cakeypath):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            self._put_ca_key_data(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

        if not os.path.exists(self._cacertpath):
            if private_key is None:
                with open(self._cakeypath, 'rb') as f:
                    private_key = serialization.load_pem_private_key(f.read(), None)

            assert private_key is not None

            builder = x509.CertificateBuilder()
            builder = builder.subject_name(self._subject_name())
            builder = builder.issuer_name(self._subject_name())
            builder = builder.not_valid_before(datetime.datetime.today()-datetime.timedelta(days=1))
            builder = builder.not_valid_after(datetime.datetime.today()+datetime.timedelta(days=10*365))
            builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(private_key.public_key())
            cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
            self._put_ca_cert_data(cert.public_bytes(serialization.Encoding.PEM))

    def _subject_name(self) -> x509.Name:
        return x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Intercepting 101'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'Intercepting 101 CA')
        ])

    def _put_ca_cert_data(self, data: bytes) -> None:
        with open(self._cacertpath, 'wb') as f:
            f.write(data)

    def _put_ca_key_data(self, data: bytes) -> None:
        with open(self._cakeypath, 'wb') as f:
            f.write(data)

class Request:
    literal: bytes = b''
    def __init__(self, literal: bytes) -> None:
        self.literal = literal

class Response:
    literal: bytes = b''
    def __init__(self, literal: bytes) -> None:
        self.literal = literal

class StrictRequestStreamFactory:
  _content: bytearray
  _parser: httptools.HttpRequestParser
  _results: List[Union[Request, Exception]]
  def __init__(self) -> None:
    self._content = bytearray()
    self._parser = httptools.HttpRequestParser(self)
    self._results = []

  def feed_data(self, data: bytes) -> List[Union[Request, Exception]]:
    self._results.clear()
    for c in data.splitlines(keepends=True):
      try:
        self._parser.feed_data(c)
      except Exception as e:
        self._results.append(e)
        self._content.clear()
      else:
        self._content.extend(c)
    return self._results

  def on_message_begin(self) -> None:
    self._content.clear()
  def on_message_complete(self) -> None:
    self._results.append(Request(self._content))

class StrictResponseStreamFactory:
  _content: bytearray
  _parser: httptools.HttpResponseParser
  _results: List[Union[Response, Exception]]
  def __init__(self) -> None:
    self._content = bytearray()
    self._parser = httptools.HttpResponseParser(self)
    self._results = []

  def feed_data(self, data: bytes) -> List[Union[Response, Exception]]:
    self._results.clear()
    for c in data.splitlines(keepends=True):
      try:
        self._parser.feed_data(c)
      except Exception as e:
        self._results.append(e)
        self._content.clear()
      else:
        self._content.extend(c)
    return self._results

  def on_message_begin(self) -> None:
    self._content.clear()
  def on_message_complete(self) -> None:
    self._results.append(Response(self._content))


async def main(host_port: Tuple[str,int], gen: CertGenerator) -> None:
    loop = asyncio.get_running_loop()

    s = await loop.create_server(lambda: ProxyProtocol(gen), host_port[0], host_port[1])
    async with s: await s.serve_forever()

if __name__ == '__main__':
    root = "keytab.d"
    os.makedirs(root, exist_ok=True)
    CAGenerator(root).generate()
    gen = CertGenerator(root)
    asyncio.run(main(('127.0.0.1', 8888), gen))
