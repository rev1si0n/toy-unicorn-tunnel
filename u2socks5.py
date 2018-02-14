#!/usr/bin/env python3
#encoding=utf8
#
#   Copyright 2017 thisforeda
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
import struct
import socket
import asyncio
import functools
from unicorn import BaseProtocol


P = struct.pack
U = struct.unpack
UP = lambda b: U("!H", b)[0]


class SOCKS5(BaseProtocol):

    STAGE_CONN_MADE = 0
    STAGE_AUTH_DONE = 2
    STAGE_TUNNEL_STREAMING = 3
    ATYPE_DOMAIN = 3
    ATYPE_IPV4 = 1
    ATYPE_IPV6 = 4

    def __init__(self, loop, cryptor, server):

        self.loop = loop
        self.transport = None
        self.cryptor = cryptor.new()
        self.server = server
        self._tcp_tunnel = None
        self._status = self.STAGE_CONN_MADE

    def data_received(self, data):
        if self._status == self.STAGE_TUNNEL_STREAMING:
            self._tcp_tunnel.send_to_remote(data)
            return

        if self._status == self.STAGE_CONN_MADE:
            v, nm, m = U("!BBB", data[:3])
            if v == 0x05 and m == 0x00:
                self._status = self.STAGE_AUTH_DONE
                self.transport.write(b"\x05\x00")
                return

            self.transport.close()

        if self._status == self.STAGE_AUTH_DONE:
            cmd, rsv, at, *_ = U("!BBB", data[1:4])
            if at == self.ATYPE_DOMAIN:
                l = U("!B", data[4:5])[0]
                a = data[5: 5 + l]
                p = UP(data[5 + l: 7 + l])
            elif at == self.ATYPE_IPV4:
                a = data[4: 8]
                p = UP(data[8: 12])
            elif at == self.ATYPE_IPV6:
                a = data[4:20]
                p = UP(data[20: 22])

        c = self.unicorn_tcp_tunnel(a,p,at,cmd)
        asyncio.ensure_future(c)

    def connection_lost(self, exc):
        self.transport.close()
        if self._tcp_tunnel:
            self._tcp_tunnel.transport.close()

    @asyncio.coroutine
    def unicorn_tcp_tunnel(self, host, port, at, cmd):
        class TcpRelay(asyncio.Protocol):

            def data_received(self, data):
                data = self.local.cryptor.dec(data)
                if self._proto_packet:
                    data = P("!B2sB6s",5 , b'\x00', 1, b'\x00')
                    self._proto_packet = False

                self.local.transport.write(data)

            def send_to_remote(self, data):
                data = self.local.cryptor.enc(data)
                self.transport.write(data)

            def connection_made(self, transport):
                self.transport = transport
                self._proto_packet = True

        try:
            al = len(host)
            payload = self.cryptor.enc(
                P("!HBBB%dsH" % al,
                    0x504b,
                    cmd,
                    at,
                    al,
                    host,
                    port
                )
            )
            transport, u = yield from asyncio.wait_for(
                self.loop.create_connection(
                    TcpRelay,
                    host=self.server['host'],
                    port=self.server['port']
                ),
            15)
            self._status = self.STAGE_TUNNEL_STREAMING
            u.local = self
            self._tcp_tunnel = u
            transport.write(payload)
        except (asyncio.TimeoutError, OSError):
            self.transport.close()
            return


if __name__ == "__main__":
    import sys
    from cryptor import Cryptor, RC4Cryptor
    try:
        if len(sys.argv) != 3:
            raise Exception("missing arguments.")

        Lhost, Lport = sys.argv[1].split(":")
        Rhost, Rport, Rpasswd = sys.argv[2].split(":")
    except Exception as err:
        print (str(err))
        print ("example argument line: local_address:local_port server_address:server_port:remote_passwd")
        exit(1)

    cryptor = RC4Cryptor(Rpasswd)
    loop = asyncio.get_event_loop()
    server = loop.run_until_complete(loop.create_server(
        functools.partial(SOCKS5, loop, cryptor, {'host': Rhost, 'port': Rport}),
        host=Lhost,
        port=Lport
    ))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
