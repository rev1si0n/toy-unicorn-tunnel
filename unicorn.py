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


__all__ = ['Unicorn', 'BaseProtocol', 'TCPRelay', 'UDPRelay']


class BaseProtocol(asyncio.Protocol, asyncio.DatagramProtocol):

    # Constants
    WAIT_CMD = 0
    UDP_TUNNEL_MODE = 1
    TCP_TUNNEL_MODE = 2

    CMD_CONNECT = 1
    CMD_BIND = 2
    CMD_UDP_ASSOC = 3

    ADDR_DOMAIN = 3
    ADDR_IPV4 = 1
    ADDR_IPV6 = 4

    def __init__(self, loop, cryptor):

        self.loop = loop
        self.transport = None
        self.cryptor = cryptor.new()

        self._peer_addr = None
        self._tcp_tunnel = None
        self._udp_tunnel = None
        self._local_addr = None
        self._sock_family = None
        self._status = self.WAIT_CMD

    def connection_made(self, transport):
        self.transport = transport
        try:
            sock = transport.get_extra_info("socket")
            self._sock_family = sock.family
            self._local_addr = sock.getsockname()[:2]
            self._peer_addr = sock.getpeername()[:2]
        except OSError:
            pass

    def request(self, data):
        sign, _c, _at, _al = struct.unpack("!HBBB", data[:5])
        if sign == 0x504b and _at \
            in (self.ADDR_DOMAIN, self.ADDR_IPV4, self.ADDR_IPV6):
            inet_ntop = socket.inet_ntop
            family = self._get_atype_family(_at)

            if _at == self.ADDR_DOMAIN:
                s = slice(0x05, 0x05 + _al)
                addr = data[s].decode('idna')

            elif _at == self.ADDR_IPV4:
                s = slice(0x05, 0x09)
                addr = inet_ntop(family, data[s])

            elif _at == self.ADDR_IPV6:
                s = slice(0x05, 0x15)
                addr = inet_ntop(family, data[s])

            s = slice(s.stop, s.stop + 2)
            params = list([_c, family, addr])
            params.append(struct.unpack("!H", data[s])[0])
            params.append(s.stop)
            return params

        return (-1,) * 5

    def _get_response_atype(self, family):
        if family == socket.AF_INET:
            return self.ADDR_IPV4
        elif family == socket.AF_INET6:
            return self.ADDR_IPV6
        else:
            return self.ADDR_DOMAIN

    def _get_atype_family(self, atype):
        if atype == self.ADDR_IPV4:
            return socket.AF_INET
        elif atype == self.ADDR_IPV6:
            return socket.AF_INET6
        else:
            return 0

    def data_received(self, data):
        # 解密客户端->server的消息
        data = self.cryptor.dec(data)
        self.on_data_received(data)

    def datagram_received(self, data, addr):
        # 如果是客户端发送的数据包则解密
        if addr == self._peer_addr:
            data = self.cryptor.dec(data)
            f = self.on_client_datagram_received
        else:
            f = self.on_remote_datagram_received
        f(data, addr)

    def send_to_remote(self, data, addr=None):
        # 如果提供了addr则代表UDP发送（UDP中继调用）
        # 否则使用TCP发送, 中继不加密发往远端的消息
        if isinstance(addr, tuple):
            sock = self.transport._sock
            sock.sendto(data, addr)
            return

        self.transport.write(data)

    def send_to_client(self, data, addr=None):
        # 加密发往客户端的消息
        data = self.cryptor.enc(data)
        self.send_to_remote(data, addr)

    def on_remote_datagram_received(self, data, addr):
        raise NotImplementedError

    def on_client_datagram_received(self, data, addr):
        raise NotImplementedError

    def on_data_received(self, data):
        raise NotImplementedError


class TCPRelay(BaseProtocol):

    def data_received(self, data):
        # TCP 远端地址发送的数据包
        # 转发到客户端
        self.local.send_to_client(data)

    def connection_lost(self, exc):
        # 连接丢失
        # 调用客户端连接进行清理
        self.local._clean_up()


class UDPRelay(BaseProtocol):

    def on_client_datagram_received(self, data, addr):
        # 客户端发送来的数据
        # 解析出目的地址并发送UDP包
        cmd, _, host, port, sp = self.request(data)
        if cmd == -1:
            return

        addr = (host, port)
        sock = self.transport._sock
        sock.sendto(data[sp:], addr)

    def on_remote_datagram_received(self, data, addr):
        # 远端服务器发送的数据
        # 打包并发送到客户端端口
        P = struct.pack
        i, p = addr
        f = self._sock_family
        f_ = self._get_response_atype(f)
        n = socket.inet_pton(f, i)
        fmt = "!HBBB%dsH%ds" % (len(n), len(data))
        payload = P(fmt, 0x504b, 0x00, f_, 0x00, n, p, data)

        self.send_to_client(payload, addr=self._peer_addr)


class Unicorn(BaseProtocol):

    @asyncio.coroutine
    def _do_connect(self, host, port):
        try:
            transport, local2remote = yield from asyncio.wait_for(
                self.loop.create_connection(
                    lambda :TCPRelay(self.loop, self.cryptor),
                    host=host,
                    port=port
                ),
            15)
            local2remote.local = self
            self._tcp_tunnel = local2remote
            self._status = self.TCP_TUNNEL_MODE

            e = 0x00 # no errors
            f = local2remote._sock_family
            i, p = local2remote._peer_addr
            f_ = self._get_response_atype(f)

        except (asyncio.TimeoutError, OSError):
            e = 0x04 # host unreachable
            f = socket.AF_INET
            f_ = self.ADDR_IPV4
            i, p = '0.0.0.0', 0
            pass

        # send info to client
        P = struct.pack
        n = socket.inet_pton(f, i)
        payload = P("!HBBB%dsH" % len(n), 0x504b, e, f_, 0x00, n, p)
        self.send_to_client(payload)

    @asyncio.coroutine
    def _do_udp_assoc(self, host, port):
        if host == '0.0.0.0':
            host, _ = self._peer_addr
        try:
            local, _ = self._local_addr
            transport, local2client = yield from asyncio.wait_for(
                self.loop.create_datagram_endpoint(
                    lambda :UDPRelay(self.loop, self.cryptor),
                    local_addr=(local, 0)
                ),
            15)
            self._udp_tunnel = local2client
            self._status = self.UDP_TUNNEL_MODE
            local2client._peer_addr = (host, port)

            e = 0x00
            f = local2client._sock_family
            i, p = local2client._local_addr
            f_ = self._get_response_atype(f)

        except (asyncio.TimeoutError, OSError):
            e = 0x04
            f = socket.AF_INET
            f_ = self.ADDR_IPV4
            i, p = '0.0.0.0', 0
            pass

        # send info to client
        P = struct.pack
        n = socket.inet_pton(f, i)
        payload = P("!HBBB%dsH" % len(n), 0x504b, e, f_, 0x00, n, p)
        self.send_to_client(payload)

    def on_data_received(self, data):
        if self._status == self.TCP_TUNNEL_MODE:
            # 进入 TCP 模式, 转发所有数据包
            self._tcp_tunnel.send_to_remote(data)
            return

        if self._status == self.UDP_TUNNEL_MODE:
            # UDP模式保持连接, 丢掉所有包
            return

        cmd, _, host, port, *_ = self.request(data)
        if cmd == self.CMD_CONNECT or cmd == self.CMD_BIND:
            # CONNECT just like the BIND command
            cr = self._do_connect(host, port)
            asyncio.ensure_future(cr)
            return
        if cmd == self.CMD_UDP_ASSOC:
            cr = self._do_udp_assoc(host, port)
            asyncio.ensure_future(cr)
            return

        # unknow command
        self._clean_up()

    def connection_lost(self, exc):
        self._clean_up()

    def _clean_up(self):
        if self._tcp_tunnel:
            self._tcp_tunnel.transport.close()
        if self._udp_tunnel:
            self._udp_tunnel.transport.close()
        self.transport.close()


if __name__ == "__main__":
    from cryptor import Cryptor, RC4Cryptor
    try:
        import uvloop
        loop = uvloop.new_event_loop()
        asyncio.set_event_loop(loop)
    except ImportError:
        pass

    cryptor = RC4Cryptor('password')
    loop = asyncio.get_event_loop()
    server = loop.run_until_complete(loop.create_server(
        functools.partial(Unicorn, loop, cryptor),
        host='0.0.0.0',
        port=1240
    ))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
