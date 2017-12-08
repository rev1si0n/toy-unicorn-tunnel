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
import os
import struct
import hashlib
from Crypto.Cipher import ARC4


class Cryptor:
    def __init__(self, key=None):
        pass

    def new(self):
        return Cryptor()
    
    def enc(self, data):
        return data

    def dec(self, data):
        return data


class RC4Cryptor(Cryptor):

    def __init__(self, key):
        if not isinstance(key, bytes):
            key = key.encode('utf-8')

        self.key = key
        self.rc4se = None
        self.rc4sd = None

    def enc(self, data):
        return self.rc4se.encrypt(data)

    def dec(self, data):
        return self.rc4sd.decrypt(data)

    def new(self):
        cr = RC4Cryptor(self.key)
        sha1 = hashlib.sha1(self.key)
        cr.rc4se = ARC4.new(sha1.digest())
        cr.rc4sd = ARC4.new(sha1.digest())
        return cr
