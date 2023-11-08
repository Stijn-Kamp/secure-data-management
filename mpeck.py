from __future__ import annotations
from miller_rabin import miller_rabin
from random import randrange
from math import prod
from mod import Mod
from functools import reduce
from blake3 import blake3
from hashlib import sha3_256
from pypbc import *


class MPECK:
    def __init__(self):
        self.params = Parameters()
        self.bilinear_map = Pairing(self.params)
        self.g = Element.random(self.bilinear_map, G1)
        self.keycount = 0

        def hash1(x: int):
            h = int(blake3(x.to_bytes(length=32, byteorder='big')).hexdigest(), 16)
            return Element(self.bilinear_map, G1, value=self.g**h)

        def hash2(x: int):
            h = int(sha3_256(x.to_bytes(length=32, byteorder='big')).hexdigest(), 16)
            return Element(self.bilinear_map, G1, value=self.g**h)

        def e(e1, e2):
            return self.bilinear_map.apply(e1, e2)

        self.h1 = hash1
        self.h2 = hash2
        self.e = e

    def generate_key(self) -> (Element, Element, int):
        x = Element.random(self.bilinear_map, Zr)
        y = Element(self.bilinear_map, G1, value=self.g**x)
        self.keycount += 1
        return (y, x, self.keycount - 1)

    def add_doc(self, public_keys: [], keywords: [int]):
        s = Element.random(self.bilinear_map, Zr)
        r = Element.random(self.bilinear_map, Zr)
        A = Element(self.bilinear_map, G1, value=self.g**r)
        for pk in public_keys:
            print(type(pk))
        B = {pk[1]: Element(self.bilinear_map, G1, value=pk[0]**s) for pk in public_keys}
        C = [Element(self.bilinear_map, G1, value=(self.h1(kw)**r) * (self.h2(kw)**s)) for kw in keywords]
        return (A, B, C)

    def trapdoor(self, secret_key: int, query: [(int, int)]):
        t = Element.random(self.bilinear_map, Zr)
        T1 = self.g**t
        T2: Element = Element.one(self.bilinear_map, G1)
        for keyword in query:
            T2 = T2 * self.h1(keyword[0])
        T2 **= t
        T3: Element = Element.one(self.bilinear_map, G1)
        for keyword in query:
            T3 = T3 * self.h2(keyword[0])
        T3 **= t.__ifloordiv__(secret_key)
        print(T1, T2, T3)
        return (T1, T2, T3, [qw[1] for qw in query])

    def test(self, public_key, S, T) -> bool:
        T1 = T[0]
        CI = Element.one(self.bilinear_map, G1)
        for i in T[3]:
            CI = CI * S[2][i]
        print(type(CI))
        A = S[0]
        T2 = T[1]
        B = S[1][public_key]
        T3 = T[2]
        a = self.e(T1, CI)
        b = self.e(A, T2)
        c = self.e(B, T3)
        print(a)
        print(b)
        print(B)
        print("T3")
        print(T3)
        print(c)
        print(b * c)
        return (a == b * c)


mpeck = MPECK()
print("a")
key0 = mpeck.generate_key()
print("b")
S = mpeck.add_doc([(key0[0], key0[2])], [1])
print("c")
T = mpeck.trapdoor(key0[1], [(1, 0)])
print("d")
print(mpeck.test(key0[2], S, T))
