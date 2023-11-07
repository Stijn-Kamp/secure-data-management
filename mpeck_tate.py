from __future__ import annotations
from miller_rabin import miller_rabin
from random import randrange
from math import prod
from mod import Mod
from functools import reduce
from tate_bilinear_pairing import ecc, eta
from blake3 import blake3
from hashlib import sha3_256


class MPECK:
    def __init__(self):
        self.keycount = 0
        self.n: int = randrange(2**256, 2**257)
        while (not miller_rabin(self.n, 5000)):
            self.n = randrange(2**256, 2**257)
        eta.init(256)
        self.g = ecc.gen()

        def hash1(x: int):
            h = int(blake3(x.to_bytes(length=32)).hexdigest(), 16)
            return ecc.scalar_mult(h, self.g)

        def hash2(x: int):
            h = int(sha3_256(x.to_bytes(length=32)).hexdigest(), 16)
            return ecc.scalar_mult(h, self.g)

        self.h1 = hash1
        self.h2 = hash2

    def generate_key(self) -> (int, int):
        x: int = randrange(0, self.n)
        y = ecc.scalar_mult(x, self.g)
        self.keycount += 1
        return (y, x, self.keycount - 1)

    def add_doc(self, public_keys: [], keywords: [int]):
        s = randrange(0, self.n)
        r = randrange(0, self.n)
        A = ecc.scalar_mult(r, self.g)
        B = {pk[1]: ecc.scalar_mult(s, pk[0]) for pk in public_keys}
        C = [ecc.add(ecc.scalar_mult(r, self.h1(kw)),
                     ecc.scalar_mult(s, self.h2(kw))) for kw in keywords]
        return (A, B, C)

    def trapdoor(self, secret_key: int, query: [(int, int)]):
        t = randrange(0, self.n)
        T1 = ecc.scalar_mult(t, self.g)
        T2 = ecc.scalar_mult(
                t,
                reduce(ecc.add, [self.h1(qw[0]) for qw in query])
                )
        T3_exp = int((Mod(secret_key, self.n) ** -1) * t)
        T3 = ecc.scalar_mult(
                T3_exp,
                reduce(ecc.add, [self.h2(qw[0]) for qw in query])
                )
        return (T1, T2, T3, [qw[1] for qw in query])

    def test(self, public_key, S, T) -> bool:
        T1 = T[0]
        CI = reduce(ecc.add, [S[2][i] for i in T[3]])
        A = S[0]
        T2 = T[1]
        B = S[1][public_key]
        T3 = T[2]
        a = eta.pairing(T1[1], T1[2], CI[1], CI[2])
        b = eta.pairing(A[1], A[2], T2[1], T2[2])
        c = eta.pairing(B[1], B[2], T3[1], T3[2])
        print(a)
        print(b)
        print(c)
        print(ecc.add(b, c))
        return (a == b * c)


mpeck = MPECK()
key0 = mpeck.generate_key()
S = mpeck.add_doc([(key0[0], key0[2])], [1])
T = mpeck.trapdoor(key0[1], [(1, 0)])
print(mpeck.test(key0[2], S, T))
