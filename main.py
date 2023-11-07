from blake3 import blake3
from hashlib import sha3_256
from miller_rabin import miller_rabin
import random
from mod import Mod
import math


def nBitRandom(n):
    # Returns a random number
    # between 2**(n-1)+1 and 2**n-1'''
    return (random.randrange(2**(n-1)+1, 2**n-1))


def key_gen():
    n = nBitRandom(257)
    while (not miller_rabin(n, 5000)):
        n = nBitRandom(257)
    g = n - 1
    return (n, g)


def get_keys(n, g, k):
    r = []
    for i in range(0, k):
        e = random.randrange(0, n)
        r.append((e, Mod(g, n) * e))
    return r


def mPECK(n, g, keys, words):
    s = random.randrange(0, n)
    r = random.randrange(0, n)
    A = Mod(g, n) * s
    B = [Mod(int(k[0]), n) * s for k in keys]
    C = [(Mod(int(blake3(int(w).to_bytes(length=32)).hexdigest(), 16), n) * r)
         + (Mod(int(sha3_256(int(w).to_bytes(length=32)).hexdigest(), 16), n) * s) for w in words]
    return (A, B, C)


def trapdoor(n, g, key, queries: ([int], [int])):
    t = random.randrange(0, n)
    T1 = Mod(g, n) * t
    # T2 = prod([int(blake3(q).hexdigest(), 16) for q in queries])
    T2 = sum([Mod(int(blake3(int(q).to_bytes(length=32)).hexdigest(), 16), n)
                    for q in queries[1]])*t
    T3 = sum([Mod(int(sha3_256(int(q).to_bytes(length=32)).hexdigest(), 16), n)
                    for q in queries[1]])*(Mod(t, n) - key)
    return (T1, T2, T3, queries[0])


def test(n, pk_index, S, T):
    def e_hat(a, b):
        o = Mod(int(a), n)
        return o + b

    return int(e_hat(T[0], sum([Mod(int(S[2][l]), n) for l in T[3]]))) == int(e_hat(S[0], T[1]) + e_hat(S[1][pk_index], T[2]))


# Testing
(n, g) = key_gen()
keys = get_keys(n, g, 5)
print(keys)
mpeck = mPECK(n, g, keys, [6, 14, 25, 39])
trapdoor = trapdoor(n, g, keys[0][0], ([0, 1, 2, 3], [6, 14, 25, 39]))
print(test(n, 0, mpeck, trapdoor))



