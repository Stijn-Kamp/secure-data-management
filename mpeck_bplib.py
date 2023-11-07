from __future__ import annotations
from miller_rabin import miller_rabin
from random import randrange
from math import prod
from mod import Mod
from functools import reduce
from blake3 import blake3
from hashlib import sha3_256
from py_ecc.bn128 import G1, G2, pairing, add, multiply, eq
import logging

logging.basicConfig(level=logging.DEBUG)


class MPECK:
    """
    class used for the MPECK scheme
    """

    def __init__(self):
        self.keycount = 0  # number of keys generated

        # Generate a random prime number of 256 bits using the miller rabin test
        self.n: int = randrange(2**256, 2**257)
        while not miller_rabin(self.n, 5000):
            self.n = randrange(2**256, 2**257)

        # Define the hash functions
        def hash1(x: int):
            h = int(blake3(x.to_bytes(length=32, byteorder="big")).hexdigest(), 16)
            return multiply(G1, h)

        def hash2(x: int):
            h = int(sha3_256(x.to_bytes(length=32, byteorder="big")).hexdigest(), 16)
            return multiply(G1, h)

        self.h1 = hash1
        self.h2 = hash2

    def generate_key(self) -> (int, int):
        """
        Generates a key pair (public key, secret key)

        Returns:
            (int, int, int): public key, secret key, key id
        """
        x: int = randrange(0, self.n)
        y = multiply(G2, x)
        self.keycount += 1
        return (y, x, self.keycount - 1)

    def add_doc(self, public_keys: [], keywords: [int]):
        """
        This function simulates adding a document to the MPECK system, associating it with specific keywords.

        Args:
            public_keys ([int]): list of public keys
            keywords ([int]): list of keywords

        Returns:
            (int, [int], [int]): A, B, C
        """
        s = randrange(0, self.n)
        r = randrange(0, self.n)
        A = multiply(G2, r)
        B = {pk[1]: multiply(pk[0], s) for pk in public_keys}
        C = [add(multiply(self.h1(kw), r), multiply(self.h2(kw), s)) for kw in keywords]
        print(type(C))
        return (A, B, C)

    def trapdoor(self, secret_key: int, query: [(int, int)]):
        """
        This function generates a trapdoor for a given secret key and a query.

        Args:
            secret_key (int): the secret key
            query ([int]): the query

        Returns:
            (int, int, int, [int]): T1, T2, T3, C
        """
        t = randrange(0, self.n)
        T1 = multiply(G2, t)
        print(type(T1))
        T2 = multiply(reduce(add, [self.h1(qw[0]) for qw in query]), t)
        T3_exp = int((Mod(secret_key, self.n) ** -1) * t)
        T3 = multiply(reduce(add, [self.h2(qw[0]) for qw in query]), T3_exp)
        return (T1, T2, T3, [qw[1] for qw in query])

    def test(self, public_key, S, T) -> bool:
        """
        This function tests the validity of a search given a public key, search results (S), and a trapdoor (T).

        Args:
            public_key (int): the public key
            S (int, [int], [int]): the search results
            T (int, int, int, [int]): the trapdoor

        Returns:
            bool: True if the search is valid, False otherwise
        """
        T1 = T[0]
        CI = reduce(add, [S[2][i] for i in T[3]])
        print(type(CI))
        A = S[0]
        T2 = T[1]
        B = S[1][public_key]
        T3 = T[2]

        a = pairing(T1, CI)
        b = pairing(A, T2)
        c = pairing(B, T3)

        print(a)
        print(b)
        print(c)
        print(b * c)
        return a == b * c


if __name__ == "__main__":
    # Test the MPECK scheme
    mpeck = MPECK()  # Initialize the MPECK scheme
    key0 = mpeck.generate_key()  # Generate a key pair for the first user
    S = mpeck.add_doc([(key0[0], key0[2])], [1])  # Add a document to the MPECK system
    T = mpeck.trapdoor(key0[1], [(1, 0)])  # Generate a trapdoor for the first user
    print(mpeck.test(key0[2], S, T))  # Test the validity of the search
