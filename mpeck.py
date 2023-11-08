from __future__ import annotations
from blake3 import blake3
from hashlib import sha3_256
from pypbc import *
from Crypto.Cipher import AES


class MPECK:
    def __init__(self):
        """
        Create the MPECK object. This sets the global variables for the class.
        These global variables are always the same, but the object does keep
        track of the amount of keys handed out, and the same object should
        therefore be used by all people for now.
        """
        self.params = Parameters()
        self.bilinear_map = Pairing(self.params)
        self.g = Element.random(self.bilinear_map, G1)
        self.keycount = 0

        def hash1(x: str):
            h = int(blake3(bytes(x, 'utf-8')).hexdigest(), 16)
            return Element(self.bilinear_map, G1, value=self.g**h)

        def hash2(x: str):
            h = int(sha3_256(bytes(x, 'utf-8')).hexdigest(), 16)
            return Element(self.bilinear_map, G1, value=self.g**h)

        def e(e1, e2):
            return self.bilinear_map.apply(e1, e2)

        self.h1 = hash1
        self.h2 = hash2
        self.e = e

    def generate_key(self) -> (Element, Element, int):
        """
        Generate a new key for the MPECK object and give it an index.

        :return: A tuple of (pk, sk, index)
        """
        x = Element.random(self.bilinear_map, Zr)
        y = Element(self.bilinear_map, G1, value=self.g**x)
        self.keycount += 1
        return (y, x, self.keycount - 1)

    def add_doc(self, public_keys: [(Element, int)], keywords: [str], message: str) -> (str, (Element, dict[int, Element])):
        """
        Compute the values to be stored for a document that is added to the
        system.

        :param [(Element,int)] public_keys: A list of public keys and their indexes to give access to the document.
        :param [str] keywords: A list of keywords to add to the document.
        :param str message: The text of the document.

        :return: A tuple of (ciphertext, (A, B, C))
        """
        s = Element.random(self.bilinear_map, Zr)
        r = Element.random(self.bilinear_map, Zr)
        A = Element(self.bilinear_map, G1, value=self.g**r)
        for pk in public_keys:
            print(type(pk))
        B = {pk[1]: Element(self.bilinear_map, G1, value=pk[0]**s) for pk in public_keys}
        C = [Element(self.bilinear_map, G1, value=(self.h1(kw)**r) * (self.h2(kw)**s)) for kw in keywords]
        key = sha3_256((self.e(self.g, self.g)**(r*s)).__str__().encode()).digest()
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(bytes(message, 'utf-8'))
        print("Ciphertext type:", type(ciphertext))
        return (ciphertext, (A, B, C))

    def trapdoor(self, secret_key: int, query: [(str, int)]) -> (Element, Element, Element, [int]):
        """
        Generate a trapdoor function.

        :param int secret_key: The secret key of the person creating the trapdoor.
        :param [(str,int)] query: The keywords to query for.

        :return: The trapdoor (T1, T2, T3, I).
        """
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
        """
        Run a test of trapdoor T on attributes S.

        :param int public_key: The index of the public key that created the trapdoor.
        :param (str,(Element,dict[int,Element])) S: The attributes to test against.
        :param (Element,Element,Element,[int]) T: The trapdoor to test.

        :return: Whether the trapdoor works for the attributes.
        """
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

    def decrypt(self, secret_key, ciphertext, A, B):
        """
        Decrypt a ciphertext using a secret key and some attributes.

        :param Element secret_key: The secret key to decrypt the ciphertext.
        :param str ciphertext: The ciphertext to decrypt.
        :param Element A: attribute used for decryption.
        :param Element B: attribute used for decryption.

        :return: The plaintext.
        """
        key = sha3_512(self.e(A, B)**(~secret_key).__str__().encode()).digest()
        cipher = AES.new(key, AES.MODE_GCM)
        plaintext = cipher.decrypt(ciphertext)


# mpeck = MPECK()
# print("a")
# key0 = mpeck.generate_key()
# print("b")
# (E, S) = mpeck.add_doc([(key0[0], key0[2])], [1])
# print("c")
# T = mpeck.trapdoor(key0[1], [(1, 0)])
# print("d")
# print(mpeck.test(key0[2], S, T))
