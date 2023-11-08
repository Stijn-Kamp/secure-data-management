from __future__ import annotations
from mpeck import MPECK


class Person:
    def __init__(self, mpeck: MPECK, server: Server):
        self.mpeck = mpeck
        self.server = server
        (self.pk, self.sk, self.keyindex) = mpeck.generate_key()

    def upload(self, other_person, document: str, keywords: [str]):
        return self.mpeck.add_doc(other_person, keywords, document)

    def trapdoor(self, keywords):
        return self.mpeck.trapdoor(self.sk, keywords)


def Consultant(Person):
    def __init__(self, mpeck: MPECK, server: Server):
        super.__init__(mpeck, server)
        print(self.pk, self.sk, self.keyindex)
        self.clients = []

    def upload(self, clientindex: int, document: str, keywords: [str]):
        return super().upload([self.clients[clientindex], (super().pk, super().keyindex)], document, keywords)

    def search(self, keywords):
        trapdoor = super().trapdoor(keywords)
        super().server.search(super().pk, trapdoor)


def Client(Person):
    def __init__(self, mpeck: MPECK, server: Server, consultant_key):
        super.__init__(mpeck, server)
        self.consultant_pk, self.consultant_keyindex = consultant_key

    def upload(self, document: str, keywords: [str]):
        return super().upload([(self.consultant_pk, self.consultant_keyindex), (super().pk, super().keyindex)], document, keywords)

    def search(self, keywords):
        trapdoor = super().trapdoor(keywords)
        super().server.search(super().pk, trapdoor)


class Server:
    def __init__(self, mpeck: MPECK):
        self.mpeck = mpeck
        self.documents = []

    def upload(self, e, s):
        self.documents.append((e, s))

    def search(self, pk, trapdoor):
        res = []
        for doc in self.documents:
            if self.mpeck.test(pk, doc[1], trapdoor):
                res.append((doc[0], doc[1][0], doc[1][1]))
        return res




mpeck = MPECK()
server = Server(mpeck)

# Consultant
consultant = Consultant(mpeck, server)
client = Client(mpeck, server, consultant)
print(client.upload("text", ["a"]))
print
