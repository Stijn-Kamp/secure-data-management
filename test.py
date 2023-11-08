from __future__ import annotations
from mpeck import MPECK


class Person:
    def __init__(self, mpeck: MPECK, server: Server):
        self.mpeck = mpeck
        self.server = server
        (self.pk, self.sk, self.keyindex) = mpeck.generate_key()

    def upload(self, other_person, document: str, keywords: [str]):
        self.server.upload(*self.mpeck.add_doc(other_person, keywords, document))

    def search(self, keywords):
        texts = self.server.search(self.keyindex, self.mpeck.trapdoor(self.sk, keywords))
        for text in texts:
            print("Text:")
            print(text)
            print(self.mpeck.decrypt(self.sk, *text))


class Consultant(Person):
    def __init__(self, mpeck: MPECK, server: Server):
        super().__init__(mpeck, server)
        self.clients = []

    def upload(self, clientindex: int, document: str, keywords: [str]):
        super().upload([self.clients[clientindex], (self.pk, self.keyindex)], document, keywords)


class Client(Person):
    def __init__(self, mpeck: MPECK, server: Server, consultant_key):
        super().__init__(mpeck, server)
        self.consultant_pk, self.consultant_keyindex = consultant_key

    def upload(self, document: str, keywords: [str]):
        super().upload([(self.consultant_pk, self.consultant_keyindex), (self.pk, self.keyindex)], document, keywords)


class Server:
    def __init__(self, mpeck: MPECK):
        self.mpeck = mpeck
        self.documents = []

    def upload(self, e, s):
        self.documents.append((e, s))

    def search(self, keyindex, trapdoor):
        res = []
        for doc in self.documents:
            if self.mpeck.test(keyindex, doc[1], trapdoor):
                res.append((doc[0], doc[1][0], doc[1][1]))
        return res




mpeck = MPECK()
server = Server(mpeck)

# Consultant
consultant = Consultant(mpeck, server)
client = Client(mpeck, server, (consultant.pk, consultant.keyindex))
print(client.upload("text", ["a"]))
print(client.search([("a", 0)]))
