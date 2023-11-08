from __future__ import annotations
from mpeck import MPECK


class Person:
    def __init__(self, mpeck: MPECK, server: Server, key_location_server: KeyLocationServer):
        self.mpeck = mpeck
        self.server = server
        self.key_location_server = key_location_server
        (self.pk, self.sk, self.keyindex) = mpeck.generate_key()

    def upload(self, other_person, document: str, keywords: [str]):
        keyword_dict = {}
        for keyword in keywords:
            keyword_dict[self.key_location_server.get(keyword)] = keyword

        keywords = []
        for i in range(0, self.key_location_server.count):
            if i in keyword_dict:
                keywords.append(keyword_dict[i])
            else:
                keywords.append("null."+str(i))

        self.server.upload(*self.mpeck.add_doc(other_person, keywords, document))

    def search(self, keywords):
        results = []
        keyword_tuples = []
        for keyword in keywords:
            keyword_tuples.append((keyword, self.key_location_server.get(keyword)))
        texts = self.server.search(self.keyindex, self.mpeck.trapdoor(self.sk, keyword_tuples))
        for text in texts:
            results.append(self.mpeck.decrypt(self.sk, *text))

        return results


class Consultant(Person):
    def __init__(self, mpeck: MPECK, server: Server, key_location_server: KeyLocationServer):
        super().__init__(mpeck, server, key_location_server)
        self.clients = {}

    def add_client(self, name: str, pk):
        if name in self.clients:
            print("Overriding client:", name)
        self.clients[name] = pk


    def upload(self, client: str, document: str, keywords: [str]):
        keywords.append("client."+client)
        super().upload([self.clients[client], (self.pk, self.keyindex)], document, keywords)


class Client(Person):
    def __init__(self, mpeck: MPECK, server: Server, key_location_server: KeyLocationServer, name, consultant_key):
        super().__init__(mpeck, server, key_location_server)
        self.consultant_pk, self.consultant_keyindex = consultant_key
        self.name = name
        self.key_location_server.add_similar("client."+self.name, "client.null")
        print(self.key_location_server.map)

    def upload(self, document: str, keywords: [str]):
        keywords.append("clients."+self.name)
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
                res.append((doc[0], doc[1][0], doc[1][1][keyindex]))
        return res


class KeyLocationServer:
    def __init__(self):
        self.map = {"client.null": 0}
        self.count = 1

    def add(self, keyword: str):
        if keyword.startswith("null."):
            raise Exception
        if keyword not in self.map:
            self.map[keyword] = self.count
            self.count += 1
        return self.map[keyword]

    def add_similar(self, add: str, similar: str):
        if add.startswith("null."):
            raise Exception
        if similar in self.map:
            self.map[add] = self.map[similar]
            return self.map[add]
        raise Exception

    def get(self, keyword: str):
        if keyword.startswith("null."):
            raise Exception
        if keyword in self.map:
            return self.map[keyword]
        print("Could not find keyword:", keyword)
        raise Exception



mpeck = MPECK()
server = Server(mpeck)
key_location_server = KeyLocationServer()

# Consultant
consultant = Consultant(mpeck, server, key_location_server)
client = Client(mpeck, server, key_location_server, "Dave", (consultant.pk, consultant.keyindex))
consultant.add_client(client.name, client.pk)
key_location_server.add("a")
client.upload("text", ["a"])
print(client.search([("a")]))
consultant.upload(client.name, "text2", ["a"])
