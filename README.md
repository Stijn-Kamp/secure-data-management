# Search in Encrypted Data
Consider a financial consultant that uses a cloud storage service to store the financial data of his
clients. The cloud storage server is **honest-but-curious**. To prevent data leakage, the consultant stores
all data on the cloud server in encrypted form.
Design and implement a demonstrator that supports the following functionality:
1. The consultant can insert financial data for all of his clients in the storage server.
2. The consultant can search for _specific_ information for any _specific_ client of his in the encrypted data on the server.
3. The client can insert data in _his_ own encrypted record on the storage server.
4. The client can search for specific data in _his_ own record on the storage server.

To achieve the aforementioned functionality, apart from a suitable encryption scheme, you need to deploy a key distribution method, during the system setup.

Your report on the design of the demonstrator should include:
1. A definition of the data model.
2. The description of an encryption scheme and a key distribution method of your choice. The combination of the encryption scheme with the key distribution method should allow the consultant to search in any client’s record and the clients to search **only** in _their_ own records.
3. The system should be designed in such a way that clients can NOT search in other clients’ data, while the consultant can search in all data. This should be demonstrated in your report, by a usage scenario of the implemented system.
All design choices should be motivated.

_**Note:** We have assumed that the cloud storage service provider is honest-but-curious. Hence, although we trust it to follow the protocol honestly, we assume that it wishes to learn as much information as possible. Your demonstrator should guarantee that the cloud storage service provider is not able to learn about the actual encrypted data it holds._