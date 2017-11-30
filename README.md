# A Cloud Storage System

A cloud storage system that allows a user (through her client
application) to store data on a remote server such that
**confidentiality** of the data stored on the server is guaranteed even
if the server is untrusted: data stored on the server is encrypted using
a **symmetric key** known only to the client.

More specifically, data is stored (encrypted with the symmetric key of a
user) on the server along with a label and a counter (a version
number). When data is to be stored under some label, a new (higher)
counter is chosen and the data is stored under the label and the new
counter; old data is still preserved (under smaller counters). Different
users can have data repositories on one server. These repositories are
strictly separated. The system can be used to securely store any kind of
data. A user may use our cloud storage system, for example, to store her
passwords remotely on a server such that she has access to them on
different devices.

Communication between a client and a server is secured and authenticated
using functionalities for **public-key encryption** and **digital
signatures**. Moreover, the functionality for **nonce generation** is
essential to prevent replay attacks (when the client and the server run
a sub-protocol to synchronize counter values for labels).

## Dependencies


* Java JDK (tested with both `openjdk-7` and `oraclejdk-8`)
* Java Cryptography Extension (only needed for `oraclejdk`)
* Bouncy Castle Cryptographic API (tested with `bcprov-jdk15on-147.jar`)
* JavaParser (tested with `javaparser-1.0.8.jar`)
* SQLJet (tested with `sqljet-1.1.6.jar`)
* JUnit (tested with `junit-4.8.2.jar`)
* Apache Ant (tested with `ant-1.8.4.jar`)
* Beans Binding (tested with `beansbinding-1.2.1.jar`)
* Miglayout Swing (tested with `miglayout-swing-5.0.jar`)
	

## Usage

1. Run class `funct.pki.PKIServerApp`

    To start the public key infrastructure which is needed for
    registration and lookup of public and verification keys.  The
    PKIServer stores the registered keys at `%TEMP%PKI_server.db` (to
    delete registered keys, you will have to delete this file).

2. Run class `cloudStorage.app.ServerRegisterApp`

    The server registration process. Server registers its keys at the
    Public-Key Infrastructure and stores the serialized keys in the
    folder `%TEMP%/CloudStorage/server.info`

3. Run class `cloudStorage.app.ServerApp`

    The server app processing the client requests (store, retrieve or
    provide last counter).

4. Run class `cloudStorage.app.UserRegisterApp <user_id [int]>`

    This client registration process for the user with that
    <user_id>. It registers her keys at the Public-Key Infrastucture and
    stores the serialized keys in the folder
    `%TEMP%/CloudStorage/user$(user_id).info`
    

5. Run class `cloudStorage.app.ClientStoreApp <user_id [int]> <label [String]> <msg [String]>`

    To allow a user to store a message on the server under a specific
    label.

6. Run class `cloudStorage.app.ClientRetrieveApp <user_id [int]> <label [String]>`

    To allow an user to retrieve the message stored on the server under
    the specific label, by command line interface.

7. Run class `cloudStorage.app.UserGUI`

   The client user interface which allows an user to store and retrieve
    message from the server.

8.  Run class `cloudStorage.app.DeleteLocalFiles`

    To delete the local files created which are stored in the folder
    `%TEMP%/CloudStorage and %TEMP%/PKIServer.db`


## Example

Run the following commands from the bin-folder of the compiled project:

```
java -cp ".:../lib/*" funct.pki.PKIServerApp

java -cp ".:../lib/*" cloudStorage.app.ServerRegisterApp
java -cp ".:../lib/*" cloudStorage.app.ServerApp

java -cp ".:../lib/*" cloudStorage.app.UserRegisterApp 101

java -cp ".:../lib/*" cloudStorage.app.ClientStoreApp 101 pwd PasswordIwantToStore
java -cp ".:../lib/*" cloudStorage.app.ClientRetrieveApp 101 pwd

java -cp ".:../lib/*" cloudStorage.app.UserGUI

java -cp ".:../lib/*" cloudStorage.app.DeleteLocalFiles
```
