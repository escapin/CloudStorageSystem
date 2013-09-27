Prerequisites:
	Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files
	
	 To download and apply the JCE, see at the bottom of this page:
	 	http://www.oracle.com/technetwork/java/javase/downloads/index.html



How-To run the StorageSystem process:

 1. Run class de.uni.trier.infsec.functionalities.pki.PKIServerApp

    This starts the public key environment which is needed for
    registration and lookup of public and verification keys.  The
    PKIServer stores the registered keys at %TEMP%PKI_server.db -
    if you want to delete registered keys, you will have to delete this
    file.

 2. Run class de.uni.trier.infsec.cloudStorage.ServerRegisterApp

    This will run the server registration process. Server will
    register its keys at the PKI environment and store the serialized
    keys to folder %TEMP%/CloudStorage/server.info

 3. Run class de.uni.trier.infsec.cloudStorage.ServerApp

    The server will process the client requests (store, retrieve or provide last counter).

 4. Run class de.uni.trier.infsec.cloudStorage.UserRegisterApp
	with parameter <user_id [int]>

    This will run registration process for the user with that user_id. It will
    register its keys at the PKI environment and store the serialized
    keys to folder %TEMP%/CloudStorage/user$(user_id).info
    
5a  Run class de.uni.trier.infsec.cloudStorage.UserGUI
	to start the application which allows to store and retrieve message as a user  

5b.1 Run class de.uni.trier.infsec.cloudStorage.ClientStoreApp
	 with parameters <user_id [int]> <label [String]> <msg [String]>
    
     To allow an user to store a message on the server under a specific label.

5b.2 Run class de.uni.trier.infsec.cloudStorage.ClientRetrieveApp
	 with parameters <user_id [int]> <label [String]>
    
     To allow an user to retrieve the message stored on the server under the specific label.



EXAMPLE:
========

Run following commands from bin-folder of the compiled project:

1. java -cp ".:../lib/*" de.uni.trier.infsec.functionalities.pki.PKIServerApp

2. java -cp ".:../lib/*" de.uni.trier.infsec.cloudStorage.ServerRegisterApp
3. java -cp ".:../lib/*" de.uni.trier.infsec.cloudStorage.ServerApp

4. java -cp ".:../lib/*" de.uni.trier.infsec.cloudStorage.UserRegisterApp 101

5a java -cp ".:../lib/*" de.uni.trier.infsec.cloudStorage.UserGUI

5b.1. java -cp ".:../lib/*" de.uni.trier.infsec.cloudStorage.ClientStoreApp 101 pwd casdasfasfafaasfsa
5b.2.  java -cp ".:../lib/*" de.uni.trier.infsec.cloudStorage.ClientRetrieveApp 101 pwd


In order to delete the files created, delete the directory %TEMP%/CloudStorage and %TEMP%/PKIServer.db
