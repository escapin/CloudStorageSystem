package de.uni.trier.infsec.cloudStorage;

import java.util.*;

import de.uni.trier.infsec.functionalities.pki.idealcor.PKISig;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIError;
import de.uni.trier.infsec.functionalities.symenc.SymEnc;
import de.uni.trier.infsec.environment.network.NetworkClient;
import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.utils.*;

public class Client {

	private static int STORE_ATTEMPTS=3; 
	// how many times the client attempts to send a message to the server with the proper count 

	private SymEnc symenc;
	private PKIEnc.Decryptor decryptor;
	private PKISig.Signer signer;
	private PKISig.Verifier verifier;
	private PKIEnc.Encryptor server_enc;
	private PKISig.Verifier server_ver;

	private int client_id;
	private LabelList lastCounter = new LabelList(); // for each label maintains the last counter

	public Client(int client_id, SymEnc symenc, PKIEnc.Decryptor decryptor, PKISig.Signer signer) throws PKIError, NetworkError {
		this.symenc = symenc;
		this.decryptor = decryptor;
		this.signer = signer;
		this.verifier = signer.getVerifier();
		this.server_enc = PKIEnc.getEncryptor(Params.SERVER_ID, Params.PKI_ENC_DOMAIN);
		this.server_ver = PKISig.getVerifier(Params.SERVER_ID, Params.PKI_DSIG_DOMAIN);
		this.client_id = client_id;
	}

	// TODO:
	// the responses of the server are supposed to always have the same structure:
	// enc(sig[ request ]).
	// Now, there is quite a bit of redundancy in the code, as for each request the parsing of
	// this is repeated independently.
	// Why don't we have a method that would do it for us. We could use it as:
	// 
	//    byte response = decryptAndValidateResponse( encryptedSignedResponse )
	//
	// (it would throw MalformedMessage if necessary).
	
	
	/**
	 * Store a message on the server under a given label
	 */
	public void store(byte[] msg, byte[] label) throws NetworkError, StorageError {
		// 1. encrypt the message with the symmetric key (the secret key of the client) 
		byte[] encrMsg = symenc.encrypt(msg);

		// 2. pick the last the counter
		int counter = lastCounter.get(label) + 1; // note that if label has not been used, lastCounter.get(label) returns -1

		for (int attempts=0; attempts<STORE_ATTEMPTS; ++attempts) {
			// Encoding the message that has to be signed: (STORE, (label, (counter, encMsg)))
			byte[] counter_msg = MessageTools.concatenate(MessageTools.intToByteArray(counter), encrMsg);
			byte[] label_counter_msg = MessageTools.concatenate(label, counter_msg);
			byte[] store_label_counter_msg = MessageTools.concatenate(Params.STORE, label_counter_msg);

			// 3. sign the message with the client private key 
			byte[] signRequest = signer.sign(store_label_counter_msg);
			byte[] msgWithSignature = MessageTools.concatenate(store_label_counter_msg, signRequest);

			// 4. encrypt the (client_id, message, signature) with the server public key
			byte[] msgToSend = server_enc.encrypt(MessageTools.concatenate(MessageTools.intToByteArray(client_id), msgWithSignature));			
			// Shape of msgToSend:
			//		(clientID, ((STORE, (label, (counter, encMsg))), signClient))
			// where signClient is the signature of ((STORE, (label, (counter, encMsg)))

			// 5. send the message to the server
			byte[] encryptedSignedResp = NetworkClient.sendRequest(msgToSend, Params.SERVER_NAME, Params.SERVER_PORT);

			// HANDLE THE SERVER RESPONSE 
			//
			// Expected server's responses (encrypted with the client's public key):
			//		((STORE_OK, signClient), signServer)
			//		((STORE_FAIL, (signClient, lastCounter)), signServer)
			// where in both cases signServer is the signature of the previous tokens
			// and lastCounter is the last value of the counter associated with label, 
			// as stored by the server.

			// 1. decrypt the message with the client private key
			byte[] signedResponse = decryptor.decrypt(encryptedSignedResp);

			byte[] response = MessageTools.first(signedResponse);
			byte[] signServer = MessageTools.second(signedResponse);

			// 2. if the signature isn't correct, the message is malformed
			// (note that the signature is incorrect if one or both messages are empty)
			if (!server_ver.verify(signServer, response))
				throw new MalformedMessage();

			// 3. analyze the message tag
			byte[] tag = MessageTools.first(response);
			if(Arrays.equals(tag, Params.STORE_OK)){
				// 4a. the server said the message has been stored correctly.
				// We only have to verify that this is a response to our request, that is 
				// the response contain the client's signature from the request. 
				byte[] signature = MessageTools.second(response);
				if(!Arrays.equals(signature, signRequest)) // the server haven't replied the message we sent
					throw new MalformedMessage();
				// we can save the counter used to send the message
				lastCounter.put(label, counter);
				return;
			}
			else if(Arrays.equals(tag, Params.STORE_FAIL)){ // the server does not accept our request, because it claims
				                                            // to have a higher counter for this label
				byte[] signature_lastCounter = MessageTools.second(response);
				if(signature_lastCounter.length==0)
					throw new MalformedMessage();
				byte[] signature = MessageTools.first(signature_lastCounter);
				byte[] lastCounter= MessageTools.second(signature_lastCounter);
				if(signature.length==0 || lastCounter.length==0)
					throw new MalformedMessage();
				// FIXME: what happens below if lastCounter is too long for the encoding of an int? Perhaps we should
				// be more specific in the test above
				int serverCounter = MessageTools.byteArrayToInt(lastCounter); 
				if (!Arrays.equals(signature, signRequest)) // the server haven't replied to the message we sent
					throw new MalformedMessage();
				if (serverCounter<counter) // the server is misbehaving (his counter is expected to be higher)
					throw new IncorrectReply();
				counter = serverCounter+1;
			}
			else
				throw new MalformedMessage();
		}		
	}

	/**
	 * Retrieve from the server the message related to the correspondent label
	 *  
	 * @param label the label related to the message to be retrieved
	 * @return the message in the server related to the label if it exists, null otherwise
	 */
	public byte[] retreive(byte[] label) throws NetworkError, StorageError {
		// SEND THE RETRIEVE REQUEST TO THE SERVER
		// 1. retrieve the last counter
		int counter = lastCounter.get(label);
		if (counter<0)
			return null; // TODO: perhaps the server has something with this label, even if we do not know about it.

		// 2. create the message to send
		byte[] label_counter = MessageTools.concatenate(label, MessageTools.intToByteArray(counter));
		byte[] retrieve_label_counter = MessageTools.concatenate(Params.RETRIEVE, label_counter);

		// 3. sign the message
		byte[] signRequest = signer.sign(retrieve_label_counter);
		byte[] msgWithSignature = MessageTools.concatenate(retrieve_label_counter, signRequest);

		// 4. encrypt (client_id, message, signature) with the server public key
		byte[] msgToSend = server_enc.encrypt(MessageTools.concatenate(MessageTools.intToByteArray(client_id), msgWithSignature));
		// Shape of encrypted msgToSend
		//		(clientID, ((RETRIEVE, (label, counter)), signClient))
		// where signClient is the signature of (RETRIEVE, (label, counter))

		// 5. send the message to the server
		byte[] encryptedSignedResponse = NetworkClient.sendRequest(msgToSend, Params.SERVER_NAME, Params.SERVER_PORT); 

		// HANDLE THE SERVER RESPONSE 
		//
		// Expected serverer responces (encrypted):
		//		((RETRIEVE_OK, (signClient, (encMsg, signEncrMsg))), signServer)
		//		((RETRIEVE_FAIL, signClient), signServer)
		// 	where in both cases signServer is the signature of the previous tokens,
		//  whereas signEncMsg is the signature of ((STORE, (label, (counter, encrMsg)))

		// 1. decrypt the message with the client private key and parse it
		byte[] signedResponse = decryptor.decrypt(encryptedSignedResponse);
		byte[] response = MessageTools.first(signedResponse);
		byte[] signServer = MessageTools.second(signedResponse);

		// 2. if the signature isn't correct, the message is malformed
		// (note that the signature is incorrect even if one or both messages are empty)
		if (!server_ver.verify(signServer, response))
			throw new MalformedMessage();

		// 3. analyze the response tag
		byte[] tag = MessageTools.first(response);

		if(Arrays.equals(tag, Params.RETRIEVE_OK)){
			// 4a. server claims to have retrieved the proper message
			byte[] signature_encrMsg_signMsg = MessageTools.second(response);
			if(signature_encrMsg_signMsg.length==0)
				throw new MalformedMessage();
			byte[] signature = MessageTools.first(signature_encrMsg_signMsg);
			byte[] encrMsg_signMsg = MessageTools.second(signature_encrMsg_signMsg);
			if(!Arrays.equals(signature, signRequest)) // the server hasn't replied to our request
				throw new MalformedMessage();
			// Now we know that what we parse is a response created by the server for our request. 
			// Therefore, if anything is wrong with this message, the server is to blame.
			byte[] encrMsg = MessageTools.first(encrMsg_signMsg);
			byte[] signMsg = MessageTools.second(encrMsg_signMsg);
			if(encrMsg.length==0 || signMsg.length==0)
				throw new IncorrectReply();
			// FIXME: again, should we expect some specific value from encrMsg.length?

			// 5. check whether the signMsg is the signature for the STORE request with encMsg.
			// This request is of the form (STORE, (label, (counter, encrMsg)))
			byte[] counter_msg = MessageTools.concatenate(MessageTools.intToByteArray(counter), encrMsg);
			byte[] label_counter_msg = MessageTools.concatenate(label, counter_msg);
			byte[] store_label_counter_msg = MessageTools.concatenate(Params.STORE, label_counter_msg);
			if(!verifier.verify(signMsg, store_label_counter_msg))  // the server hasn't replied with the encrypted message we requested
				throw new IncorrectReply();
	
			// 6. everything is ok; decrypt the message and return it 
			return symenc.decrypt(encrMsg);
		}
		else if(Arrays.equals(tag, Params.RETRIEVE_FAIL)){
			// 4b. the server counldn't retrieve the message
			byte[] signature = MessageTools.second(response);
			if(signature.length==0)
				throw new MalformedMessage();
			if(!Arrays.equals(signature, signRequest)) // the server haven't replied to the message we sent
				throw new MalformedMessage();
			// now we know that the server replied to our request; but then why does it fail?
			throw new IncorrectReply();
		}
		else
			throw new MalformedMessage();
	}

	@SuppressWarnings("serial")
	public class StorageError extends Exception {}

	/**
	 * Exception thrown when the response of the server does not conform
	 * to an expected format (we get, for instance, a trash message or a response
	 * to a different request). 
	 */
	@SuppressWarnings("serial")
	public class MalformedMessage extends StorageError {}

	/**
	 * Exception thrown when the response is invalid and demonstrates that the server
	 * has misbehaved (the server has be ill-implemented or malicious).
	 */
	@SuppressWarnings("serial")
	public class IncorrectReply extends StorageError {}

	/**
	 * List of labels.
	 * For each 'label' maintains an counter representing 
	 * how many times the label has been used.
	 */
	static private class LabelList {

		static class Node {
			byte[] key;
			int counter;
			Node next;

			public Node(byte[] key, int counter, Node next) {
				this.key = key;
				this.counter = counter;
				this.next = next;
			}
		}

		private Node firstElement = null;

		public void put(byte[] key, int counter) {
			for(Node tmp = firstElement; tmp != null; tmp=tmp.next)
				if( Arrays.equals(key, tmp.key) ){
					tmp.counter = counter;
					return;
				}
			firstElement = new Node(key, counter, firstElement);
		}

		public int get(byte[] key) {
			for(Node tmp = firstElement; tmp != null; tmp=tmp.next)
				if( Arrays.equals(key, tmp.key)  )
					return tmp.counter;	
			return -1; // if the label is not present, return -1
		}

		/*
		public boolean containsKey(byte[] key) {
			return get(key) >= 0;
		}
		*/
	}
}
