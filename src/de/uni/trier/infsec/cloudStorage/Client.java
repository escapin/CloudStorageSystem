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
			byte[] signClient = signer.sign(store_label_counter_msg);
			byte[] msgWithSignature = MessageTools.concatenate(store_label_counter_msg, signClient);

			// 4. encrypt the (client_id, message, signature) with the server public key
			byte[] msgToSend = server_enc.encrypt(MessageTools.concatenate(MessageTools.intToByteArray(client_id), msgWithSignature));			
			// Shape of msgToSend:
			//		(clientID, ((STORE, (label, (counter, encMsg))), signClient))
			// where signClient is the signature of ((STORE, (label, (counter, encMsg)))

			// 5. send the message to the server
			byte[] encryptedSignedResp = NetworkClient.sendRequest(msgToSend, Params.SERVER_NAME, Params.SERVER_PORT);

			/* HANDLE THE SERVER RESPONSE
			 * Expected server's responses (encrypted with the client's public key):
			 * 			((signClient, STORE_OK), signServer)							or
			 * 			((signClient, (STORE_FAIL, lastCounter)), signServer)
			 * where:
			 * - signServer: signature of all the previous tokens
			 * - signClient: signature of the message for which we are receiving the response 
			 * - lastCounter: the higher value of the counter associated with label, as stored by the server
			 */
			
			// Decrypt the validate the message in order to make sure that it is a response to the client's request.
			ServerResponse response = decryptValidateResp(encryptedSignedResp, signClient);
			// response is either STORE_OK or (STORE_FAIL, lastCounter)
			
			// analyze the response tag
			if(Arrays.equals(response.tag, Params.STORE_OK)){  // message successfully stored 
				// we can save the counter used to send the message
				lastCounter.put(label, counter);
				return;
			}
			else if(Arrays.equals(response.tag, Params.STORE_FAIL)){ // the server hasn't accepted the request, because it claims
				                                                     // to have a higher counter for this label
				byte[] lastCounter = response.info;
				if(lastCounter.length!=4) // since lastCounter is supposed to be a integer, its length must be 4 bytes
					throw new IncorrectReply();
				int serverCounter = MessageTools.byteArrayToInt(lastCounter); 
				if (serverCounter<counter) // the server is misbehaving (his counter is expected to be higher)
					throw new IncorrectReply();
				counter = serverCounter+1;
			}
			else
				throw new IncorrectReply();
		}
		throw new StoreFailure(); 
		// This exception may be thrown if several clients try to store 
		// concurrently a message into the server with the same label.
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
		byte[] signClient = signer.sign(retrieve_label_counter);
		byte[] msgWithSignature = MessageTools.concatenate(retrieve_label_counter, signClient);

		// 4. encrypt (client_id, message, signature) with the server public key
		byte[] msgToSend = server_enc.encrypt(MessageTools.concatenate(MessageTools.intToByteArray(client_id), msgWithSignature));
		// Shape of encrypted msgToSend
		//		(clientID, ((RETRIEVE, (label, counter)), signClient))
		// where signClient is the signature of (RETRIEVE, (label, counter))

		// 5. send the message to the server
		byte[] encryptedSignedResp = NetworkClient.sendRequest(msgToSend, Params.SERVER_NAME, Params.SERVER_PORT); 

				
		/* HANDLE THE SERVER RESPONSE
		 * Expected server's responses (encrypted with the client's public key):
		 * 			((signClient, (RETRIEVE_OK, (encMsg, signEncrMsg))), signServer)					or
		 * 			((signClient, RETRIEVE_FAIL), signServer)
		 * where:
		 * - signServer: signature of all the previous tokens
		 * - signClient: signature of the message for which we are receiving the response 
		 * - signEncMsg: the signature of ((STORE, (label, (counter, encrMsg)))
		 */
		
		// Validate the message in order to be sure that it has been sent by the server
		// and it's the correct reply of our request
		ServerResponse response = decryptValidateResp(encryptedSignedResp, signClient);
		// msgCore is either (RETRIEVE_OK, (encMsg, signEncrMsg)) or RETRIEVE_FAIL
		
		// analyze the response tag
		if(Arrays.equals(response.tag, Params.RETRIEVE_OK)){
			byte[] encrMsg = MessageTools.first(response.info);
			byte[] signMsg = MessageTools.second(response.info);
			// check whether the signMsg is the signature for the STORE request with encrMsg
			// which is of the form (STORE, (label, (counter, encrMsg)))
			byte[] counter_msg = MessageTools.concatenate(MessageTools.intToByteArray(counter), encrMsg);
			byte[] label_counter_msg = MessageTools.concatenate(label, counter_msg);
			byte[] store_label_counter_msg = MessageTools.concatenate(Params.STORE, label_counter_msg);
			if(!verifier.verify(signMsg, store_label_counter_msg))  // the server hasn't replied with the encrypted message we requested
				throw new IncorrectReply();
	
			// everything is ok; decrypt the message and return it 
			return symenc.decrypt(encrMsg);
		}
		else if(Arrays.equals(response.tag, Params.RETRIEVE_FAIL)){
			// The server claims that it counldn't retrieve the message.
			// But because the 'counter' is saved only after the server acknowledges 
			// that the message was successfully stored, it should not happen.
			throw new IncorrectReply();
		}
		else
			throw new MalformedMessage();
	}
	
	
	private class ServerResponse {
		byte[] tag;
		byte[] info;
		
		ServerResponse(byte[] tag, byte[] info) {
			this.tag = tag;
			this.info = info;
		}
	}
	
	/**
	 * Decrypt the message, verify that it's a response of the server to our request
	 * (otherwise an exception is thrown). 
	 * 
	 * @param encryptedSignedResponse the message received from the network. Its shape should be: Enc_Client{((signClient, msgCore), signServer)}
	 * @param signRequest the signature on the client's request
	 * @return a ServerResponse object
	 * @throws MalformedMessage if something went wrong during the validation process
	 */
	private ServerResponse decryptValidateResp(byte[] encryptedSignedResponse, byte[] signRequest) throws MalformedMessage {
		// decrypt the message with the client private key and parse it
		byte[] signedResponse = decryptor.decrypt(encryptedSignedResponse);
		byte[] payload = MessageTools.first(signedResponse);
		byte[] signServer = MessageTools.second(signedResponse);

		// if the signature isn't correct, the message is malformed
		// (note that the signature is incorrect even if one or both messages are empty)
		if (!server_ver.verify(signServer, payload))
			throw new MalformedMessage();
		// check whether this is a response to the client's request as identified by signRequest 
		byte[] signatureClient = MessageTools.first(payload);
		if(!Arrays.equals(signatureClient, signRequest))
			throw new MalformedMessage();
		byte[] response = MessageTools.second(payload); // response should be of the form (tag, info), where info may be empty
		return new ServerResponse( MessageTools.first(response), MessageTools.second(response)); 
	}

	public class StorageError extends Exception {}

	/**
	 * Exception thrown when the response of the server does not conform
	 * to an expected format (we get, for instance, a trash message or a response
	 * to a different request). 
	 */
	public class MalformedMessage extends StorageError {}

	/**
	 * Exception thrown when the response is invalid and demonstrates that the server
	 * has misbehaved (the server has be ill-implemented or malicious).
	 */
	public class IncorrectReply extends StorageError {}

	/**
	 * Exception thrown when the the server is not able to store the message we sent to it, e.g.
	 * because it has always an higher counter related to our label.
	 */
	public class StoreFailure extends StorageError {}
	
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
	}
}
