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
			 * 			((STORE_OK, signClient), signServer)							or
			 * 			((STORE_FAIL, lastCounter) signClient), signServer)
			 * where:
			 * - signServer: signature of all the previous tokens
			 * - signClient: signature of the message for which we are receiving the response 
			 * - lastCounter: the higher value of the counter associated with label, as stored by the server
			 */
			
			// Validate the message in order to be sure that it has been sent by the server
			// and it's the correct reply of our request
			byte[] msgCore = decryptValidateResp(encryptedSignedResp, signClient);
			// msgCore is either STORE_OK or (STORE_FAIL, lastCounter)
			
			// analyze the message tag
			byte[] tag = MessageTools.first(msgCore);
			if(Arrays.equals(tag, Params.STORE_OK)){
				// we can save the counter used to send the message
				lastCounter.put(label, counter);
				return;
			}
			else if(Arrays.equals(tag, Params.STORE_FAIL)){ // the server does not accept our request, because it claims
				                                            // to have a higher counter for this label
				byte[] lastCounter = MessageTools.second(msgCore);
				if(lastCounter.length!=4) // since lastCounter is supposed to be a integer, its length must be 4 bytes
					throw new MalformedMessage();
				int serverCounter = MessageTools.byteArrayToInt(lastCounter); 
				if (serverCounter<counter) // the server is misbehaving (his counter is expected to be higher)
					throw new IncorrectReply();
				counter = serverCounter+1;
			}
			else
				throw new MalformedMessage();
		}
		throw new StoreFailure(); 
		// This exception could be thrown when several clients try to store 
		// concurrently a message into the server with the same 'label'.
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
		 * 			(((RETRIEVE_OK, (encMsg, signEncrMsg)), signClient), signServer)							or
		 * 			((RETRIEVE_FAIL, signClient), signServer)
		 * where:
		 * - signServer: signature of all the previous tokens
		 * - signClient: signature of the message for which we are receiving the response 
		 * - signEncMsg: the signature of ((STORE, (label, (counter, encrMsg)))
		 */
		
		// Validate the message in order to be sure that it has been sent by the server
		// and it's the correct reply of our request
		byte[] msgCore = decryptValidateResp(encryptedSignedResp, signClient);
		// msgCore is either (RETRIEVE_OK, (encMsg, signEncrMsg)) or RETRIEVE_FAIL
		
		// analyze the response tag
		byte[] tag = MessageTools.first(msgCore);

		if(Arrays.equals(tag, Params.RETRIEVE_OK)){
			byte[] encrMsg_signMsg = MessageTools.second(msgCore);
			byte[] encrMsg = MessageTools.first(encrMsg_signMsg);
			byte[] signMsg = MessageTools.second(encrMsg_signMsg);
			// all the security checks about these message are done by verifying that
			// signMsg is the signature of the STORE request with encrMsg
			
			// check whether the signMsg is the signature for the STORE request with encrMsg.
			// This request is of the form (STORE, (label, (counter, encrMsg)))
			byte[] counter_msg = MessageTools.concatenate(MessageTools.intToByteArray(counter), encrMsg);
			byte[] label_counter_msg = MessageTools.concatenate(label, counter_msg);
			byte[] store_label_counter_msg = MessageTools.concatenate(Params.STORE, label_counter_msg);
			if(!verifier.verify(signMsg, store_label_counter_msg))  // the server hasn't replied with the encrypted message we requested
				throw new IncorrectReply();
	
			// everything is ok; decrypt the message and return it 
			return symenc.decrypt(encrMsg);
		}
		else if(Arrays.equals(tag, Params.RETRIEVE_FAIL)){
			// the server counldn't retrieve the message
			// since we know the server replied to our request and since the 'counter' has been saved
			// just after the server acknowledged the storing of the message was successful, then why does it fail?
			throw new IncorrectReply();
		}
		else
			throw new MalformedMessage();
	}
	
	
	
	
	/**
	 * Decrypt the message, verify that it's a reply from the server and that
	 * it's the response for the request we sent to it. 
	 * If no exception are thrown, we know that what 
	 * we return is a response created by the server for our request.
	 * Therefore, if anything is wrong with this message, the server is to blame.
	 * 
	 * @param encryptedSignedResponse the message received from the network. Its shape should be: EncPUclient{((msgCore, signClient), signServer)}
	 * @param signRequest the signature of the message we sent to the server
	 * @return the rest of the message received from the network (msgCore)
	 * @throws MalformedMessage if something went wrong during the validation process
	 */
	private byte[] decryptValidateResp(byte[] encryptedSignedResponse, byte[] signRequest) throws MalformedMessage {
		// 1. decrypt the message with the client private key and parse it
		byte[] signedResponse = decryptor.decrypt(encryptedSignedResponse);
		byte[] response = MessageTools.first(signedResponse);
		byte[] signServer = MessageTools.second(signedResponse);

		// 2. if the signature isn't correct, the message is malformed
		// (note that the signature is incorrect even if one or both messages are empty)
		if (!server_ver.verify(signServer, response))
			throw new MalformedMessage();
		// 3. check whether the server are responding exactly to the message we sent 
		byte[] signature = MessageTools.second(response);
		if(!Arrays.equals(signature, signRequest))
			throw new MalformedMessage();
		return MessageTools.first(response); // we return the rest of the message
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
	 * Exception thrown when the the server is not able to store the message we sent to it, e.g.
	 * because it has always an higher counter related to our label.
	 */
	@SuppressWarnings("serial")
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

		/*
		public boolean containsKey(byte[] key) {
			return get(key) >= 0;
		}
		*/
	}
}
