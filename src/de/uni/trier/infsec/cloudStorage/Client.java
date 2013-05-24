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

	private SymEnc symenc;
	private PKIEnc.Decryptor decryptor;
	private PKISig.Signer signer;
	private PKIEnc.Encryptor server_enc;
	private PKISig.Verifier server_ver;
	
	private int client_id;
	private LabelList lastCounter = new LabelList(); // for each label maintains the last counter
	
	public Client(int client_id, SymEnc symenc, PKIEnc.Decryptor decryptor, PKISig.Signer signer) throws PKIError, NetworkError {
		this.symenc = symenc;
		this.decryptor = decryptor;
		this.signer = signer;
		this.server_enc = PKIEnc.getEncryptor(Params.SERVER_ID, Params.PKI_ENC_DOMAIN);
		this.server_ver = PKISig.getVerifier(Params.SERVER_ID, Params.PKI_DSIG_DOMAIN);
		this.client_id = client_id;
	}
	
	/**
	 * Store a message on the server under a given label
	 * 
	 * @param message the message which has to be stored
	 * @param label the label related to the message
	 */
	public void store(byte[] msg, byte[] label) throws NetworkError, MalformedMessage, IncorrectReply{
		// 1. encrypt the message with the symmetric key
		byte[] encrMsg = symenc.encrypt(msg);
		 
		// 2. pick the last the counter
		int counter = lastCounter.get(label) + 1; // note that if label has not been used, get(label) returns -1
		
		int attempts=0;
		do{
			/* Encoding the message that has to be signed: (STORE, (label, (counter, encMsg)))  */
			byte[] counter_msg = MessageTools.concatenate(MessageTools.intToByteArray(counter), encrMsg);
			byte[] label_counter_msg = MessageTools.concatenate(label, counter_msg);
			byte[] store_label_counter_msg = MessageTools.concatenate(Params.STORE, label_counter_msg);
			
			// 3. sign the message with the client private key 
			byte[] signClient = signer.sign(store_label_counter_msg);
			byte[] msgSign = MessageTools.concatenate(store_label_counter_msg, signClient);
			
			// 4. encrypt the (client_id, message, signature) with the server public key
			byte[] msgToSend = server_enc.encrypt(MessageTools.concatenate(MessageTools.intToByteArray(client_id), msgSign));
			
			// Shape of msgToSend:
			//		(clientID, ((STORE, (label, (counter, encMsg))), signClient))
			// where signClient is the signature of ((STORE, (label, (counter, encMsg)))
			
			// 5. send the message to the server
			byte[] encryptedResp = NetworkClient.sendRequest(msgToSend, Params.SERVER_NAME, Params.SERVER_PORT);
	
			// HANDLE THE SERVER RESPONSE 
			//
			// Expected serverResp:
			//		((STORE_OK, signClient), signServer)
			//		((STORE_FAIL, (signClient, lastCounter)), signServer)
			// 	where in both cases signServer is the signature of the previous tokens
			
			
			// 1. decrypt the message with the client private key
			byte[] serverResp = decryptor.decrypt(encryptedResp);
			
			byte[] msgResponse = MessageTools.first(serverResp);
			byte[] signServer = MessageTools.second(serverResp);
			
			// 2. if the signature isn't correct, the message is malformed
			// note that the signature is incorrect even if one or both messages are empty
			if (!server_ver.verify(signServer, msgResponse))
				throw new MalformedMessage();
			
			// 3. analyze the ack
			byte[] ack = MessageTools.first(msgResponse);
			
			if(Arrays.equals(ack, Params.STORE_OK)){
				// 4a. the server said the message has been stored correctly
				// we have just to verify that the signClient sent by the server is the same 
				// we generate when we sent the message
				byte[] signature = MessageTools.second(msgResponse);
				if(signature.length==0)
					throw new MalformedMessage();
				if(!Arrays.equals(signature, signClient)) // the server haven't replied the message we sent
					throw new IncorrectReply();
				// we can save the counter used to send the message
				lastCounter.put(label, counter);
				return;
			}
			else if(Arrays.equals(ack, Params.STORE_FAIL)){
				// 4b. server claims to have an higher counter for that label
				byte[] signature_lastCounter = MessageTools.second(msgResponse);
				if(signature_lastCounter.length==0)
					throw new MalformedMessage();
				byte[] signature = MessageTools.first(signature_lastCounter);
				byte[] lastCounter= MessageTools.second(signature_lastCounter);
				if(signature.length==0 || lastCounter.length==0)
					throw new MalformedMessage();
				int serverCounter = MessageTools.byteArrayToInt(lastCounter);
				if(!Arrays.equals(signature, signClient) || serverCounter<counter) // the server haven't replied to the message we sent
					throw new IncorrectReply();
				counter=serverCounter+1;
			}
			else
				throw new MalformedMessage();
			attempts++;
		} while(attempts<Params.CLIENT_ATTEMPTS);		
	}
	
	/**
	 * Retrieve from the server the message related to the correspondent label
	 *  
	 * @param label the label related to the message to be retrieved
	 * @return the message in the server related to the label if it exists, null otherwise
	 */
	public byte[] retreive(byte[] label) throws NetworkError, MalformedMessage, IncorrectReply{
		/* SEND THE FETCH REQUEST TO THE SERVER */
		// 1. retrieve the last counter
		int counter;
		if(lastCounter.containsKey(label))
			counter = lastCounter.get(label);
		else
			return null; // FIXME: not necessarily; perhaps the server has something with this label, even if we do not know about it.
		
		// 2. create the message to send
		byte[] label_counter=MessageTools.concatenate(label, MessageTools.intToByteArray(counter));
		byte[] retrieve_label_counter=MessageTools.concatenate(Params.RETRIEVE, label_counter);
		
		// 3. sign the message
		byte[] signClient = signer.sign(retrieve_label_counter);
		
		byte[]	msgSign = MessageTools.concatenate(retrieve_label_counter, signClient);
		
		// 4. encrypt the (client_id, message, signature) with the server public key
		byte[] msgToSend = server_enc.encrypt(MessageTools.concatenate(MessageTools.intToByteArray(client_id), msgSign));
		
		// Shape of msgToSend:
		//		(clientID, ((RETRIEVE, (label, counter)), signClient))
		// where signClient is the signature of (RETRIEVE, (label, counter))
		
		// 5. send the message to the server
		byte[] serverResp = NetworkClient.sendRequest(msgToSend, Params.SERVER_NAME, Params.SERVER_PORT); 
		
		
		
		// HANDLE THE SERVER RESPONSE 
		//
		// Expected serverResp:
		//		((RETRIEVE_OK, (signClient, (encMsg, signEncrMsg))), signServer)
		//		((RETRIEVE_FAIL, signClient), signServer)
		// 	where in both cases signServer is the signature of the previous tokens,
		//  whereas signEncMsg is the signature of ((STORE, (label, (counter, encrMsg)))
		
		// 1. decrypt the message with the client private key
		serverResp = decryptor.decrypt(serverResp);
		
		byte[] msgResponse = MessageTools.first(serverResp);
		byte[] signServer = MessageTools.second(serverResp);
		
		// 2. if the signature isn't correct, the message is malformed
		// note that the signature is incorrect even if one or both messages are empty
		if (!server_ver.verify(signServer, msgResponse))
			throw new MalformedMessage();
		
		// 3. analyze the ack
		byte[] ack = MessageTools.first(msgResponse);
		
		if(Arrays.equals(ack, Params.RETRIEVE_OK)){
			// 4a. server claims to have retrieved the proper message
			byte[] signature_encrMsg_signMsg = MessageTools.second(msgResponse);
			if(signature_encrMsg_signMsg.length==0)
				throw new MalformedMessage();
			byte[] signature=MessageTools.first(signature_encrMsg_signMsg);
			byte[] encrMsg_signMsg=MessageTools.second(signature_encrMsg_signMsg);
			if(signature.length==0 || encrMsg_signMsg.length==0)
				throw new MalformedMessage();
			if(!Arrays.equals(signature, signClient)) // the server haven't replied to the message we sent
				throw new IncorrectReply();
			byte[] encrMsg = MessageTools.first(encrMsg_signMsg);
			byte[] signMsg = MessageTools.second(encrMsg_signMsg);
			if(encrMsg.length==0 || signMsg.length==0)
				throw new MalformedMessage();
			
			// 5. check whether the signMsg is the signature for encMsg received or not
			/* Encoding the message that has to be signed: (STORE, (label, (counter, encrMsg)))  */
			byte[] counter_msg = MessageTools.concatenate(MessageTools.intToByteArray(counter), encrMsg);
			byte[] label_counter_msg = MessageTools.concatenate(label, counter_msg);
			byte[] store_label_counter_msg = MessageTools.concatenate(Params.STORE, label_counter_msg);
			if(!Arrays.equals(signMsg, signer.sign(store_label_counter_msg)))  // the server haven't replied with the encrypted message we requested
					throw new IncorrectReply();
			
			// 6. decrypt the message and return it 
			return symenc.decrypt(encrMsg);
		}
		else if(Arrays.equals(ack, Params.RETRIEVE_FAIL)){
			// 4b. the server counldn't retrieve the message
			byte[] signature = MessageTools.second(msgResponse);
			if(signature.length==0)
				throw new MalformedMessage();
			if(!Arrays.equals(signature, signClient)) // the server haven't replied to the message we sent
				throw new IncorrectReply();
			return null;
		}
		else
			throw new MalformedMessage();
	}
	
	@SuppressWarnings("serial")
	public class MalformedMessage extends Exception {}
	
	@SuppressWarnings("serial")
	public class IncorrectReply extends Exception {}
	
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
	                tmp.counter=counter;
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
	    
	    public boolean containsKey(byte[] key) {
	    	return get(key) >= 0;
	    }
	}
}
