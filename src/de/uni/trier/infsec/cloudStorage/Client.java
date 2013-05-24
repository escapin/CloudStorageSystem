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
	
	private LabelList lastCounter = new LabelList(); // for each label maintains the last counter
	
	public Client(SymEnc symenc, PKIEnc.Decryptor decryptor, PKISig.Signer signer) throws PKIError, NetworkError {
		this.symenc = symenc;
		this.decryptor = decryptor;
		this.signer = signer;
		this.server_enc = PKIEnc.getEncryptor(Params.SERVER_ID, Params.PKI_ENC_DOMAIN);
		this.server_ver = PKISig.getVerifier(Params.SERVER_ID, Params.PKI_DSIG_DOMAIN);
		
	}
	
	/**
	 * Store a message on the server under a given label
	 * 
	 * @param message the message which has to be stored
	 * @param label the label related to the message
	 */
	public void store(byte[] msg, byte[] label) throws NetworkError, MalformedMessage, IncorrectReply{
		// 1. encrypt the message with the symmetric key and encode it with the label
		byte[] encrMsg = symenc.encrypt(msg);
		byte[] msg_label = MessageTools.concatenate(encrMsg, label); 
		
		// 2. pick the last the counter
		int counter = lastCounter.get(label) + 1; // note that if label has not been used, get(label) returns -1
		lastCounter.put(label, counter); // TODO: is this a good place to do this
		
		int attempts=0;
		do{
			// Shape of msgToSend
			//   ENC_PUserver{ENC_SIM(msg),label,counter, SIGNclient([ENC_SIM(msg),label,counter])} 
			
			byte[] msg_label_counter = MessageTools.concatenate(msg_label, MessageTools.intToByteArray(counter));
			
			// 3. sign the message with the client private key 
			byte[] signature = signer.sign(msg_label_counter);
			
			// 4. encrypt the (message, signature) with the server public key
			byte[] msgToSend = server_enc.encrypt(MessageTools.concatenate(msg_label_counter, signature));
			
			// 5. send the message to the server
			byte[] encryptedResp = NetworkClient.sendRequest(msgToSend, Params.SERVER_NAME, Params.SERVER_PORT);
			// TODO: since we have 'FETCH' for retrieve, shouldn't we have 'PUT' (or something like this) here?
			
			// HANDLE THE SERVER RESPONSE 
			//
			// Expected serverResp
			// Let
			// SIGNclient = SIGNclient([FETCH,label,counter])
			//
			// ENC_PUclient{SIGNclient, 0, SIGNserver([SIGNclient, 0]) }
			// 		or
			// ENC_PUclient{lastCounter, SIGNclient, 1, SIGNserver([ lastCounter, SIGNclient, 1]) }
			//
			// FIXME: it this description up-to-date? What is 'FETCH' doing here?
			// The type of answer is at diffent positions in 
			// different replies -- that's stragne.
			
			// 1. decrypt the message with the client private key
			byte[] serverResp = decryptor.decrypt(encryptedResp);
			
			// FIXME: Should we check the correct shape of the response before processing it?
			
			// 2. serverResp should have this structure: (message, signatureServer)
			byte[] msgResponse = MessageTools.first(serverResp);
			byte[] signatureServer = MessageTools.second(serverResp);
			
			// 3. verify the signature
			if (!server_ver.verify(signatureServer, msgResponse))
				throw new MalformedMessage();
				
			// TODO: We need to discuss this process again.
			// 4. analyze the ack
			int ack = MessageTools.byteArrayToInt(MessageTools.second(msgResponse));
			// FIXME: I think that it is nicer if ack (encoding the type of response) is the first part of the first
			// part of the response, because the format of the rest depends on it.
			byte[] rest=MessageTools.first(msgResponse);
			if(ack==0){ // rest is just the signature of the message sent
				if(attempts>0)	// if we aren't in the first attempt we have to update the counter to the proper label in 'lastCounter'
					lastCounter.put(label, counter); // FIXME:  it should be done when the counter gets changed.
				
				// check whether the signature received is the signature of the message sent or not
				if(!Arrays.equals(signature, rest))
							throw new IncorrectReply();
				return;
			} else {
				// rest is (last_count, signature)
				if(!Arrays.equals(signature, MessageTools.second(rest)))
					throw new IncorrectReply();
				counter = MessageTools.byteArrayToInt(MessageTools.first(rest))+1; 
				// FIXME: we have to check whether it is not smaller than our current counter. 
			}
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
		/* 
		 * SEND THE FETCH REQUEST TO THE SERVER
		 */
		// 1. retrieve the last counter
		int counter;
		if(lastCounter.containsKey(label))
			counter = lastCounter.get(label);
		else
			return null; // FIXME: not necessarily; perhaps the server has something with this label, even if we do not know about it.
		// 2. create the message to send
		byte[] fetch_label=MessageTools.concatenate("FETCH".getBytes(), label);
		byte[] fetch_label_counter=MessageTools.concatenate(fetch_label, MessageTools.intToByteArray(counter));
		// FIXME: we do not put the counter to this request; rather, we ask the server for the newest value
		
		// 4. encrypt the (message, signature) with the server public key
		byte[] msgToSend = server_enc.encrypt(fetch_label_counter);
					
		/* Shape of msgToSend
		 *   ENC_PUserver{FETCH,label,counter, SIGNclient([FETCH,label,counter])} 
		 */
		// 5. send the message to the server
		byte[] serverResp = NetworkClient.sendRequest(msgToSend, Params.SERVER_NAME, Params.SERVER_PORT); 
		
		/* 
		 * HANDLE THE SERVER RESPONSE 
		 *
		 * Expected serverResp
		 * Let
		 * SIGNclient = SIGNclient(ENC(msg),label, counter)
		 * 
		 * ENC_PUclient{ENC(msg), SIGNclient}
		 */
		// 1. decrypt the message with the client private key
		serverResp = decryptor.decrypt(serverResp);
		
		// FIXME: Should we check the correct shape of the response before processing it?
		
		// 2. serverResp should have this structure: (ENC(msg), signClient)
		byte[] encrMsg = MessageTools.first(serverResp);
		byte[] signClient = MessageTools.second(serverResp);
		// FIXME: The counter should also be in the response.
		// We also need to make sure that the server does not give us a reply with a smaller counter than the one we have.
		
		// 3. verify that the message received corresponds to the message stored in the server
		byte[] msg_label = MessageTools.concatenate(encrMsg, label);
		byte[] msg_label_counter = MessageTools.concatenate(msg_label, MessageTools.intToByteArray(counter));
		if (!server_ver.verify(signClient, msg_label_counter)) // to ensure that we got the message we asked for
			throw new MalformedMessage();
		
		// 4. decrypt the message and return it 
		return symenc.decrypt(encrMsg);
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
