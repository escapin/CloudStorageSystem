package de.uni.trier.infsec.cloudStorage;

import java.util.Arrays;

import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.functionalities.pki.idealcor.*;
import de.uni.trier.infsec.utils.MessageTools;

public class Server{
	
	private static PKIEnc.Decryptor server_decr = new PKIEnc.Decryptor(Params.SERVER_ID);
	private static PKISig.Signer signer = new PKISig.Signer(Params.SERVER_ID);
	
	private static Storage msgStorage = new Storage();
	
	/**
	 * Process every request coming from a client and reply with the proper response 
	 */
	public static byte[] processRequest(byte[] request) throws MalformedMessage, NetworkError, PKIError {
		/*
		 * Every request has this shape:
		 * 		Enc_Server{ (clientID, ([payload], signClient)) }
		 * 
		 * where 'signClient' is the signature of the payload made by the client		
		 */
		
		// decrypt the request 
		byte[] id_payload_signClient = server_decr.decrypt(request);
		
		byte[] id = MessageTools.first(id_payload_signClient);
		if(id.length!=4) // since clientID is supposed to be a integer, its length must be 4 bytes
			throw new MalformedMessage();
		int userID = MessageTools.byteArrayToInt(id);
		byte[] payload_signClient=MessageTools.second(id_payload_signClient);
		byte[] payload = MessageTools.first(payload_signClient);
		byte[] signClient=MessageTools.second(payload_signClient);
		// verify that the message comes from the client 'clientID'
		PKISig.Verifier clientVerifier = PKISig.getVerifier(userID, Params.PKI_DSIG_DOMAIN);
		if(!clientVerifier.verify(signClient, payload))
			throw new MalformedMessage();
		
		// analyze the request tag
		byte[] tag = MessageTools.first(payload);
		byte[] payloadResp;
		if(Arrays.equals(tag, Params.STORE))
			// we have to store also 'signClient' because when the client asks us to retrieve the message,
			// he wants to be sure that we are giving him the proper message
			payloadResp = store(userID, signClient, MessageTools.second(payload));
		else if(Arrays.equals(tag, Params.RETRIEVE))
			payloadResp =  retrieve(userID, MessageTools.second(payload));
		else
			throw new MalformedMessage();
		
		/*
		 * The shape of the response must be:
		 * 		Enc_client{ ((signClient, [payloadResp]), signServer) }
		 * 
		 * where 'signServer' is the signature of the previous tokens 
		 */
		// add the signClient token in front of the payloadResp
		byte[] signClient_payloadResp = MessageTools.concatenate(signClient, payloadResp);
		// sign the message with the server private key
		byte[] signServer = signer.sign(signClient_payloadResp);
		byte[] msgSigned = MessageTools.concatenate(signClient_payloadResp, signServer);
		
		// encrypt the message for the client and return it
		PKIEnc.Encryptor clientEncryptor = PKIEnc.getEncryptor(userID, Params.PKI_ENC_DOMAIN);
		
		return clientEncryptor.encrypt(msgSigned);
	}
	
	/**
	 * Try to store the message and reply:
	 * - STORE_OK:	the message has been stored correctly
	 * - (STORE_FAIL, lastCounter):	there is already a message stored with the same (userID, label) but with an higher counter 
	 */
	private static byte[] store(int userID, byte[] signClient, byte[] label_counter_encMsg) throws MalformedMessage{
		// Shape of the message to parse: (label, (counter, encMsg))
		byte[] label = MessageTools.first(label_counter_encMsg);
		byte[] counter_encMsg = MessageTools.second(label_counter_encMsg);
		byte[] counterB = MessageTools.first(counter_encMsg);
		byte[] encMsg = MessageTools.second(counter_encMsg);
		if(label.length==0 || counterB.length!=4 || encMsg.length==0)
			throw new MalformedMessage();
		int counter = MessageTools.byteArrayToInt(counterB);
		// check whether the counter is higher than the highest counter associated with that 'label'
		int lastCounter=msgStorage.getLastCounter(userID, label);
		if(counter<=lastCounter)
			// we can't store the message
			// we have to return the message (STORE_FAIL, lastCounter)
			return MessageTools.concatenate(Params.STORE_FAIL, MessageTools.intToByteArray(lastCounter));
		// otherwise we can store the message
		msgStorage.insert(userID, label, counter, encMsg, signClient);
		return Params.STORE_OK;
	}
	
	
	/**
	 * Try to retrieve the message indexed with (userID, label, counter) and reply:
	 * - (RETRIEVE_OK, (encMsg, signEncrMsg)):	the message and the signature of it when it was sent to the server 
	 * - RETREIVE_FAIL:	there isn't any message indexed with (userID, label, counter)
	 */
	private static byte[] retrieve(int userID, byte[] label_counter) throws MalformedMessage{
		// Shape of the message to parse: (label, counter)
		byte[] label = MessageTools.first(label_counter);
		byte[] counterB = MessageTools.second(label_counter);
		if(label.length==0 || counterB.length!=4)
			throw new MalformedMessage();
		int counter = MessageTools.byteArrayToInt(counterB);
		byte[] encMsg = msgStorage.getMessage(userID, label, counter);
		if(encMsg==null) // the message isn't in the storage
			return Params.RETRIEVE_FAIL;
		byte[] signEncMsg = msgStorage.getSignature(userID, label, counter);
		byte[] msg_sign = MessageTools.concatenate(encMsg, signEncMsg);
		return MessageTools.concatenate(Params.RETRIEVE_OK, msg_sign);
	}
	
	/**
	 * Exception thrown when the request we received does not conform
	 * to an expected format (we get, for instance, a trash message). 
	 */
	@SuppressWarnings("serial")
	public static class MalformedMessage extends Exception {}
}