package de.uni.trier.infsec.cloudStorage;

import java.util.*;

import de.uni.trier.infsec.functionalities.pki.idealcor.PKISig;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIError;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIEnc.Encryptor;
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
	
	private CountList list = new CountList(); // FIXME: 'list' is not a very informative name; could we have something better?
	//private Map<byte[], Integer>  list= new HashMap<byte[], Integer>(); 
	
	public Client(SymEnc symenc, PKIEnc.Decryptor decryptor, PKISig.Signer signer) throws PKIError, NetworkError {
		this.symenc = symenc;
		this.decryptor = decryptor;
		this.signer = signer;
		this.server_enc = PKIEnc.getEncryptor(Params.SERVER_ID, Params.PKI_ENC_DOMAIN);
		this.server_ver = PKISig.getVerifier(Params.SERVER_ID, Params.PKI_DSIG_DOMAIN);
		
	}
	
	/**
	 * Store a message into a server under a label
	 * 
	 * @param message the message which has to be stored
	 * @param label the label related to the message
	 */
	public void store(byte[] msg, byte[] label) throws NetworkError, IncorrectSignature, IncorrectReply{
		// FIXME: we do we use this kind of comments? Is it suppose to show up in javadocs?
		/**
		 * SEND A MESSAGE TO A SERVER
		 */
		// 1. encrypt the message with the symmetric key
		byte[] encrMsg = symenc.encrypt(msg);
		// 2. takes the counter
		int counter=0;
		if(list.containsKey(label))
			counter=((Integer) list.get(label)).intValue()+1; // FIXME: why these conversions? We simply want to store values of type int 
		list.put(label, new Integer(counter));
		
		byte[] signClient=null;
		byte[] serverResp;
		int ack;
		int attempts=0;
		do{
			serverResp = sendToServer(encrMsg, label, counter, signClient); // FIXME: signClient is null
			/**
			 * Expected serverResp
			 * Let
			 * SIGNclient = SIGNclient([ENC_SIM(msg),label,count])
			 * 
			 * ENC_PUclient{SIGNclient, 0, SIGNserver([SIGNclient, 0]) }
			 * 		or
			 * ENC_PUclient{lastCounter, SIGNclient, 1, SIGNserver([ lastCounter, SIGNclient, 1]) }
			 */
			
			/**
			 * HANDLE THE RESPONSE FROM THE SERVER
			 */
			// 1. decrypt the message with the client private key
			serverResp = decryptor.decrypt(serverResp);
			
			// 2. msgResponse should have this structure: (message, signatureServer)
			byte[] msgResponse = MessageTools.first(serverResp);
			byte[] signatureServer = MessageTools.second(serverResp);
			
			// 3. verify the signature
			if (!server_ver.verify(signatureServer, msgResponse))
				throw new IncorrectSignature();
				
			// 4. analyze the ack
			ack = MessageTools.byteArrayToInt(MessageTools.second(msgResponse));
			byte[] tmp=MessageTools.first(msgResponse);
			if(ack==0){ // tmp is just the signature of the message sent
				// check whether the signature received is the signature of the message sent
				if(!Arrays.equals(signClient, tmp)) // FIXME: as noted, signClient is null (the same below);
							throw new IncorrectReply();
			} else {
				// tmp is (last_count, signature)
				if(!Arrays.equals(signClient, MessageTools.second(tmp)))
					throw new IncorrectReply();
				counter = MessageTools.byteArrayToInt(MessageTools.first(tmp)); // FIXME: it should be probaly +1, shouldn't it?
			}
			attempts++;
		} while(ack!=0 && attempts<Params.CLIENT_ATTEMPTS);
	}
	
	
	private byte[] sendToServer(byte[] encrMsg, byte[] label, int counter, byte[] signature) throws NetworkError{
		/**
		 * Shape of msgToSend
		 *   ENC_PUserver{ENC_SIM(msg),label,counter, SIGNclient([ENC_SIM(msg),label,count])} 
		 */
		
		byte[] msgToSend= MessageTools.concatenate(encrMsg, label); 
		// FIXME: we do not need to save variable names. It would be nicer (for me at least), if we use 
		// different variable names to indicate different messages. In this case, the name msgToSend 
		// is misleading, as it is not yet the message to sent. 
		msgToSend = MessageTools.concatenate(msgToSend, MessageTools.intToByteArray(counter));
				
		// 3. sign the message with the client private key 
		signature = signer.sign(msgToSend); // FIXME: the value of parameter 'signature' is ignored; why do we have this parameter then?
				
		// 4. encrypt the (message+signature) with the server public key
		msgToSend = server_enc.encrypt(MessageTools.concatenate(msgToSend, signature));
		
		// 5. send the message to the server and return the response
		return NetworkClient.sendRequest(msgToSend, Params.SERVER_NAME, Params.SERVER_PORT);
	}
	
	/**
	 * Retrieve from the server the message related to the correspondent label
	 *  
	 * @param label the label related to the message to be retrieved
	 * @return the message in the server related to the label if it exists, null otherwise
	 */
	public byte[] retreive(byte[] label){
		return null;
	}
	
	@SuppressWarnings("serial")
	public class IncorrectSignature extends Exception {}
	
	@SuppressWarnings("serial")
	public class IncorrectReply extends Exception {}

}
