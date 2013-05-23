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
	
	private LabelList lastCounter = new LabelList(); // for each label maintains the last counter
	
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
		/* 
		 * SEND A MESSAGE TO A SERVER 
		 */
		// 1. encrypt the message with the symmetric key and encode it with the label
		byte[] encrMsg = symenc.encrypt(msg);
		byte[] msg_label = MessageTools.concatenate(encrMsg, label); 
		
		// 2. pick the last the counter
		int counter=0;
		if(lastCounter.containsKey(label))
			counter = lastCounter.get(label)+1; 
		lastCounter.put(label, counter);
		
		byte[] msg_label_counter, signClient, msgToSend, serverResp;
		int ack;
		int attempts=0;
		do{
			msg_label_counter = MessageTools.concatenate(msg_label, MessageTools.intToByteArray(counter));
			
			// 3. sign the message with the client private key 
			signClient = signer.sign(msg_label_counter);
			
			// 4. encrypt the (message, signature) with the server public key
			msgToSend = server_enc.encrypt(MessageTools.concatenate(msg_label_counter, signClient));
			
			// 5. send the message to the server
			
			/* Shape of msgToSend
			 *   ENC_PUserver{ENC_SIM(msg),label,counter, SIGNclient([ENC_SIM(msg),label,count])} 
			 */
			serverResp = NetworkClient.sendRequest(msgToSend, Params.SERVER_NAME, Params.SERVER_PORT); 
			
			/* 
			 * HANDLE THE SERVERR RESPONSE 
			 *
			 * Expected serverResp
			 * Let
			 * SIGNclient = SIGNclient([ENC_SIM(msg),label,count])
			 * 
			 * ENC_PUclient{SIGNclient, 0, SIGNserver([SIGNclient, 0]) }
			 * 		or
			 * ENC_PUclient{lastCounter, SIGNclient, 1, SIGNserver([ lastCounter, SIGNclient, 1]) }
			 */
			// 1. decrypt the message with the client private key
			serverResp = decryptor.decrypt(serverResp);
			
			// FIXME: Should we check the correct shape of the response before processing it?
			
			// 2. msgResponse should have this structure: (message, signatureServer)
			byte[] msgResponse = MessageTools.first(serverResp);
			byte[] signatureServer = MessageTools.second(serverResp);
			
			// 3. verify the signature
			if (!server_ver.verify(signatureServer, msgResponse))
				throw new IncorrectSignature();
				
			// 4. analyze the ack
			ack = MessageTools.byteArrayToInt(MessageTools.second(msgResponse));
			byte[] rest=MessageTools.first(msgResponse);
			if(ack==0){ // rest is just the signature of the message sent
				// check whether the signature received is the signature of the message sent
				if(!Arrays.equals(signClient, rest))
							throw new IncorrectReply();
			} else {
				// rest is (last_count, signature)
				if(!Arrays.equals(signClient, MessageTools.second(rest)))
					throw new IncorrectReply();
				counter = MessageTools.byteArrayToInt(MessageTools.first(rest))+1;
			}
			attempts++;
		} while(ack!=0 && attempts<Params.CLIENT_ATTEMPTS);
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
