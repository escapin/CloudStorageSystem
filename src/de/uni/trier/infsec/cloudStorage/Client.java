package de.uni.trier.infsec.cloudStorage;

import java.util.HashMap;
import java.util.Map;

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
	
	private CountList list = new CountList();
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
	public void store(byte[] msg, byte[] label){
		/**
		 * SEND A MESSAGE TO A SERVER
		 */
		// 1. encrypt the message and add the label
		
		byte[] toStore= MessageTools.concatenate(symenc.encrypt(msg), label); // Correct with symmetric key?
		
		// 2. add count
		int count=0;
		if(list.containsKey(label))
			count=((Integer) list.get(label)).intValue()+1;
		list.put(label, new Integer(count));
		
		toStore=MessageTools.concatenate(toStore, MessageTools.intToByteArray(count));
		
		// 3. sign the message with the client private key 
		byte[] signature = signer.sign(toStore);
		
		// 4. encrypt the (message+signature) with the server public key
		byte[] msgToSend=server_enc.encrypt(MessageTools.concatenate(toStore, signature));
		
		/**
		 * Shape of msgToSend
		 *   ENC_PUserver{ENC_SIM(msg),label,count, SIGNclient([ENC_SIM(msg),label,count])} 
		 */
		
		// 5. send the message to the server and take the response
		byte[] serverResp;
		try{
			serverResp = NetworkClient.sendRequest(msgToSend, Params.SERVER_NAME, Params.SERVER_PORT);
		} catch(NetworkError e) {
			return;
		}
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
			return; 	// or maybe throw an exception!
		
		// 4. analyze the Ack
		int ack = MessageTools.byteArrayToInt(MessageTools.second(msgResponse));
		/*
		if(ack==0)
			// everything fine!
		else
			// the "count" variable in the message sent is lower 
			// than the last counter in the server with that label! 
		*/
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
}
