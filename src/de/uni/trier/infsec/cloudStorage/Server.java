package de.uni.trier.infsec.cloudStorage;

import de.uni.trier.infsec.functionalities.pki.idealcor.PKIEnc;

public class Server{
	
	private static PKIEnc.Decryptor server_decr = new PKIEnc.Decryptor(Params.SERVER_ID);
	
	
	/**
	 * Process every request coming from a client and reply with a message 
	 * 
	 * @param request
	 * @return
	 */
	public static byte[] processRequest(byte[] request){
		// 1. decrypt the request with the server private key		
		byte[] msg = server_decr.decrypt(request);
		
		return null;
	}
	
	
	/* ENC_PUserver{ENC_SIM(msg),label,counter, SIGNclient([ENC_SIM(msg),label,counter])} */
	private static void store(byte[] encMsg, byte[] label, int counter, byte[] clientID, byte[] clientSignature){
		
	}
	
	/* ENC_PUserver{FETCH,label,counter} */
	private static byte[] getMsg(byte[] label, int index){
		return null;
	}
}
