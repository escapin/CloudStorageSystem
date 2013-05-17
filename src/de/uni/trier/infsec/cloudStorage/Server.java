package de.uni.trier.infsec.cloudStorage;

import de.uni.trier.infsec.functionalities.pki.idealcor.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKISig;

public class Server {
	
	private PKIEnc encryptor;
	private PKISig signer;
	
	public Server(PKIEnc encryptor, PKISig signer) {
		this.encryptor = encryptor;
		this.signer = signer;
	}
	
	
	/**
	 * Process every request coming from a client and reply with a message 
	 * 
	 * @param msg
	 * @return
	 */
	public byte[] processRequest(byte[] msg){
		return null;
	}
	
	private void store(byte[] msg, byte[] label, int index, byte[] clienID, byte[] clientSignature){
		
	}
	private byte[] getMessage(byte[] label, int index){
		return null;
	}
}
