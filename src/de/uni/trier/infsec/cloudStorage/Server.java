package de.uni.trier.infsec.cloudStorage;

import de.uni.trier.infsec.functionalities.pki.idealcor.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKISig;

public class Server {
	
	private PKIEnc.Decryptor decryptor;
	private PKISig.Signer signer;
	
	public Server(PKIEnc.Decryptor decryptor, PKISig.Signer signer) {
		this.decryptor = decryptor;
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
