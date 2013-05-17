package de.uni.trier.infsec.cloudStorage;

import de.uni.trier.infsec.functionalities.pki.idealcor.PKISig;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIEnc;

public class Client {

	private PKIEnc encryptor;
	private PKISig signer;
	
	public Client(PKIEnc encryptor, PKISig signer) {
		this.encryptor = encryptor;
		this.signer = signer;
	}
	
	/**
	 * Store a message into a server under a label
	 * 
	 * @param message the message that has to be stored
	 * @param label the label related to the message
	 */
	public void store(byte[] msg, byte[] label){
		
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
