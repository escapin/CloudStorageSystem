package de.uni.trier.infsec.cloudStorage;

import de.uni.trier.infsec.functionalities.pki.idealcor.PKISig;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIError;
import de.uni.trier.infsec.functionalities.symenc.SymEnc;
import de.uni.trier.infsec.environment.network.NetworkError;

public class Client {

	private SymEnc symenc;
	private PKIEnc.Decryptor decryptor;
	private PKISig.Signer signer;
	private PKIEnc.Encryptor server_enc;
	private PKISig.Verifier server_ver;
	
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
