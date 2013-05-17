package de.uni.trier.infsec.cloudStorage;

import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIError;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKISig;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIEnc;

public class Setup {

	public static final int HONEST_CLIENT_ID = 100;
	
	public static void main(String args[]) {
		setup(true);
	}
	
	
	public static void setup(boolean secret_bit) {
		
		// Create and register the server
		PKIEnc.Decryptor server_decryptor = new PKIEnc.Decryptor(Params.SERVER_ID);
		PKISig.Signer server_signer = new PKISig.Signer(Params.SERVER_ID);
		try {
			PKIEnc.register(server_decryptor.getEncryptor(), Params.PKI_ENC_DOMAIN);
			PKISig.register(server_signer.getVerifier(), Params.PKI_DSIG_DOMAIN);
		} 
		catch (PKIError | NetworkError e) { // registration failed
			return;
		}
		Server server = new Server(server_decryptor, server_signer);

		
		// Create and register the client
		// (we consider one honest client; the remaining clients will be subsumed 
		// by the adversary)
		PKIEnc.Decryptor client_decryptor = new PKIEnc.Decryptor(HONEST_CLIENT_ID);
		PKISig.Signer client_signer = new PKISig.Signer(HONEST_CLIENT_ID);
		try {
			PKIEnc.register(client_decryptor.getEncryptor(), Params.PKI_ENC_DOMAIN);
			PKISig.register(client_signer.getVerifier(), Params.PKI_DSIG_DOMAIN);
		} 
		catch (PKIError | NetworkError e) { // registration failed
			return;
		}
		
		Client client = new Client(client_decryptor, client_signer);
		
		while( Environment.untrustedInput() != 0 ) {
			// the adversary decides what to do:
			// TODO: fill this up
		}
	}	
}
