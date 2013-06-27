package de.uni.trier.infsec.cloudStorage;

import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIError;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKISig;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIEnc;
import de.uni.trier.infsec.functionalities.symenc.SymEnc;

/**
 * A setup for modeling one honest client interacting with possibly dishonest server
 * and -- possibly -- other dishonest clients. All the dishonest parties are subsumed
 * by the adversary.
 */
public class Setup {

	public static final int HONEST_CLIENT_ID = 100;

	public static void main(String args[]) {
		setup(true);
	}

	public static void setup(boolean secret_bit) {
		// Create and register the client
		// (we consider one honest client; the remaining clients will be subsumed 
		// by the adversary)
		SymEnc client_symenc = new SymEnc();
		PKIEnc.Decryptor client_decryptor = new PKIEnc.Decryptor(HONEST_CLIENT_ID);
		PKISig.Signer client_signer = new PKISig.Signer(HONEST_CLIENT_ID);
		Client client = null;
		try {
			PKIEnc.register(client_decryptor.getEncryptor(), Params.PKI_ENC_DOMAIN);
			PKISig.register(client_signer.getVerifier(), Params.PKI_DSIG_DOMAIN);
			client = new Client(HONEST_CLIENT_ID, client_symenc, client_decryptor, client_signer, new NetworkReal());
		} 
		catch (PKIError | NetworkError e) { // registration failed or it was impossible to obtain the server public keys
			return;
		}

		while( Environment.untrustedInput() != 0 ) {
			// the adversary decides what to do:
			int action = Environment.untrustedInput();

			switch (action) {
			case 0: // client.store
				byte[] label = Environment.untrustedInputMessage();
				byte[] msg1 = Environment.untrustedInputMessage();
				byte[] msg2 = Environment.untrustedInputMessage();
				if (msg1.length != msg2.length) break;
				byte[] msg = new byte[msg1.length];
				for (int i=0; i<msg1.length; ++i) {
					msg[i] = (secret_bit ? msg1[i] : msg2[i]);
				}
				try {
					client.store(msg, label);
				}
				catch(Exception e) {}
				break;

			case 1: // client.retrieve
				label = Environment.untrustedInputMessage();
				try {
					client.retrieve(label);	// the result (the retrieved message) is ignored
				}
				catch(Exception e) {}
				break;

			case 2: // registering a corrupted encryptor
				byte[] pub_key = Environment.untrustedInputMessage();
				int enc_id = Environment.untrustedInput();
				PKIEnc.Encryptor corrupted_encryptor = new PKIEnc.Encryptor(enc_id, pub_key);
				try {
					PKIEnc.register(corrupted_encryptor, Params.PKI_ENC_DOMAIN);
				}
				catch (Exception e) {}
				break;

			case 3: // registering a corrupted verifier
				byte[] verif_key = Environment.untrustedInputMessage();
				int verif_id = Environment.untrustedInput();
				PKISig.Verifier corrupted_verifier = new PKISig.Verifier(verif_id, verif_key);
				try {
					PKISig.register(corrupted_verifier, Params.PKI_DSIG_DOMAIN);
				}
				catch (Exception e) {}
				break;
			}
		}
	}	
}
;