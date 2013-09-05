package de.uni.trier.infsec.cloudStorage;

import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.functionalities.pkienc.*;
import de.uni.trier.infsec.functionalities.pkisig.*;
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
		Decryptor client_decryptor = new Decryptor();
		Signer client_signer = new Signer();
		Client client = null;
		try {
			RegisterEnc.registerEncryptor(client_decryptor.getEncryptor(), HONEST_CLIENT_ID, Params.PKI_ENC_DOMAIN);
			RegisterSig.registerVerifier(client_signer.getVerifier(), HONEST_CLIENT_ID, Params.PKI_DSIG_DOMAIN);
			client = new Client(HONEST_CLIENT_ID, client_symenc, client_decryptor, client_signer, new NetworkReal());
		} 
		catch (RegisterEnc.PKIError e) { // encryptor registration failed -- id already registered
			return;
		}
		catch (RegisterSig.PKIError e) { // verifier registration failed -- id already registered
			return;
		}
		catch (NetworkError e) { // registration failed -- problems with the connection
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
					try {
						msg[i] = (secret_bit ? msg1[i] : msg2[i]);
					} catch (Exception e) { }
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
				Encryptor corrupted_encryptor = new Encryptor(pub_key);
				try {
					RegisterEnc.registerEncryptor(corrupted_encryptor, enc_id, Params.PKI_ENC_DOMAIN);
				}
				catch (Exception e) {}
				break;

			case 3: // registering a corrupted verifier
				byte[] verif_key = Environment.untrustedInputMessage();
				int verif_id = Environment.untrustedInput();
				Verifier corrupted_verifier = new Verifier(verif_key);
				try {
					RegisterSig.registerVerifier(corrupted_verifier, verif_id, Params.PKI_DSIG_DOMAIN);
				}
				catch (Exception e) {}
				break;
			}
		}
	}	
}
;