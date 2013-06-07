package de.uni.trier.infsec.tests;

import java.io.File;
import java.util.Arrays;

import junit.framework.TestCase;
import org.junit.Test;
import de.uni.trier.infsec.cloudStorage.*;
import de.uni.trier.infsec.cloudStorage.Server.MalformedMessage;
import de.uni.trier.infsec.functionalities.pki.real.PKI;
import de.uni.trier.infsec.functionalities.pki.real.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.real.PKIServerCore;
import de.uni.trier.infsec.functionalities.pki.real.PKISig;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.symenc.real.SymEnc;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.Utilities;



public class CloudStorageTest extends TestCase {

	@Test
	public void test() throws Exception{
		setUp(); // delete the PKI database
		PKI.useLocalMode();
		NetworkInterface network = new NetworkTest();
		// CLIENT 01
		int clientID01=1;
		SymEnc symenc01 = new SymEnc();
		PKIEnc.Decryptor decryptor01 = new PKIEnc.Decryptor(clientID01);
		PKISig.Signer signer01 = new PKISig.Signer(clientID01);
		Client client01=null;
		try {
			// register the client to the PKIEnc domain
			PKIEnc.register(decryptor01.getEncryptor(), Params.PKI_ENC_DOMAIN);
			PKISig.register(signer01.getVerifier(), Params.PKI_DSIG_DOMAIN);
			client01 = new Client(clientID01, symenc01, decryptor01, signer01, network);
		} catch (Exception e) {
			System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		}
		
		//byte[] msg01="message01client01".getBytes("UTF-8");
		//byte[] labelMsg01="labelMessage01client01".getBytes("UTF-8");
		byte[] msg01={0x01};
		byte[] labelMsg01={0x02};
		byte[] retrieveMsg01=null;
		try{
			client01.store(msg01, labelMsg01);
			//retrieveMsg01=client01.retreive(labelMsg01);
		} catch (Exception e) {
			System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		}
		/*
		assertTrue("Received data is not equal to sent data", Arrays.equals(msg01, retrieveMsg01));
		//fail("Not yet implemented");
		
		 // CLIENT 02
		int clientID02=2;
		SymEnc symenc02 = new SymEnc();
		PKIEnc.Decryptor decryptor02 = new PKIEnc.Decryptor(clientID02);
		PKISig.Signer signer02 = new PKISig.Signer(clientID02);
		Client client02=null;
		try {
			client02 = new Client(clientID02, symenc02, decryptor02, signer02, network);
		} catch (Exception e) {
			System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		}
		 */
	}

	private class NetworkTest implements NetworkInterface {
		public byte[] sendRequest(byte[] msg) {
			try {
				return Server.processRequest(msg);
			} catch (MalformedMessage | NetworkError | PKIError e) {
				System.err.println( e.getClass().getName() + ": " + e.getMessage() );
			    return null;
			}
		}
	}
	
	@Override
	protected void setUp() throws Exception {
		super.setUp();
		File f = new File(PKIServerCore.DEFAULT_DATABASE);
		f.delete();
	}
}


/*
package de.uni.trier.infsec.cloudStorage;

import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIError;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKISig;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIEnc;
import de.uni.trier.infsec.functionalities.symenc.SymEnc;


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
			client = new Client(HONEST_CLIENT_ID, client_symenc, client_decryptor, client_signer);
		} 
		catch (PKIError e) {
			return;
		} catch (NetworkError e) { // registration failed or it was impossible to obtain the server public keys
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
					} catch(Exception e) {}
				}
				try {
					client.store(msg, label);
				}
				catch(Exception e) {}
				break;

			case 1: // client.retrieve
				label = Environment.untrustedInputMessage();
				try {
					client.retreive(label);	// the result (the retrieved message) is ignored
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
 */
