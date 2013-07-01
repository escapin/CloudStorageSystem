package de.uni.trier.infsec.tests;

import java.io.File;
import java.util.Arrays;

import junit.framework.TestCase;
import org.junit.Test;
import de.uni.trier.infsec.cloudStorage.*;
import de.uni.trier.infsec.cloudStorage.Client.CounterOutOfDate;
import de.uni.trier.infsec.cloudStorage.Server.MalformedMessage;
import de.uni.trier.infsec.functionalities.pki.real.PKI;
import de.uni.trier.infsec.functionalities.pki.real.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.real.PKIServerCore;
import de.uni.trier.infsec.functionalities.pki.real.PKISig;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.symenc.real.SymEnc;
import de.uni.trier.infsec.lib.network.NetworkError;

public class CloudStorageTest extends TestCase {

	@Test
	public void test() throws Exception {
		
		// delete the database where the message are stored
		File f = new File(Params.STORAGE_DB);
		if(f.exists())
			f.delete();
		
		PKI.useLocalMode();
		// Register the server:
		Server.init();

		NetworkInterface network = new NetworkTest();
		
		// CLIENT 01
		int userID01=101;
		SymEnc symenc01 = new SymEnc();
		PKIEnc.Decryptor decryptor01 = new PKIEnc.Decryptor();
		PKISig.Signer signer01 = new PKISig.Signer();
		// register the client to the PKIEnc domain
		PKIEnc.registerEncryptor(decryptor01.getEncryptor(), userID01, Params.PKI_ENC_DOMAIN);
		PKISig.registerVerifier(signer01.getVerifier(), userID01, Params.PKI_DSIG_DOMAIN);
		Client client01 = new Client(userID01, symenc01, decryptor01, signer01, network);
		
		// CLIENT 02
		int userID02=102;
		SymEnc symenc02 = new SymEnc();
		PKIEnc.Decryptor decryptor02 = new PKIEnc.Decryptor();
		PKISig.Signer signer02 = new PKISig.Signer();
		// register the client to the PKIEnc domain
		PKIEnc.registerEncryptor(decryptor02.getEncryptor(), userID02, Params.PKI_ENC_DOMAIN);
		PKISig.registerVerifier(signer02.getVerifier(), userID02, Params.PKI_DSIG_DOMAIN);
		Client client02 = new Client(userID02, symenc02, decryptor02, signer02, network);
		
		
		byte[] msg01="message01".getBytes();
		byte[] label01="label01".getBytes();
		byte[] msg02="message02".getBytes();
		byte[] label02="label02".getBytes();
		
		
		client01.store(msg01, label01);
		
		client02.store(msg02, label02);
		
		byte[] retrieveMsg01=client01.retrieve(label01);
		byte[] retrieveMsg02=client02.retrieve(label02);
		
		System.out.println("\"" + new String(msg01) + "\" equals to \"" + new String(retrieveMsg01) + "\"");
		assertTrue("Data retrieved not equal to data stored", Arrays.equals(msg01, retrieveMsg01));
		
		System.out.println("\"" + new String(msg02) + "\" equals to \"" + new String(retrieveMsg02) + "\"");
		assertTrue("Data retrieved not equal to data stored", Arrays.equals(msg02, retrieveMsg02));
		
		byte[] msg03="message03".getBytes();
		
		// store the msg03 under the same label of the msg01
		client01.store(msg03, label01);
		
		// we expect to retrieve msg03 instead of msg01
		byte[] retrieveMsg03=client01.retrieve(label01);
		
		System.out.println("\"" + new String(msg03) + "\" equals to \"" + new String(retrieveMsg03) + "\"");
		assertTrue("Data retrieved not equal to data stored", Arrays.equals(msg03, retrieveMsg03));
		
		
		// CLIENT 03
		int userID03=103;
		SymEnc symenc03 = new SymEnc();
		PKIEnc.Decryptor decryptor03 = new PKIEnc.Decryptor();
		PKISig.Signer signer03 = new PKISig.Signer();
		// register the client to the PKIEnc domain
		PKIEnc.registerEncryptor(decryptor03.getEncryptor(), userID03, Params.PKI_ENC_DOMAIN);
		PKISig.registerVerifier(signer03.getVerifier(), userID03, Params.PKI_DSIG_DOMAIN);
		Client client03 = new Client(userID03, symenc03, decryptor03, signer03, network);
		
		// 
		client03.store(msg03, label01);
		byte[] retrieveMsg = client03.retrieve(label01);
		System.out.println("\"" + new String(msg03) + "\" equals to \"" + new String(retrieveMsg) + "\"");
		assertTrue("Data retrieved not equal to data stored", Arrays.equals(msg03, retrieveMsg));
	
		
		retrieveMsg = client02.retrieve(label01);
		assertTrue("Retrieved a message never stored", retrieveMsg==null);
		
		
		// test the CounterSynchronizationError() exception
		Client client04= new Client(userID03, symenc03, decryptor03, signer03, network);
		// client03 and client04 belong to the same user!
		byte[] msg04 = "message03".getBytes();
		try{
			client04.store(msg04, label01);
		} catch (CounterOutOfDate e){
			System.out.println("Houston, we had had a problem: the counter is out of date!");
			// if it happens, just do it again! 
			client04.store(msg04, label01); 
			// FIXME: and now we do not try to catch an exception? why?
			// because before throwing a CounterOutOfDate exception we update the counter. Therefore, since 
			// there isn't any concurrency, we are sure that another CounterOutOfDate exception can't happen again.  
		}
		// client03 should retrieve exactly msg04
		retrieveMsg = client03.retrieve(label01);
		
		System.out.println("\"" + new String(msg04) + "\" equals to \"" + new String(retrieveMsg) + "\"");
		assertTrue("Data retrieved not equal to data stored", Arrays.equals(msg04, retrieveMsg));
	}

	private class NetworkTest implements NetworkInterface {
		public byte[] sendRequest(byte[] msg) throws NetworkError{
				try {
					return Server.processRequest(msg);
				} catch (MalformedMessage | PKIError e) {
					e.printStackTrace();
				}
				return null;
		}
	}
	
	@Override
	protected void setUp() throws Exception {
		super.setUp();
		File f = new File(PKIServerCore.DEFAULT_DATABASE);
		f.delete();
	}
}
