package de.uni.trier.infsec.tests;

import static org.junit.Assert.*;

import org.junit.Test;

import de.uni.trier.infsec.cloudStorage.NetworkInterface;
import de.uni.trier.infsec.cloudStorage.Params;
import de.uni.trier.infsec.cloudStorage.Server;
import de.uni.trier.infsec.cloudStorage.Server.MalformedMessage;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.lib.network.NetworkClient;
import de.uni.trier.infsec.lib.network.NetworkError;

public class ClientTest {

	@Test
	public void test() {
		fail("Not yet implemented");
	}

	private class NetworkTest implements NetworkInterface {
		public byte[] sendRequest(byte[] msg) {
			byte[] resp=null;
			try {
				resp=Server.processRequest(msg);
			} catch (MalformedMessage | NetworkError | PKIError e) {
				System.err.println( e.getClass().getName() + ": " + e.getMessage() );
			    System.exit(0);
			}
			return resp;
		}
	}
}
