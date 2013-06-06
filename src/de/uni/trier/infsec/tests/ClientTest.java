package de.uni.trier.infsec.tests;

import junit.framework.TestCase;
import org.junit.Test;
import de.uni.trier.infsec.cloudStorage.NetworkInterface;
import de.uni.trier.infsec.cloudStorage.Server;
import de.uni.trier.infsec.cloudStorage.Server.MalformedMessage;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.lib.network.NetworkError;

// TODO: why ClientTest? Aren't we going to test clients and the server together?
public class ClientTest extends TestCase {

	@Test
	public void test() {
		fail("Not yet implemented");
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
}
