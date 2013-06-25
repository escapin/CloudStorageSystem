package de.uni.trier.infsec.cloudStorage;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.pki.real.PKI;
import de.uni.trier.infsec.functionalities.pki.real.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.real.PKISig;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.lib.network.NetworkServer;
import de.uni.trier.infsec.utils.MessageTools;

public class ServerApp {

	private static PKIEnc.Decryptor server_decr;
	private static PKISig.Signer server_sign;
	
	public static void main(String[] args) throws Exception{		
		System.setProperty("remotemode", Boolean.toString(true));
		PKI.useRemoteMode();
		
		ServerApp.setupServer();
		ServerApp.run();
	}

	private static void setupServer() {
		byte[] serialized=null;
		try {
			serialized = readFromFile(Params.PATH_SERVER);
		} catch (FileNotFoundException e){
			System.out.println("Server not registered yet!\nType \'ServerRegisterApp' to register it.");
			System.exit(0);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(0);
		}
		byte[] decryptor_signer = MessageTools.second(serialized);
		server_decr = PKIEnc.decryptorFromBytes(MessageTools.first(decryptor_signer));
		server_sign = PKISig.signerFromBytes(MessageTools.second(decryptor_signer));
		Server.init(server_decr, server_sign);
	}
	
	private static void run() throws Exception{
		System.out.println("Cloud Storage server is running...");
		// Busy waiting - not a nice solution at all, but should be ok for now.
		NetworkServer.listenForRequests(Params.SERVER_PORT);
		while(true){
			byte[] request = NetworkServer.nextRequest(Params.SERVER_PORT);
			if (request != null) {
				byte[] response = Server.processRequest(request);
				NetworkServer.response(response);
			} else {				
				Thread.sleep(500);
			}
		}
	}
		
	private static byte[] readFromFile(String path) throws IOException {
		FileInputStream f = new FileInputStream(path);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		while (f.available() > 0){			
			bos.write(f.read());
		}
		f.close();
		byte[] data = bos.toByteArray();
		return data;
	}
	
	
}
