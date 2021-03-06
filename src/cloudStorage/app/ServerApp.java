package cloudStorage.app;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.SQLException;

import cloudStorage.core.Params;
import cloudStorage.core.Server;
import funct.pki.PKI;
import funct.pkienc.*;
import funct.pkisig.*;
import lib.network.NetworkServer;
import utils.MessageTools;

public class ServerApp {

	private static Decryptor server_decr;
	private static Signer server_sign;

	public static void main(String[] args) throws Exception{		
		System.setProperty("remotemode", Boolean.toString(true));
		PKI.useRemoteMode();

		ServerApp.setupServer();
		ServerApp.run();
	}

	private static void setupServer() throws ClassNotFoundException, SQLException {
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
		server_decr = Decryptor.fromBytes(MessageTools.first(decryptor_signer));
		server_sign = Signer.fromBytes(MessageTools.second(decryptor_signer));
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
