package de.uni.trier.infsec.cloudStorage;

import de.uni.trier.infsec.lib.network.*;

public class NetworkReal implements NetworkInterface {
	public byte[] sendRequest(byte[] msg) {
		byte[] resp=null;
		try{
		resp= NetworkClient.sendRequest(msg, Params.SERVER_NAME, Params.SERVER_PORT);
		} catch (NetworkError e){
			System.err.println( e.getClass().getName() + ", NetworkError: " + e.getMessage() );
		    System.exit(0);
		}
		return resp;
	}
}
