package de.uni.trier.infsec.cloudStorage;

import de.uni.trier.infsec.environment.network.*;

public class NetworkReal implements NetworkInterface {
	public byte[] sendRequest(byte[] msg) throws NetworkError {
		return NetworkClient.sendRequest(msg, Params.SERVER_NAME, Params.SERVER_PORT);
	}
}
