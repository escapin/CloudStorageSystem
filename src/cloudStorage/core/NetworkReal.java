package cloudStorage.core;

import lib.network.*;

public class NetworkReal implements NetworkInterface {
	public byte[] sendRequest(byte[] msg) throws NetworkError {
		return NetworkClient.sendRequest(msg, Params.SERVER_NAME, Params.SERVER_PORT);
	}
}
