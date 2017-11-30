package cloudStorage;

import lib.network.NetworkError;

/**
 * Interface to handle both test and real network implementations.
 */
public interface NetworkInterface{
	byte[] sendRequest(byte[] msgReq) throws NetworkError;
}
