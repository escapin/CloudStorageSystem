package de.uni.trier.infsec.cloudStorage;

import de.uni.trier.infsec.environment.network.NetworkError;

/**
 * Interface to handle both test and real network implementations.
 */
public interface NetworkInterface{
	byte[] sendRequest(byte[] msgReq) throws NetworkError;
}
