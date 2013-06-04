package de.uni.trier.infsec.cloudStorage;

/**
 * Interface to handle both test and real network implementations.
 */
public interface NetworkInterface {
	byte[] sendRequest(byte[] msgReq);
}
