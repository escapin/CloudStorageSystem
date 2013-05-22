package de.uni.trier.infsec.cloudStorage;

public class Params {
	
	public static byte[] PKI_DSIG_DOMAIN = "PKI_DSIG".getBytes();
	public static byte[] PKI_ENC_DOMAIN  = "PKI_ENC".getBytes();
	
	public static int SERVER_ID = 1;
	
	public static String SERVER_NAME = "192.168.1.1";
	public static int SERVER_PORT= 8080;
	
	public static int CLIENT_ATTEMPTS=3; 
	// how many times the client attempts to send a message to the server with the proper count 
}
