package de.uni.trier.infsec.cloudStorage;

public class Params {

	public static byte[] PKI_DSIG_DOMAIN = "PKI_DSIG".getBytes();
	public static byte[] PKI_ENC_DOMAIN  = "PKI_ENC".getBytes();

	public static int SERVER_ID = 1;

	public static String SERVER_NAME = "192.168.1.1";
	public static int SERVER_PORT= 8080;

	// Request tags
	public static byte[] STORE={0};
	public static byte[] STORE_OK={1};
	public static byte[] STORE_FAIL={2};

	// Response tags
	public static byte[] RETRIEVE={3};
	public static byte[] RETRIEVE_OK={4};
	public static byte[] RETRIEVE_FAIL={5};
}

