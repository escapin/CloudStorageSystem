package de.uni.trier.infsec.cloudStorage;

import java.io.File;

public class Params {

	public static byte[] PKI_DSIG_DOMAIN = "PKI_DSIG".getBytes();
	public static byte[] PKI_ENC_DOMAIN  = "PKI_ENC".getBytes();
	public static int SERVER_ID = -1;
	public static String SERVER_NAME = "localhost";
	public static int SERVER_PORT= 7075;

	// Request tags
	public static byte[] STORE="STORE".getBytes();
	public static byte[] STORE_OK="STORE_OK".getBytes();
	public static byte[] STORE_FAIL="STORE_FAIL".getBytes();
	public static byte[] GET_COUNTER="GET_COUNTER".getBytes();

	// Response tags
	public static byte[] RETRIEVE="RETRIEVE".getBytes();
	public static byte[] RETRIEVE_OK="RETRIEVE_OK".getBytes();
	public static byte[] RETRIEVE_FAIL="RETRIEVE_FAIL".getBytes();
	public static byte[] LAST_COUNTER="LAST_COUNTER".getBytes();

	// Storage
	public static final String PATH_STORAGE = System.getProperty("java.io.tmpdir") + File.separator + "CloudStorage" + File.separator;
	public static final String STORAGE_DB = PATH_STORAGE + File.separator + "cloud_storage.db";
	public static final String PATH_SERVER = Params.PATH_STORAGE + File.separator + "server.info";
	public static final String PATH_USER = Params.PATH_STORAGE + File.separator;
}

