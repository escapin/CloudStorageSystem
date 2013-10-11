package de.uni.trier.infsec.cloudStorage;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import de.uni.trier.infsec.cloudStorage.Client.CounterOutOfDate;
import de.uni.trier.infsec.functionalities.pki.PKI;
import de.uni.trier.infsec.functionalities.pkienc.*;
import de.uni.trier.infsec.functionalities.pkisig.*;
import de.uni.trier.infsec.functionalities.symenc.SymEnc;
import de.uni.trier.infsec.utils.MessageTools;

public class ClientStoreApp {

	private static Decryptor user_decr;
	private static Signer user_sign;
	private static SymEnc symenc;
	
	private static final int STORE_ATTEMPTS = 3; 
	// attempts to store a msg under a label in such a way that server and client counters are aligned
	
	public static void main(String[] args) throws Exception{		
		System.setProperty("remotemode", Boolean.toString(true));
		PKI.useRemoteMode();
		
		int userID = 0;
		byte[] label=null;
		byte[] msg=null;
		if (args.length < 1 || args.length > 3) {
			System.out.println("Wrong number of Arguments!\nExpected: ClientStoreApp <user_id [int]> <label [String]> <msg [String]>\nExample: ClientRegisterApp 101 pwd blank");
			System.exit(0);
		} else {
			try {				
				userID = Integer.parseInt(args[0]);
				label = args[1].getBytes();
				msg = args[2].getBytes();
			} catch (Exception e) {
				System.out.println("Something is wrong with arguments!\nClientStoreApp <user_id [int]> <label [String]> <msg [String]>\nExample: ClientRegisterApp 101 pwd blank");
				System.exit(0);
			}
		}
		setupClient(userID);
		
		NetworkInterface network = new NetworkReal();
		Client client = new Client(userID, symenc, user_decr, user_sign, network);
		
		boolean outOfDate=true;
		int i=0;
		for(;i<STORE_ATTEMPTS && outOfDate; i++){
			outOfDate=false;
			try{
				client.store(msg, label);
			} catch(CounterOutOfDate e){
				outOfDate=true;
			}
		}
		if(i>=STORE_ATTEMPTS)
			System.out.println("The message has not been stored: during " + STORE_ATTEMPTS + " attempts, the Client's counter has always been out of date!");
	}

	private static void setupClient(int userID) {
		byte[] serialized=null;
		try {
			serialized = readFromFile(Params.PATH_USER + "user" + userID + ".info");
		} catch (FileNotFoundException e){
			System.out.println("User " + userID + " not registered!\nType \'UserRegisterApp <user_id [int]>\' to register him/her.");
			System.exit(0);
		} catch (IOException e) {
			System.out.println("Error while trying to retreive from the memory the client's keys: the file is damaged!");
			System.exit(0);
		}
		byte[] sym_decr_sig = MessageTools.second(serialized);
		symenc = new SymEnc(MessageTools.first(sym_decr_sig));
		byte[] decr_sign = MessageTools.second(sym_decr_sig);
		user_decr = Decryptor.fromBytes(MessageTools.first(decr_sign));
		user_sign = Signer.fromBytes(MessageTools.second(decr_sign));
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
