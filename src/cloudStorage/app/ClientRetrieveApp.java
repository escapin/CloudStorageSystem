package cloudStorage.app;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import cloudStorage.core.Client;
import cloudStorage.core.NetworkInterface;
import cloudStorage.core.NetworkReal;
import cloudStorage.core.Params;
import funct.pki.PKI;
import funct.pkienc.*;
import funct.pkisig.*;
import funct.symenc.SymEnc;
import utils.MessageTools;

public class ClientRetrieveApp {

	private static Decryptor user_decr;
	private static Signer user_sign;
	private static SymEnc symenc;
	
	public static void main(String[] args) throws Exception{		
		System.setProperty("remotemode", Boolean.toString(true));
		PKI.useRemoteMode();
		
		int userID = 0;
		byte[] label=null;
		if (args.length < 1 || args.length > 2) {
			System.out.println("Wrong number of Arguments!\nExpected: ClientRetrieveApp <user_id [int]> <label [String]>\nExample: ClientRetrieveApp 101 pwd");
			System.exit(0);
		} else {
			try {				
				userID = Integer.parseInt(args[0]);
				label = args[1].getBytes();
			} catch (Exception e) {
				System.out.println("Something is wrong with arguments!\nClientRetrieveApp <user_id [int]> <label [String]> \nExample: ClientRetrieveApp 101 pwd");
				System.exit(0);
			}
		}
		setupClient(userID);
		
		NetworkInterface network = new NetworkReal();
		Client client = new Client(userID, symenc, user_decr, user_sign, network);
		
		byte[] msg = client.retrieve(label);
		if(msg!=null)
			System.out.println("Message stored in the server under the label '" + new String(label) + "'\n" + new String(msg) );
		else
			System.out.println("No message stored in the server under the label '" + new String(label) + "'");
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
