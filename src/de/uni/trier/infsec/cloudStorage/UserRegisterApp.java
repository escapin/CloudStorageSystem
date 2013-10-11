package de.uni.trier.infsec.cloudStorage;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.pki.PKI;
import de.uni.trier.infsec.functionalities.pkienc.*;
import de.uni.trier.infsec.functionalities.pkisig.*;
import de.uni.trier.infsec.functionalities.symenc.SymEnc;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;

public class UserRegisterApp {

	public static void main(String[] args) {
		System.setProperty("remotemode", Boolean.toString(true));
		int userID=0;
		if (args.length != 1) {
			System.out.println("Wrong number of Arguments!\nExpected: UserRegisterApp <user_id [int]>\nExample: UserRegisterApp 101");
			System.exit(0);
		} else {
			try {				
				userID = Integer.parseInt(args[0]);
			} catch (Exception e) {
				System.out.println("Something is wrong with arguments!\nExpected: UserRegisterApp <user_id [int]>\nExample: UserRegisterApp 101");
				System.exit(0);
			}
			UserRegisterApp.register(userID);
			System.out.println("User " + userID + " registered!");
		}
	}	

	private static void register(int userID) {
		PKI.useRemoteMode();
		Decryptor user_decryptor = new Decryptor();
		Signer user_signer = new Signer();
		try {
			RegisterEnc.registerEncryptor(user_decryptor.getEncryptor(), userID, Params.PKI_ENC_DOMAIN);
			RegisterSig.registerVerifier(user_signer.getVerifier(), userID, Params.PKI_DSIG_DOMAIN);
		} catch (RegisterEnc.PKIError | RegisterSig.PKIError e) {
			outl("\tUser " + userID + " already registered!\n\tYou can directly execute the client.");
			System.exit(0);
		} catch (NetworkError e) {
			outl("Error while trying to register the encryption/verification keys!");
			System.exit(0);
		}
		byte[] id = MessageTools.intToByteArray(userID);
		SymEnc symenc = new SymEnc();
		byte[] decryptor = user_decryptor.toBytes();
		byte[] signer = user_signer.toBytes();

		byte[] decr_sig = MessageTools.concatenate(decryptor, signer);
		byte[] sym_decr_sig = MessageTools.concatenate(symenc.getKey(), decr_sig);
		byte[] serialized = MessageTools.concatenate(id, sym_decr_sig);
		try {
			storeAsFile(serialized, Params.PATH_USER + "user" + userID + ".info");
		} catch (IOException e) {
			outl("Error while trying to store the encryption/verification keys!");
			System.exit(0);
		}
	}

	public static void storeAsFile(byte[] data, String sFile) throws IOException {
		File f = new File(sFile);
		File fdir = new File(sFile.substring(0, sFile.lastIndexOf(File.separator)));
		if (f.exists()) f.delete();
		fdir.mkdirs();
		f.createNewFile();

		FileOutputStream file = new FileOutputStream(f);
		file.write(data);
		file.flush();
		file.close();
	}
	private static void out(String s){
		System.out.print(s);
	}
	private static void outl(String s){
		System.out.println(s);
	}
}
