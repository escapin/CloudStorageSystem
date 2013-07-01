package de.uni.trier.infsec.cloudStorage;


import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.pki.real.PKI;
import de.uni.trier.infsec.functionalities.pki.real.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.pki.real.PKISig;
import de.uni.trier.infsec.functionalities.symenc.real.SymEnc;
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
				e.printStackTrace();
				System.exit(0);
			}
			UserRegisterApp.register(userID);
		}
	}

	
	
	private static void register(int userID) {
		PKI.useRemoteMode();
		PKIEnc.Decryptor user_decryptor = new PKIEnc.Decryptor();
		PKISig.Signer user_signer = new PKISig.Signer();
		try {
			PKIEnc.registerEncryptor(user_decryptor.getEncryptor(), userID, Params.PKI_ENC_DOMAIN);
			PKISig.registerVerifier(user_signer.getVerifier(), userID, Params.PKI_DSIG_DOMAIN);
		} catch (PKIError e) {
			e.printStackTrace();
			System.exit(0);
		} catch (NetworkError e) {
			e.printStackTrace();
			System.exit(0);
		}
		byte[] id = MessageTools.intToByteArray(userID);
		SymEnc symenc = new SymEnc();
		byte[] decryptor = PKIEnc.decryptorToBytes(user_decryptor);
        byte[] signer = PKISig.signerToBytes(user_signer);
        
        byte[] decr_sig = MessageTools.concatenate(decryptor, signer);
        byte[] sym_decr_sig = MessageTools.concatenate(symenc.getKey(), decr_sig);
        byte[] serialized = MessageTools.concatenate(id, sym_decr_sig);
        try {
			storeAsFile(serialized, Params.PATH_USER + "user" + userID + ".info");
			System.out.println("User " + userID + " registered!");
		} catch (IOException e) {
			e.printStackTrace();
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
	
}
