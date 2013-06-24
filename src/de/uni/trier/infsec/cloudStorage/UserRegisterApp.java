package de.uni.trier.infsec.cloudStorage;


import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.pki.real.PKI;
import de.uni.trier.infsec.functionalities.pki.real.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.pki.real.PKISig;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;

public class UserRegisterApp {

		
	public static void main(String[] args) {
		System.setProperty("remotemode", Boolean.toString(true));
		if (args.length < 1) {
			System.out.println("Wrong number of Arguments!\nExpected: UserRegisterApp <user_id [int]>\nExample: UserRegisterApp 101");
		} else {
			try {				
				int clientID = Integer.parseInt(args[0]);
				UserRegisterApp.register(clientID);
			} catch (Exception e) {
				System.out.println("Something is wrong with arguments.!\nExpected: VoterStandalone <voter_id [int]>\nExample: VoterStandalone 42");
				e.printStackTrace();
			}
		}
	}

	
	
	private static void register(int userID) {
		PKI.useRemoteMode();
		PKIEnc.Decryptor user_decryptor = new PKIEnc.Decryptor(userID);
		PKISig.Signer user_signer = new PKISig.Signer(userID);
		try {
			PKIEnc.register(user_decryptor.getEncryptor(), Params.PKI_ENC_DOMAIN);
			PKISig.register(user_signer.getVerifier(), Params.PKI_DSIG_DOMAIN);

		} catch (PKIError e) {
			e.printStackTrace();
		} catch (NetworkError e) {
			e.printStackTrace();
		}
		byte[] id = MessageTools.intToByteArray(userID);
        byte[] decryptor = PKIEnc.decryptorToBytes(user_decryptor);
        byte[] signer = PKISig.signerToBytes(user_signer);
        byte[] serialized = MessageTools.concatenate(id, MessageTools.concatenate(decryptor, signer));
        try {
			storeAsFile(serialized, Params.PATH_SERVER);
		} catch (IOException e) {
			e.printStackTrace();
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
