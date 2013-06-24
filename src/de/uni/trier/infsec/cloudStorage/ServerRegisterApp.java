package de.uni.trier.infsec.cloudStorage;

import static de.uni.trier.infsec.utils.MessageTools.concatenate;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.pki.real.PKI;
import de.uni.trier.infsec.functionalities.pki.real.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.pki.real.PKISig;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;

public class ServerRegisterApp {

	
	public static void main(String[] args) {		
		System.setProperty("remotemode", Boolean.toString(true));
		ServerRegisterApp.registerAndSave();
	}

	private static void registerAndSave(){
		PKI.useRemoteMode();
		PKIEnc.Decryptor server_decr = new PKIEnc.Decryptor(Params.SERVER_ID);
		PKISig.Signer server_signer = new PKISig.Signer(Params.SERVER_ID);
		try {
			PKIEnc.register(server_decr.getEncryptor(), Params.PKI_ENC_DOMAIN);
			PKISig.register(server_signer.getVerifier(), Params.PKI_DSIG_DOMAIN);
		} catch (PKIError e) {
			e.printStackTrace();
		} catch (NetworkError e) {
			e.printStackTrace();
		}
		byte[] id = MessageTools.intToByteArray(Params.SERVER_ID);
        byte[] decryptor = PKIEnc.decryptorToBytes(server_decr);
        byte[] signer = PKISig.signerToBytes(server_signer);
        byte[] serialized = concatenate(id, concatenate(decryptor, signer));
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
