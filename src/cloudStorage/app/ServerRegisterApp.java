package cloudStorage.app;

import static utils.MessageTools.concatenate;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import cloudStorage.core.Params;
import funct.pki.PKI;
import funct.pkienc.*;
import funct.pkisig.*;
import lib.network.NetworkError;
import utils.MessageTools;

public class ServerRegisterApp {


	public static void main(String[] args) {		
		System.setProperty("remotemode", Boolean.toString(true));
		ServerRegisterApp.registerAndSave();
		System.out.println("Cloud Storage server registered!");
	}

	private static void registerAndSave(){
		PKI.useRemoteMode();
		Decryptor server_decr = new Decryptor();
		Signer server_signer = new Signer();
		try {
			RegisterEnc.registerEncryptor(server_decr.getEncryptor(), Params.SERVER_ID, Params.PKI_ENC_DOMAIN);
			RegisterSig.registerVerifier(server_signer.getVerifier(), Params.SERVER_ID, Params.PKI_DSIG_DOMAIN);
		} catch (RegisterEnc.PKIError | RegisterSig.PKIError e) {
			outl("\tCloud Server already registered!\n\tYou can directly execute it.");
			System.exit(0);
		} catch (NetworkError e) {
			outl("Error while trying to register the encryption/verification keys!");
			System.exit(0);
		}
		byte[] id = MessageTools.intToByteArray(Params.SERVER_ID);
		byte[] decryptor = server_decr.toBytes();
		byte[] signer = server_signer.toBytes();
		byte[] serialized = concatenate(id, concatenate(decryptor, signer));
		try {
			storeAsFile(serialized, Params.PATH_SERVER);
		} catch (IOException e) {
			outl("Error while trying to store the encryption/verification keys!");
			System.exit(0);
		}
	}

	public static void storeAsFile(byte[] data, String sFile) throws IOException {
		File f = new File(sFile);
		File fdir = new File(sFile.substring(0, sFile.lastIndexOf(File.separator)));
		if (f.exists()) 
			f.delete();
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
