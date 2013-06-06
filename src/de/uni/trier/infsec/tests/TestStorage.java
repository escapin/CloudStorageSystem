package de.uni.trier.infsec.tests;

import java.io.File;
import java.util.Arrays;

import de.uni.trier.infsec.cloudStorage.StorageDB;

// TODO: convert it into a test case

public class TestStorage {
	public static void main(String[] args){
		// String fileDB = System.getProperty("java.io.tmpdir") + File.separator + "cloud_storage.db";
		String fileDB = "storageDB" + File.separator + "cloud_storage.db";
		StorageDB storage = new StorageDB(fileDB);
		
		storage.insert(100, "label01".getBytes(), 1, "msgLabel01".getBytes(), "signLabel01".getBytes());
		storage.insert(100, "label01".getBytes(), 2, "msgLabel02".getBytes(), "signLabel02".getBytes());
		storage.insert(100, "label01".getBytes(), 3, "msgLabel03".getBytes(), "signLabel03".getBytes());
		storage.insert(100, "label02".getBytes(), 1, "msgLabel03".getBytes(), "signLabel03".getBytes());
		
		byte[] msg=storage.getMessage(100, "label01".getBytes(), 1);
 		byte[] sign=storage.getSignature(100, "label01".getBytes(), 1);
		if(Arrays.equals(msg, "msgLabel01".getBytes()) && Arrays.equals(sign, "signLabel01".getBytes()))
			System.out.println("OK");
		System.out.println(storage.getLastCounter(100, "label01".getBytes()));
		
		
		storage.insert(100, "label01".getBytes(), 6, "msgLabel05".getBytes(), "signLabel05".getBytes());
		msg=storage.getMessage(100, "label01".getBytes(), 6);
 		sign=storage.getSignature(100, "label01".getBytes(), 6);
		if(Arrays.equals(msg, "msgLabel05".getBytes()) && Arrays.equals(sign, "signLabel05".getBytes()))
			System.out.println("OK");
		System.out.println(storage.getLastCounter(10, "label01".getBytes()));
		
		System.out.println(storage.getLastCounter(100, "label02".getBytes()));
	}
}
