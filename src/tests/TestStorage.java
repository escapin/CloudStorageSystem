package tests;

import junit.framework.TestCase;

import org.junit.Test;

import cloudStorage.core.StorageDB;

import java.io.File;
import java.sql.SQLException;
import java.util.Arrays;

// TODO: convert it into a test case

public class TestStorage extends TestCase{
	@Test
	public void test() throws Exception {
		// String fileDB = System.getProperty("java.io.tmpdir") + File.separator + "cloud_storage.db";
		String fileDB = System.getProperty("java.io.tmpdir") + File.separator + "cloud_storage.db";
		//if the database already exists we delete it
		File f = new File(fileDB);
		if(f.exists())
			f.delete();
		StorageDB storage = new StorageDB(fileDB);
		
		storage.insert(100, "label01".getBytes(), 1, "msgLabel01".getBytes(), "signLabel01".getBytes());
		storage.insert(100, "label01".getBytes(), 2, "msgLabel02".getBytes(), "signLabel02".getBytes());
		storage.insert(100, "label01".getBytes(), 3, "msgLabel03".getBytes(), "signLabel03".getBytes());
		storage.insert(100, "label02".getBytes(), 1, "msgLabel03".getBytes(), "signLabel03".getBytes());
		
		byte[] msg=storage.getMessage(100, "label01".getBytes(), 1);
 		byte[] sign=storage.getSignature(100, "label01".getBytes(), 1);
 		// the message and the signature retrieved must be equals to those ones stored with the first counter (i.e., 1)
 		assertTrue(Arrays.equals(msg, "msgLabel01".getBytes()) && Arrays.equals(sign, "signLabel01".getBytes()));
		// the last label has to be 3
 		assertTrue(storage.getLastCounter(100, "label01".getBytes())==3);
		
		
		storage.insert(100, "label01".getBytes(), 6, "msgLabel05".getBytes(), "signLabel05".getBytes());
		// updated the entry with new msg/sign, so get methods have to return the last insertion 
 		msg=storage.getMessage(100, "label01".getBytes(), 6);
 		sign=storage.getSignature(100, "label01".getBytes(), 6);
		assertTrue(Arrays.equals(msg, "msgLabel05".getBytes()) && Arrays.equals(sign, "signLabel05".getBytes()));
		// getLastCounter for an user not in the db has to return -1
 		assertTrue(storage.getLastCounter(10, "label01".getBytes())==-1);
		// getLastCounter for a label used only once hat to return 2
		assertTrue(storage.getLastCounter(100, "label02".getBytes())==1);
	}
}
