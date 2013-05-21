package de.uni.trier.infsec.cloudStorage;

import java.util.*;

/**
 * Separate class to store the message on the server side.
 * 
 * @author scapin
 *
 */
public class Storage {
	private Map<KeyStorage,byte[]> storage = new HashMap<KeyStorage,byte[]>();
	
	public void add(byte[] label, int count, byte[] msg){
		storage.put(new KeyStorage(label, count), msg);
	}

	public byte[] get(byte[] label, int count){
		return storage.get(new KeyStorage(label, count));
	}

	public void remove(byte[] label, int count){
		storage.remove(new KeyStorage(label, count));
	}

	
	private class KeyStorage{
		private byte[] label;
		private int count;
		
		public KeyStorage(byte[] label, int count){
			this.label=label;
			this.count=count;
		}
		public byte[] getLabel(){
			return label;
		}
		public int getCount(){
			return count;
		}
		
		public boolean equals(Object obj){
			if(obj instanceof KeyStorage){
				KeyStorage k = (KeyStorage) obj;
				return Arrays.equals(this.getLabel(), k.getLabel()) && this.getCount()==k.getCount();
			}
			return false;
		}
	}
}


