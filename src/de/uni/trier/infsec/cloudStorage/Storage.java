package de.uni.trier.infsec.cloudStorage;

import java.util.*;

/**
 * Separate class to store the message on the server side.
 * 
 * @author scapin
 *
 */
public class Storage {
	Map<KeyStorage,byte[]> storage = new HashMap<KeyStorage,byte[]>();
	
	public void add(byte[] label, int index, byte[] msg){
		storage.put(new KeyStorage(label, index), msg);
	}
	public byte[] get(byte[] label, int index){
		return storage.get(new KeyStorage(label, index));
	}
	public void remove(byte[] label, int index){
		storage.remove(new KeyStorage(label, index));
	}
	
	private class KeyStorage{
		private byte[] label;
		private int index;
		
		public KeyStorage(byte[] label, int index){
			this.label=label;
			this.index=index;
		}
		public byte[] getLabel(){
			return label;
		}
		public int getIndex(){
			return index;
		}
		
		public boolean equals(Object obj){
			if(obj instanceof KeyStorage){
				KeyStorage k = (KeyStorage) obj;
				return this.getLabel().equals(k.getLabel()) && this.getIndex()==k.getIndex();
			}
			return false;
		}
	}
}


