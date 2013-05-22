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
	
	/**
	 * For each label inserted maintains the higher counter
	 */
	private Map<String, Integer> maxCount = new HashMap<String, Integer>();
	
	public void add(byte[] label, int count, byte[] msg){
		storage.put(new KeyStorage(label.toString(), count), msg);
		Integer lastCount;
		if ( (lastCount = maxCount.get(label.toString())) == null || count>lastCount.intValue())
				maxCount.put(label.toString(), new Integer(count));
	}

	public byte[] get(byte[] label, int count){
		return storage.get(new KeyStorage(label.toString(), count));
	}
	
	public int getLastCount(byte[] label){
		// What if maxCount.get(label.toString()) is null?
		return maxCount.get(label.toString()).intValue();
	}

	/**
	 * The byte array "label" has to be converted in a String "toString()" method 
	 * so that we can use the method "equals" 
	 */
	private class KeyStorage{
		private String label;
		private int count;
		
		public KeyStorage(String label, int count){
			this.label=label;
			this.count=count;
		}
		public String getLabel(){
			return label;
		}
		public int getCount(){
			return count;
		}
		
		public boolean equals(Object obj){
			if(obj instanceof KeyStorage){
				KeyStorage k = (KeyStorage) obj;
				return this.getLabel().equals(k.getLabel()) && this.getCount()==k.getCount();
			}
			return false;
		}
	}
}


