package de.uni.trier.infsec.cloudStorage;

import java.util.*;

import de.uni.trier.infsec.utils.MessageTools;

/**
 * Separate class to store the message on the server side.
 * 
 * @author scapin
 *
 */
public class Storage {
	private Map<KeyStorage,byte[]> storage;
	
	/**
	 * For each label inserted maintains the higher counter
	 */
	private Map<String, Integer> maxCount;
	
	public Storage(){
		storage = new HashMap<KeyStorage,byte[]>();
		maxCount = new HashMap<String, Integer>();
	}
	
	/**
	 * Store a message and its signature under the index (label, counter)
	 */
	public void insert(byte[] label, int counter, byte[] msg, byte[] msgSign){
		storage.put(new KeyStorage(label.toString(), counter), MessageTools.concatenate(msg, msgSign));
		Integer lastCount;
		if ( (lastCount = maxCount.get(label.toString())) == null || counter>lastCount.intValue())
				maxCount.put(label.toString(), new Integer(counter));
	}

	/**
	 * Retrieve the message associated to the index (label, index)
	 */
	public byte[] getMessage(byte[] label, int counter){
		byte[] msg_sign = storage.get(new KeyStorage(label.toString(), counter)); 
		return MessageTools.first(msg_sign);
	}
	
	/**
	 * Retrieve the signature associated to the index (label, index)
	 */
	public byte[] getSignature(byte[] label, int counter){
		byte[] msg_sign = storage.get(new KeyStorage(label.toString(), counter)); 
		return MessageTools.second(msg_sign);
	}
	
	/**
	 * Return the higher counter associated with a particular label
	 */
	public int getLastCounter(byte[] label){
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


