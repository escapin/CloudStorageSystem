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
	private Map<KeyStorage, Integer> maxCount;
	
	public Storage(){
		storage = new HashMap<KeyStorage,byte[]>();
		maxCount = new HashMap<KeyStorage, Integer>();
	}
	
	/**
	 * Store a message and its signature under the index (userID, label, counter)
	 */
	public void insert(int userID, byte[] label, int counter, byte[] msg, byte[] msgSign){
		storage.put(new KeyStorage(userID, label.toString(), counter), MessageTools.concatenate(msg, msgSign));
		KeyStorage k = new KeyStorage(userID, label.toString(), -1);
		Integer lastCount;
		if ( (lastCount = maxCount.get(k)) == null || counter>lastCount.intValue())
				maxCount.put(k, new Integer(counter));
	}

	/**
	 * Retrieve the message associated to the index (userID, label, index) if it's in the storage,
	 * null otherwise
	 */
	public byte[] getMessage(int userID, byte[] label, int counter){
		byte[] msg_sign = storage.get(new KeyStorage(userID, label.toString(), counter));
		if(msg_sign!=null)
			return MessageTools.first(msg_sign);
		else
			return null;
	}
	
	/**
	 * Retrieve the signature associated to the index (userID, label, index) if if it's in the storage,
	 * null otherwise
	 */
	public byte[] getSignature(int userID, byte[] label, int counter){
		byte[] msg_sign = storage.get(new KeyStorage(userID, label.toString(), counter)); 
		if(msg_sign!=null)
			return MessageTools.second(msg_sign);
		else
			return null;
	}
	
	/**
	 * Return the higher counter associated with a particular (userID, label)
	 */
	public int getLastCounter(int userID, byte[] label){
		// What if maxCount.get(label.toString()) is null?
		return maxCount.get(new KeyStorage(userID, label.toString(), -1)).intValue();
	}

	/**
	 * The byte array "label" has to be converted in a String "toString()" method 
	 * so that we can use the method "equals" 
	 */
	private class KeyStorage{
		private int userID;
		private String label;
		private int count;
		
		public KeyStorage(int userID, String label, int count){
			this.userID = userID;
			this.label=label;
			this.count=count;
		}
		public int getUserID(){
			return userID;
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
				return this.userID==k.getUserID() && this.getLabel().equals(k.getLabel()) && this.getCount()==k.getCount();
			}
			return false;
		}
	}
}


