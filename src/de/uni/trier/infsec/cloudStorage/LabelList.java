package de.uni.trier.infsec.cloudStorage;

import java.util.Arrays;
/**
 * List of labels.
 * For each 'label' maintains an counter representing 
 * how many times the label has been used.
 * 
 * @author scapin
 *
 */
public class LabelList {
	
	/**
	 * A simple (key, counter) pair
	 * 
	 * @author scapin
	 *
	 */
	static class Pair {
		byte[] key;
		int counter;
		Pair next;
		public Pair(byte[] key, int counter, Pair next) {
			this.key = key;
			this.counter = counter;
			this.next = next;
		}
	}
	
	private Pair lastElement = null;
	
	public void put(byte[] key, int counter) {
		for(Pair tmp = lastElement; tmp != null; tmp=tmp.next)
            if( Arrays.equals(key, tmp.key) ){
                tmp.counter=counter;
                return;
            }
		lastElement = new Pair(key, counter, lastElement);
	}

    public int get(byte[] key) {
        for(Pair tmp = lastElement; tmp != null; tmp=tmp.next)
            if( Arrays.equals(key, tmp.key)  )
                return tmp.counter;	
        return -1; // if the label is not present, return a negative counter
    }
    
    public boolean containsKey(byte[] key) {
        for(Pair tmp = lastElement; tmp != null; tmp = tmp.next) 
        	if( Arrays.equals(key, tmp.key)  )
                return true;
        return false;
    }
    
}
