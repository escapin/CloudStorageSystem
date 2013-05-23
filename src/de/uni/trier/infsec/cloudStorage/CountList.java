package de.uni.trier.infsec.cloudStorage;

import java.util.Arrays;
/**
 * It behaves as an Hashmap (provides almost the same interface) without being it
 * Just to be easier to be verified!
 * 
 * @author scapin
 *
 */
public class CountList {
	
	/**
	 * A simple (key, count) pair
	 * 
	 * @author scapin
	 *
	 */
	static class Pair {
		byte[] key;
		Object count; // FIXME: why do we store object if we only want to store ints?
		Pair next;
		public Pair(byte[] key, Object count, Pair next) {
			this.key = key;
			this.count = count;
			this.next = next;
		}
	}
	
	private Pair lastElement = null;
	
	public void put(byte[] key, Object count) {
		for(Pair tmp = lastElement; tmp != null; tmp=tmp.next)
            if( Arrays.equals(key, tmp.key) ){
                tmp.count=count;
                return;
            }
		lastElement = new Pair(key, count, lastElement);
	}

    public Object get(byte[] key) {
        for(Pair tmp = lastElement; tmp != null; tmp=tmp.next)
            if( Arrays.equals(key, tmp.key)  )
                return tmp.count;	
        return null;
    }
    
    public boolean containsKey(byte[] key) {
        for(Pair tmp = lastElement; tmp != null; tmp = tmp.next) 
        	if( Arrays.equals(key, tmp.key)  )
                return true;
        return false;
    }
    
}
