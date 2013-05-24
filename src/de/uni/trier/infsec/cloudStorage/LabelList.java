package de.uni.trier.infsec.cloudStorage;

import java.util.Arrays;
/**
 * List of labels.
 * For each 'label' maintains an counter representing 
 * how many times the label has been used.
 */
public class LabelList {
	
	static class Node {
		byte[] key;
		int counter;
		Node next;
		public Node(byte[] key, int counter, Node next) {
			this.key = key;
			this.counter = counter;
			this.next = next;
		}
	}
	
	private Node firstElement = null;
	
	public void put(byte[] key, int counter) {
		for(Node tmp = firstElement; tmp != null; tmp=tmp.next)
            if( Arrays.equals(key, tmp.key) ){
                tmp.counter=counter;
                return;
            }
		firstElement = new Node(key, counter, firstElement);
	}

    public int get(byte[] key) {
        for(Node tmp = firstElement; tmp != null; tmp=tmp.next)
            if( Arrays.equals(key, tmp.key)  )
                return tmp.counter;	
        return -1; // if the label is not present, return -1
    }
    
    public boolean containsKey(byte[] key) {
    	return get(key) >= 0;
    }
}
