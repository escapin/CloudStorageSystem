package de.uni.trier.infsec.cloudStorage;

import java.io.File;


import java.sql.*;

import de.uni.trier.infsec.functionalities.pki.real.PKIServerCore;
import de.uni.trier.infsec.utils.Utilities;

public class StorageDB {
	
	
	//public static final String FILE_DATABASE = System.getProperty("java.io.tmpdir") + File.separator + "cloud_storage.db";
	// private String file_database = "storageDB" + File.separator + "cloud_storage.db";
	private String file_database;
	private String TABLE_STORAGE = "msg_storage";
	private Connection db;
	//private static final String DB_TABLE = ;
	
	public StorageDB(String file_database){
		this.file_database=file_database;
		boolean dbExist = (new File(file_database)).exists();
		try {
			// connect to a database. If database does not exist, 
			// then it will be created and finally a database object will be returned
			Class.forName("org.sqlite.JDBC");
			db = DriverManager.getConnection("jdbc:sqlite:" + file_database);
			
			// only if the database didn't exist, create the table
			if(!dbExist){
				// Creates a Statement object for sending SQL statements to the database
				Statement stmt = db.createStatement();
				// Creates 'msg_storage' table 
				String sql = "CREATE TABLE " + TABLE_STORAGE +
					"(userID INTEGER NOT NULL, " +
					"label TEXT NOT NULL, " +
					"counter INTEGER NOT NULL, " +
					"message TEXT, " +
					"signature TEXT,  " +
					"PRIMARY KEY (userID, label, counter));";
				stmt.executeUpdate(sql);
				stmt.close();
			}
		    db.close();
	    } catch ( Exception e ) {
	      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
	      System.exit(0);
	    }
	    //System.out.println("Opened database successfully");
	}
	
	/**
	 * Store a message and its signature under the index (userID, label, counter)
	 * If the (userID, label, counter) has already been used, throw an SQL exception
	 */
	public void insert(int userID, byte[] label, int counter, byte[] msg, byte[] msgSign){
		try {
			db = DriverManager.getConnection("jdbc:sqlite:" + file_database);
			// Creates a Statement object for sending SQL statements to the database
			Statement stmt = db.createStatement();
			String insert = "INSERT INTO " + TABLE_STORAGE + " (userID, label, counter, message, signature) " +
	                   " VALUES (" +
	                   " '" + userID + "'," +
	                   " '" + Utilities.byteArrayToHexString(label) + "'," +
	                   " '" + counter + "'," +
	                   " '" + Utilities.byteArrayToHexString(msg) + "'," +
	                   " '" + Utilities.byteArrayToHexString(msgSign) + "');";
			stmt.executeUpdate(insert);
			stmt.close();
		    db.close();
	    } catch ( Exception e ) {
	      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
	      System.exit(0);
	    }
	}
		
	
	/**
	 * Retrieve the message associated to the index (userID, label, index) if it's in the storage,
	 * null otherwise
	 */
	public byte[] getMessage(int userID, byte[] label, int counter){
		try{
			db = DriverManager.getConnection("jdbc:sqlite:" + file_database);
			// Creates a Statement object for sending SQL statements to the database
			Statement stmt = db.createStatement();
			/*
			 * SELECT signature FROM msg_storage WHERE userID='userID', label='label' AND counter='counter'	
			 */
			String query = "SELECT * FROM " + TABLE_STORAGE + 
					" WHERE userID='" + userID + "' AND " +
							"label='" + Utilities.byteArrayToHexString(label) + "' AND " +
							"counter='" + counter + "';";
			ResultSet rs = stmt.executeQuery(query);
			if(!rs.next()) // no rows
				return null;
			String sign = rs.getString("message");
			stmt.close();
		    db.close();
		    return Utilities.hexStringToByteArray(sign);
			
		} catch ( Exception e ) {
		      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		}
		return null;	
	}
	/**
	 * Retrieve the signature associated to the index (userID, label, index) if if it's in the storage,
	 * null otherwise
	 */
	public byte[] getSignature(int userID, byte[] label, int counter){
		try{
			db = DriverManager.getConnection("jdbc:sqlite:" + file_database);
			// Creates a Statement object for sending SQL statements to the database
			Statement stmt = db.createStatement();
			/*
			 * SELECT signature FROM msg_storage WHERE userID='userID', label='label' AND counter='counter'	
			 */
			String query = "SELECT * FROM " + TABLE_STORAGE + 
					" WHERE userID='" + userID + "' AND " +
							"label='" + Utilities.byteArrayToHexString(label) + "' AND " +
							"counter='" + counter + "';";
			ResultSet rs = stmt.executeQuery(query);
			if(!rs.next()) // no rows
				return null;
			String sign = rs.getString("signature");
			stmt.close();
		    db.close();
		    return Utilities.hexStringToByteArray(sign);
			
		} catch ( Exception e ) {
		      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		}
		return null;	
	}
	/**
	 * Return the higher counter associated with a particular (userID, label), if exist
	 * -1 otherwise
	 */
	public int getLastCounter(int userID, byte[] label){
		try{
			db = DriverManager.getConnection("jdbc:sqlite:" + file_database);
			// Creates a Statement object for sending SQL statements to the database
			Statement stmt = db.createStatement();
			String query = "SELECT * FROM " + TABLE_STORAGE + 
					" WHERE userID='" + userID + "' AND " +
							"label='" + Utilities.byteArrayToHexString(label) + "' ;";
			ResultSet rs = stmt.executeQuery(query);
			if(!rs.next()) // no rows
				return -1;
			// there is at least a row with the (userID, label) pair
			query = "SELECT MAX(counter) FROM " + TABLE_STORAGE + 
					" WHERE userID='" + userID + "' AND " +
							"label='" + Utilities.byteArrayToHexString(label) + "' ;";
			rs = stmt.executeQuery(query);
			int counter = rs.getInt(1);
			stmt.close();
		    db.close();
		    return counter;
			
		} catch ( Exception e ) {
		      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		}
		return -1;	
	}		
	
}

/*
// checks whether the index has already been used
	String query = "SELECT * FROM " + TABLE_STORAGE + " WHERE " +
			" userID='" + userID + "', " +
			" label='" + Utilities.byteArrayToHexString(label) + "' AND " +
			" counter= '" + counter + "';";
	ResultSet rs = stmt.executeQuery(query);
	if(rs.getRow()!=0){
		// there is already a record with this index
		// it cannot be that there is more than one because (userID, label, counter) is a primary key
		 rs.updateString("message", Utilities.byteArrayToHexString(msg));
		 rs.updateString("signature", Utilities.byteArrayToHexString(msgSign));
		 rs.updateRow();
		 rs.close();
	}
	else{
		// we have to insert a new row
		rs.close();
		String insert = "INSERT INTO " + TABLE_STORAGE + " (userID, label, counter, message, signature) " +
                   " VALUES (" +
                   " '" + userID + "'," +
                   " '" + Utilities.byteArrayToHexString(label) + "'," +
                   " '" + counter + "'," +
                   " '" + Utilities.byteArrayToHexString(msg) + "'," +
                   " '" + Utilities.byteArrayToHexString(msgSign) + "');";
		stmt.executeUpdate(insert);
	}
*/
