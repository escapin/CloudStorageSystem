package de.uni.trier.infsec.cloudStorage;

import java.io.File;
import java.sql.*;

public class StorageDB {
	
	
	//public static final String FILE_DATABASE = System.getProperty("java.io.tmpdir") + File.separator + "cloud_storage.db";
	// private String file_database = "storageDB" + File.separator + "cloud_storage.db";
	private String db_file;
	private String TABLE_STORAGE = "msg_storage";
	private Connection db;
	//private static final String DB_TABLE = ;
	
	public StorageDB(String db_file) throws ClassNotFoundException, SQLException{
		this.db_file=db_file;
		boolean dbExist = (new File(db_file)).exists();
		try {
			// checks whether the path where we want to store the db file
			// exists. 
			File fdir = new File(db_file.substring(0, db_file.lastIndexOf(File.separator)));
			// If not, we create it!
			fdir.mkdirs();
			// connect to a database. If database does not exist, 
			// then it will be created and finally a database object will be returned
			Class.forName("org.sqlite.JDBC");
			db = DriverManager.getConnection("jdbc:sqlite:" + db_file);
			
			// only if the database does not exist, create the table
			if(!dbExist){
				
				// Creates 'msg_storage' table 
				String sql = "CREATE TABLE " + TABLE_STORAGE +
					"(userID INTEGER NOT NULL, " +
					"label BLOB NOT NULL, " +
					"counter INTEGER NOT NULL, " +
					"message BLOB, " +
					"signature BLOB,  " +
					"PRIMARY KEY (userID, label, counter));";
				
				// Creates a Statement object for sending SQL statements to the database
				Statement stmt = db.createStatement();
				stmt.execute(sql);
				stmt.close();
			}
	    } finally{
	    	if(db!=null) // if an exception is thrown, it could be that the db has not been initialized
	    		db.close();
	    }
	}
	
	/**
	 * Store a message and its signature under the index (userID, label, counter)
	 * If the (userID, label, counter) has already been used, throw an SQL exception
	 * @throws SQLException 
	 */
	public void insert(int userID, byte[] label, int counter, byte[] msg, byte[] msgSign) throws SQLException{
		try {
			db = DriverManager.getConnection("jdbc:sqlite:" + db_file);
			
			String sql = "INSERT INTO " + TABLE_STORAGE + " (userID, label, counter, message, signature) " +
	                   " VALUES (?,?,?,?,?);";
			// Creates a Statement object for sending SQL statements to the database
			PreparedStatement pstmt = db.prepareStatement(sql);
			pstmt.setInt(1, userID);
			pstmt.setBytes(2, label);
			pstmt.setInt(3, counter);
			pstmt.setBytes(4, msg);
			pstmt.setBytes(5, msgSign);
			
			pstmt.executeUpdate();
			pstmt.close();
		} finally {
			db.close(); // unless an external problem occurs (e.g., the sqlite library is missing), db is never null at this point
		}
	}
		
	
	/**	
	 * Retrieve the message associated to the index (userID, label, index) if it is in the DB,
	 * null otherwise
	 * @throws SQLException 
	 */
	public byte[] getMessage(int userID, byte[] label, int counter) throws SQLException{
		byte[] msg=null;
		try{
			db = DriverManager.getConnection("jdbc:sqlite:" + db_file);
			/*
			 * SELECT signature FROM msg_storage WHERE userID='userID', label='label' AND counter='counter'	
			 */
			String sql = "SELECT * FROM " + TABLE_STORAGE + 
					" WHERE userID=? AND label=? AND counter=?;";
			// Creates a Statement object for sending SQL statements to the database
			PreparedStatement pstmt = db.prepareStatement(sql);
			pstmt.setInt(1, userID);
			pstmt.setBytes(2, label);
			pstmt.setInt(3, counter);
			
			ResultSet rs = pstmt.executeQuery();
			if(rs.next()) // there is one row
				msg = rs.getBytes("message");
			pstmt.close();
		} finally{
			db.close(); // unless an external problem occurs (e.g., the sqlite library is missing), db is never null at this point
		}
		return msg;
	}
	
	/**
	 * Retrieve the signature associated to the index (userID, label, index) if if it's in the storage,
	 * null otherwise
	 * @throws SQLException 
	 */
	public byte[] getSignature(int userID, byte[] label, int counter) throws SQLException{
		byte[] sign = null;
		try{
			db = DriverManager.getConnection("jdbc:sqlite:" + db_file);
			/*
			 * SELECT signature FROM msg_storage WHERE userID='userID', label='label' AND counter='counter'	
			 */
			String sql = "SELECT * FROM " + TABLE_STORAGE + 
					" WHERE userID=? AND label=? AND counter=?;";
			// Creates a Statement object for sending SQL statements to the database
			PreparedStatement pstmt = db.prepareStatement(sql);
			pstmt.setInt(1, userID);
			pstmt.setBytes(2, label);
			pstmt.setInt(3, counter);
			
			ResultSet rs = pstmt.executeQuery();
			if(rs.next()) // there is a rows
				sign = rs.getBytes("signature");
			pstmt.close();
		} finally{
			db.close(); // unless an external problem occurs (e.g., the sqlite library is missing), db is never null at this point
		}
	    return sign;
	}
	/**
	 * Return the higher counter associated with a particular (userID, label), if exist
	 * -1 otherwise
	 * @throws SQLException 
	 */
	public int getLastCounter(int userID, byte[] label) throws SQLException{
		int counter=-1;
		try{
			db = DriverManager.getConnection("jdbc:sqlite:" + db_file);
			/*String sql = "SELECT * FROM " + TABLE_STORAGE + 
					" WHERE userID=? AND label=?;";
			// Creates a Statement object for sending SQL statements to the database
			PreparedStatement pstmt = db.prepareStatement(sql);
			pstmt.setInt(1,userID);
			pstmt.setBytes(2, label);
			ResultSet rs = pstmt.executeQuery();
			if(!rs.next()) // no rows
				return -1;*/
			String sql = "SELECT MAX(counter) FROM " + TABLE_STORAGE + 
					" WHERE userID=? AND label=?;";
			PreparedStatement pstmt = db.prepareStatement(sql);
			pstmt.setInt(1,userID);
			pstmt.setBytes(2, label);
			ResultSet rs = pstmt.executeQuery();
			if (rs.next()){
				counter=rs.getInt(1); // if the first row is NULL, this method returns 0;
				if(rs.wasNull()) // no counter under this (userID, label) pair
					counter = -1;
			}
			pstmt.close();
		} finally {
			db.close(); // unless an external problem occurs (e.g., the sqlite library is missing), db is never null at this point
		}
		return counter;
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
