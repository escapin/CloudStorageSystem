package de.uni.trier.infsec.cloudStorage;


import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.UIManager;
import javax.swing.JTextField;
import javax.swing.JLabel;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JButton;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.CardLayout;
import java.awt.Color;
import javax.swing.SwingConstants;
import java.awt.Font;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.pki.real.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.real.PKISig;
import de.uni.trier.infsec.functionalities.symenc.real.SymEnc;
import de.uni.trier.infsec.utils.MessageTools;


public class UserGUI extends JFrame {
	
	private static final long serialVersionUID = 1L;
	private int userID;
	private JTextField textField;
	

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} catch (Throwable e) {
			e.printStackTrace();
		}
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					UserGUI frame = new UserGUI();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	JLabel lblUserNotRegister = new JLabel("");
	/**
	 * Create the frame.
	 */
	public UserGUI() {
		setTitle("User - Cloud Storage 2013");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 300);
		
		
		CardLayout cl = new CardLayout();
		getContentPane().setLayout(cl);
		
		
		
		// login Panel
		JPanel login = new JPanel();
		JButton btnLogIn = new JButton("Log In");
		
		JLabel lblUserId = new JLabel("User ID:");
		
		textField = new JTextField();
		textField.setColumns(10);
		lblUserNotRegister.setFont(new Font("Dialog", Font.BOLD, 14));
		lblUserNotRegister.setHorizontalAlignment(SwingConstants.LEFT);
		
		
		lblUserNotRegister.setForeground(Color.RED);
		
		GroupLayout gl_login = new GroupLayout(login);
		gl_login.setHorizontalGroup(
			gl_login.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_login.createSequentialGroup()
					.addGap(57)
					.addGroup(gl_login.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_login.createSequentialGroup()
							.addComponent(lblUserId, GroupLayout.PREFERRED_SIZE, 56, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(textField, GroupLayout.PREFERRED_SIZE, 114, GroupLayout.PREFERRED_SIZE))
						.addGroup(gl_login.createParallelGroup(Alignment.TRAILING)
							.addComponent(btnLogIn)
							.addComponent(lblUserNotRegister, GroupLayout.PREFERRED_SIZE, 368, GroupLayout.PREFERRED_SIZE)))
					.addContainerGap(25, Short.MAX_VALUE))
		);
		gl_login.setVerticalGroup(
			gl_login.createParallelGroup(Alignment.TRAILING)
				.addGroup(gl_login.createSequentialGroup()
					.addGap(58)
					.addGroup(gl_login.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblUserId, GroupLayout.DEFAULT_SIZE, 17, Short.MAX_VALUE)
						.addComponent(textField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addGap(37)
					.addComponent(lblUserNotRegister, GroupLayout.PREFERRED_SIZE, 88, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(btnLogIn)
					.addGap(61))
		);
		login.setLayout(gl_login);
		
		btnLogIn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				lblUserNotRegister.setText("");
				boolean isNumber=true;
				try{
					userID = Integer.parseInt(textField.getText());
				} catch (NumberFormatException e){
					isNumber=false;
					System.out.println("'" + textField.getText() + "' is not a proper userID!\nPlease insert the ID number of a previously registered user.");
					lblUserNotRegister.setText("<html>'" + textField.getText() + "' is not a proper userID!<br>Please insert the ID number of a registered user.</html>");
					
				}
				if(isNumber){
					boolean userRegistered=true;
					try {
						setupClient(userID);
					} catch (FileNotFoundException e){
						userRegistered=false;
						System.out.println("User " + userID + " not registered!\nType \'UserRegisterApp <user_id [int]>\' in a terminal to register him/her.");
						lblUserNotRegister.setText("<html>User " + userID + " not registered!<br>Type \'UserRegisterApp &lt;user_id [int]&gt;\' in a terminal to register him/her.</html>");
					} catch (IOException e){
						userRegistered=false;
						System.out.println("IOException occurred while reading the credentials of the user!");
						lblUserNotRegister.setText("IOException occurred while reading the credentials of the user!");
					}
					if(userRegistered){
						CardLayout cl = (CardLayout) getContentPane().getLayout();
						cl.show(getContentPane(), "2");
					}
				}
			}
		});
		
		
		// main windows panel
		JPanel main = new JPanel();
		JButton btnLogOut = new JButton("Log Out");
		
		btnLogOut.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				CardLayout cl = (CardLayout) getContentPane().getLayout();
				cl.show(getContentPane(), "1");
			}
		});
		GroupLayout gl_main = new GroupLayout(main);
		gl_main.setHorizontalGroup(
			gl_main.createParallelGroup(Alignment.TRAILING)
				.addGroup(gl_main.createSequentialGroup()
					.addContainerGap(326, Short.MAX_VALUE)
					.addComponent(btnLogOut)
					.addGap(34))
		);
		gl_main.setVerticalGroup(
			gl_main.createParallelGroup(Alignment.TRAILING)
				.addGroup(gl_main.createSequentialGroup()
					.addContainerGap(223, Short.MAX_VALUE)
					.addComponent(btnLogOut)
					.addGap(52))
		);
		main.setLayout(gl_main);
		
		// add the two layout to the main
		getContentPane().add(login, "1");
		getContentPane().add(main, "2");
		// set the default option
		cl.show(getContentPane(), "1");
	}
	
	
	/*
	 * CORE CODE
	 */
	private static PKIEnc.Decryptor user_decr;
	private static PKISig.Signer user_sign;
	private static SymEnc symenc;
	
	private static void setupClient(int userID) throws IOException{
		byte[] serialized=null;
		
		serialized = readFromFile(Params.PATH_USER + "user" + userID + ".info");
		
		byte[] sym_decr_sig = MessageTools.second(serialized);
		symenc = new SymEnc(MessageTools.first(sym_decr_sig));
		byte[] decr_sign = MessageTools.second(sym_decr_sig);
		user_decr = PKIEnc.decryptorFromBytes(MessageTools.first(decr_sign));
		user_sign = PKISig.signerFromBytes(MessageTools.second(decr_sign));
		
	}
	
	private static byte[] readFromFile(String path) throws IOException {
		FileInputStream f = new FileInputStream(path);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		while (f.available() > 0){			
			bos.write(f.read());
		}
		f.close();
		byte[] data = bos.toByteArray();
		return data;
	}
}

