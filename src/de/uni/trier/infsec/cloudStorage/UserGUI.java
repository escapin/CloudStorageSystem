package de.uni.trier.infsec.cloudStorage;


import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JScrollPane;
import javax.swing.UIManager;
import javax.swing.JTextField;
import javax.swing.JLabel;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JButton;
import java.awt.BorderLayout;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.awt.CardLayout;
import java.awt.Color;
import javax.swing.SwingConstants;
import java.awt.Font;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.pki.real.PKI;
import de.uni.trier.infsec.functionalities.pki.real.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.real.PKISig;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.symenc.real.SymEnc;
import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.lib.network.NetworkError;
import javax.swing.JTextArea;




public class UserGUI extends JFrame {
	
	private static final long serialVersionUID = 1L;
	private int userID;
	private JTextField textField;
	private JLabel lblUserNotRegister;
	private JTextField textField_1;
	private JPanel center;
	private final static String STORE = "Store";
    private final static String RETRIEVE = "Retrieve";
	
	
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
		lblUserNotRegister = new JLabel("");
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
					} catch (PKIError e){
						userRegistered=false;
						System.out.println("PKI Error occurred while connecting with the PKI server!");
						lblUserNotRegister.setText("PKI Error occurred while connecting with the PKI server!");
					} catch (NetworkError e){
						userRegistered=false;
						System.out.println("Network Error occurred while connecting with the PKI server!");
						lblUserNotRegister.setText("Network Error Error occurred while connecting with the PKI server!");
					}
					if(userRegistered){
						setTitle("User " + userID + " - Cloud Storage 2013");
						CardLayout cl = (CardLayout) getContentPane().getLayout();
						cl.show(getContentPane(), "2");
					}
				}
			}
		});
		
		
		// main windows panel
		JPanel main = new JPanel();
		
		// add the two layout to the main
		getContentPane().add(login, "1");
		getContentPane().add(main, "2");
		main.setLayout(new BorderLayout(0, 0));
		// set the default option
		cl.show(getContentPane(), "1");
		
		// North panel
		JPanel north = new JPanel();
		main.add(north, BorderLayout.NORTH);
		
		JComboBox comboBox = new JComboBox();
		comboBox.setModel(new DefaultComboBoxModel(new String[] {STORE, RETRIEVE}));
		
		JLabel lblUserId_1 = new JLabel("Label:");
		
		textField_1 = new JTextField();
		textField_1.setColumns(10);
		GroupLayout gl_north = new GroupLayout(north);
		gl_north.setHorizontalGroup(
			gl_north.createParallelGroup(Alignment.TRAILING)
				.addGroup(gl_north.createSequentialGroup()
					.addGap(23)
					.addComponent(comboBox, GroupLayout.PREFERRED_SIZE, 118, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED, 85, Short.MAX_VALUE)
					.addComponent(lblUserId_1)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(textField_1, GroupLayout.PREFERRED_SIZE, 128, GroupLayout.PREFERRED_SIZE)
					.addGap(34))
		);
		gl_north.setVerticalGroup(
			gl_north.createParallelGroup(Alignment.LEADING)
				.addGroup(Alignment.TRAILING, gl_north.createSequentialGroup()
					.addContainerGap(29, Short.MAX_VALUE)
					.addGroup(gl_north.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblUserId_1)
						.addComponent(textField_1, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(comboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addGap(20))
		);
		north.setLayout(gl_north);
		
		
		// Center panel
		center = new JPanel();
		main.add(center, BorderLayout.CENTER);
		CardLayout clCenter = new CardLayout(0, 0);
		center.setLayout(clCenter);
		
		JPanel storePanel = new JPanel();
		
		
		JLabel lblInsertTheMessage = new JLabel("Insert the message:");
		
		JTextArea textToStore = new JTextArea();
		JScrollPane ScrollTextToStore = new JScrollPane(textToStore);
		GroupLayout gl_storePanel = new GroupLayout(storePanel);
		gl_storePanel.setHorizontalGroup(
			gl_storePanel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_storePanel.createSequentialGroup()
					.addGroup(gl_storePanel.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_storePanel.createSequentialGroup()
							.addContainerGap()
							.addComponent(lblInsertTheMessage))
						.addGroup(gl_storePanel.createSequentialGroup()
							.addGap(27)
							.addComponent(ScrollTextToStore, GroupLayout.PREFERRED_SIZE, 389, GroupLayout.PREFERRED_SIZE)))
					.addContainerGap(34, Short.MAX_VALUE))
		);
		gl_storePanel.setVerticalGroup(
			gl_storePanel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_storePanel.createSequentialGroup()
					.addComponent(lblInsertTheMessage)
					.addGap(18)
					.addComponent(ScrollTextToStore, GroupLayout.PREFERRED_SIZE, 103, GroupLayout.PREFERRED_SIZE)
					.addContainerGap(54, Short.MAX_VALUE))
		);
		storePanel.setLayout(gl_storePanel);
		
		JPanel retrievePanel = new JPanel();
		
		
		JLabel lblNewLabel = new JLabel("Retreive the text");
		GroupLayout gl_retrievePanel = new GroupLayout(retrievePanel);
		gl_retrievePanel.setHorizontalGroup(
			gl_retrievePanel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_retrievePanel.createSequentialGroup()
					.addGap(27)
					.addComponent(lblNewLabel)
					.addContainerGap(353, Short.MAX_VALUE))
		);
		gl_retrievePanel.setVerticalGroup(
			gl_retrievePanel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_retrievePanel.createSequentialGroup()
					.addContainerGap()
					.addComponent(lblNewLabel)
					.addContainerGap(163, Short.MAX_VALUE))
		);
		retrievePanel.setLayout(gl_retrievePanel);
		
		center.add(storePanel, STORE);
		center.add(retrievePanel, RETRIEVE);
		comboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				 JComboBox jcb = (JComboBox) e.getSource();
				 CardLayout cl = (CardLayout)(center.getLayout());
				 cl.show(center, jcb.getSelectedItem().toString());
			}
		});
		
		// South panel
		JPanel south = new JPanel();
		main.add(south, BorderLayout.SOUTH);
		
		JButton btnLogOut = new JButton("Log Out");
		btnLogOut.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				destroyClient();
				setTitle("User - Cloud Storage 2013");
				CardLayout cl = (CardLayout) getContentPane().getLayout();
				cl.show(getContentPane(), "1");
			}
		});
		GroupLayout gl_south = new GroupLayout(south);
		gl_south.setHorizontalGroup(
			gl_south.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_south.createSequentialGroup()
					.addContainerGap()
					.addComponent(btnLogOut)
					.addContainerGap(348, Short.MAX_VALUE))
		);
		gl_south.setVerticalGroup(
			gl_south.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_south.createSequentialGroup()
					.addComponent(btnLogOut)
					.addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
		);
		south.setLayout(gl_south);
	}
	
	
	/*
	 * CORE CODE
	 */
	private PKIEnc.Decryptor user_decr;
	private PKISig.Signer user_sign;
	private SymEnc symenc;
	Client client;
	
	private void setupClient(int userID) throws IOException, PKIError, NetworkError{
		System.setProperty("remotemode", Boolean.toString(true));
		PKI.useRemoteMode();
		
		byte[] serialized = readFromFile(Params.PATH_USER + "user" + userID + ".info");
		
		byte[] sym_decr_sig = MessageTools.second(serialized);
		symenc = new SymEnc(MessageTools.first(sym_decr_sig));
		byte[] decr_sign = MessageTools.second(sym_decr_sig);
		user_decr = PKIEnc.decryptorFromBytes(MessageTools.first(decr_sign));
		user_sign = PKISig.signerFromBytes(MessageTools.second(decr_sign));
		
		NetworkInterface network = new NetworkReal();
		client = new Client(userID, symenc, user_decr, user_sign, network);
	}
	
	private void destroyClient(){
		user_decr=null;
		user_sign=null;
		symenc=null;
		client=null;
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

