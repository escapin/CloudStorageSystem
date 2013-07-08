package de.uni.trier.infsec.functionalities.pki.idealcor;

import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.environment.crypto.CryptoLib;
import de.uni.trier.infsec.environment.crypto.KeyPair;
import de.uni.trier.infsec.environment.network.NetworkError;

/**
 * Ideal functionality for public-key encryption with PKI (Public Key Infrastructure).
 * 
 * The intended usage is as follows.
 * 
 * An honest party A creates her decryptor, encryptor and registers in the following way:
 *
 *		PKIEnc.Decryptor dec_a = new PKIEnc.Decryptor(ID_A);
 *		PKIEnc.Encryptor enc_a = dec_a.getEncryptor(); // enc_a is an uncorrupted encryptor 
 *		try {
 *			PKIEnc.register(enc_a, PKI_DOMAIN);
 *		}
 *		catch (PKIError e) {}     // registration failed: the identifier has been already claimed.
 *		catch (NetworkError e) {} // or we have not got any answer
 *
 * A decryptor can be used to decrypt messages (encrypted for A).
 * 
 * For a corrupted party B, we do this:
 * 
 *		PKIEnc.Encryptor enc_b = new PKIEnc.Encryptor(ID_A, pubk);
 *		// register encryptor as above
 *
 * To encrypt something for A, one does the following:
 * 
 *		try {
 *			PKIEnc.Encryptor encryptor_of_a = PKIEnc.getEncryptor(ID_A, PKI_DOMAIN);
 *			encryptor_of_a.encrypt(message1);
 *		}
 *		catch(PKIError e) {} // if ID_A has not been successfully registered, we land here
 *		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI
 *
 * The fact (assumption) that the encryptor of A is uncorrupted can be made explicit in 
 * the code by casting to UncorruptedEncryptor (only possible for the ideal functionality):
 * 
 *		PKIEnc.UncorruptedEncryptor uncorrupted_encryptor_of_a = (PKIEnc.UncorruptedEncryptor) encryptor_of_a;
 *
 * Note that an exception is thrown if this assumption is false.
 */
public class PKIEnc {

	/// The public interface ///

	/** Encryptor encapsulating possibly corrupted public key.
	 */
	static public class Encryptor {
		protected byte[] publicKey;

		public Encryptor(byte[] publicKey) {
			this.publicKey = publicKey;
		}

		public byte[] encrypt(byte[] message) {
			return MessageTools.copyOf(CryptoLib.pke_encrypt(MessageTools.copyOf(message), MessageTools.copyOf(publicKey)));
		}

		public byte[] getPublicKey() {
			return MessageTools.copyOf(publicKey);
		}

		protected Encryptor copy() {
			return new Encryptor(publicKey);
		}
	}

	/**
	 * Uncorrupted encryptor.
	 * 
	 * The only way to obtain such an encryptor is through a decryptor.
	 * 
	 * This class is not in the public interface of the corresponding real functionality.
	 */
	static public final class UncorruptedEncryptor extends Encryptor {
		private EncryptionLog log;

		private UncorruptedEncryptor(byte[] publicKey, EncryptionLog log) {
			super(publicKey);
			this.log = log;
		}

		public byte[] encrypt(byte[] message) {
			byte[] randomCipher = null;
			// keep asking the environment for the ciphertext, until a fresh one is given:
			while( randomCipher==null || log.containsCiphertext(randomCipher) ) {
				randomCipher = MessageTools.copyOf(CryptoLib.pke_encrypt(MessageTools.getZeroMessage(message.length), MessageTools.copyOf(publicKey)));
			}
			log.add(MessageTools.copyOf(message), randomCipher);
			return MessageTools.copyOf(randomCipher);
		}

		protected Encryptor copy() {
			return new UncorruptedEncryptor(publicKey, log);
		}
	}

	/** An object encapsulating the private and public keys of some party. */
	static public class Decryptor {
		private byte[] publicKey;
		private byte[] privateKey;
		private EncryptionLog log;

		public Decryptor() {
			KeyPair keypair = CryptoLib.pke_generateKeyPair();
			this.privateKey = MessageTools.copyOf(keypair.privateKey);
			this.publicKey = MessageTools.copyOf(keypair.publicKey);
			this.log = new EncryptionLog();
		}

		/** "Decrypts" a message by, first trying to find in in the log (and returning
		 *   the related plaintext) and, only if this fails, by using real decryption. */
		public byte[] decrypt(byte[] message) {
			byte[] messageCopy = MessageTools.copyOf(message);
			if (!log.containsCiphertext(messageCopy)) {
				return MessageTools.copyOf( CryptoLib.pke_decrypt(MessageTools.copyOf(privateKey), messageCopy) );
			} else {
				return MessageTools.copyOf( log.lookup(messageCopy) );
			}
		}

		/** Returns a new uncorrupted encryptor object sharing the same public key, ID, and log. */
		public Encryptor getEncryptor() {
			return new UncorruptedEncryptor(publicKey, log);
		}
	}

	public static void registerEncryptor(Encryptor encryptor, int id, byte[] pki_domain) throws PKIError, NetworkError {
		if( Environment.untrustedInput() == 0 ) throw new NetworkError();
		if( registeredAgents.fetch(id, pki_domain) != null ) // encryptor.id is registered?
			throw new PKIError();
		registeredAgents.add(id, pki_domain, encryptor);
	}

	public static Encryptor getEncryptor(int id, byte[] pki_domain) throws PKIError, NetworkError {
		if( Environment.untrustedInput() == 0 ) throw new NetworkError();
		PKIEnc.Encryptor enc = registeredAgents.fetch(id, pki_domain);
		if (enc == null)
			throw new PKIError();
		return enc.copy();
	}

	/// IMPLEMENTATION ///

	private static class RegisteredAgents {
		private static class EncryptorList {
			final int id;
			byte[] domain;
			PKIEnc.Encryptor encryptor;
			EncryptorList next;
			EncryptorList(int id, byte[] domain, PKIEnc.Encryptor encryptor, EncryptorList next) {
				this.id = id;
				this.domain = domain;
				this.encryptor= encryptor;
				this.next = next;
			}
		}

		private EncryptorList first = null;

		public void add(int id, byte[] domain, PKIEnc.Encryptor encr) {
			first = new EncryptorList(id, domain, encr, first);
		}

		PKIEnc.Encryptor fetch(int ID, byte[] domain) {
			for( EncryptorList node = first;  node != null;  node = node.next ) {
				if( ID == node.id && MessageTools.equal(domain, node.domain) )
					return node.encryptor;
			}
			return null;
		}
	}

	private static RegisteredAgents registeredAgents = new RegisteredAgents();

	private static class EncryptionLog {

		private static class MessagePairList {
			byte[] ciphertext;
			byte[] plaintext;
			MessagePairList next;
			public MessagePairList(byte[] ciphertext, byte[] plaintext, MessagePairList next) {
				this.ciphertext = ciphertext;
				this.plaintext = plaintext;
				this.next = next;
			}
		}

		private MessagePairList first = null;

		public void add(byte[] plaintext, byte[] ciphertext) {
			first = new MessagePairList(ciphertext, plaintext, first);
		}

		byte[] lookup(byte[] ciphertext) {
			for( MessagePairList node = first;  node != null;  node = node.next ) {
				if( MessageTools.equal(node.ciphertext, ciphertext) )
					return node.plaintext;
			}
			return null;
		}

		boolean containsCiphertext(byte[] ciphertext) {
			return lookup(ciphertext) != null;
		}
	}
}
