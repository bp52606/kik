package hr.fer.kik;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import com.google.crypto.tink.subtle.Hkdf;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
public class MessengerClient {

	private String username;
	private int maxSkip;

	private Map<String, byte[]> sending = new LinkedHashMap<>();
	private Map<String, byte[]> receiving = new LinkedHashMap<>();
	private Map<String, Integer> Ns = new LinkedHashMap<>();
	private Map<String, Integer> Nr = new LinkedHashMap<>();
	private Map<String, Integer> PN = new LinkedHashMap<>();

	private Map<String, Map<Integer,byte[]>> MKSKIPPED = new LinkedHashMap<>();

	public MessengerClient(String username, int maxSkip) {
		super();
		this.username = username;
		this.maxSkip = maxSkip;
	}

	public void addConnection(String peerUsername, byte[] chainKeySend, byte[] chainKeyReceive) {

		sending.put(peerUsername, chainKeySend);
		receiving.put(peerUsername, chainKeyReceive);
		Ns.put(peerUsername, 0);
		Nr.put(peerUsername, 0);
		PN.put(peerUsername, 0);
		MKSKIPPED.put(peerUsername, new LinkedHashMap<>());
	}

	public byte[] sendMessage(String peerUsername, String message) throws GeneralSecurityException {

		byte[] chainKeySend = sending.get(peerUsername);

		//hkdf
		byte [] hkdf = Hkdf.computeHkdf("HMACSHA256",chainKeySend,null,null,80);

		byte[] chainKey = Arrays.copyOfRange(hkdf, 0, 32);
		byte[] messageKey = Arrays.copyOfRange(hkdf, 32, 64);
		byte[] iv = Arrays.copyOfRange(hkdf, 64, 80);

		sending.put(peerUsername, chainKey);
		Ns.put(peerUsername, Ns.get(peerUsername)+1);

		//encrypting
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(messageKey, "AES");
		GCMParameterSpec paramSpec = new GCMParameterSpec(128, iv);

		cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);
		byte[] ciphertext = cipher.doFinal(message.getBytes());

		byte[] transfer = new byte[iv.length+ciphertext.length+Integer.BYTES];
		System.arraycopy(iv, 0, transfer, 0, iv.length);
		System.arraycopy(ByteBuffer.allocate(4).putInt(Ns.get(peerUsername)).array(), 0, transfer, iv.length, Integer.BYTES);
		System.arraycopy(ciphertext, 0, transfer, iv.length+Integer.BYTES, ciphertext.length);
		return transfer;
	}

	public String receiveMessage(String peerUsername, byte[] message) throws Exception {
		// dummy implementation

		byte[] iv = Arrays.copyOfRange(message, 0, 16);
		byte[] ns = Arrays.copyOfRange(message, 16,20);
		byte[] ciphertext  = Arrays.copyOfRange(message, 20, message.length);

		ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
		buffer.put(ns);
		buffer.rewind();
		int numberS = buffer.getInt();

		byte[] chainKeyReceive = receiving.get(peerUsername);

		//hkdf
		byte [] hkdf = Hkdf.computeHkdf("HMACSHA256",chainKeyReceive,null,null,80);

		byte[] chainKey = Arrays.copyOfRange(hkdf, 0, 32);
		byte[] messageKey = Arrays.copyOfRange(hkdf, 32, 64);


		//try skipped message keys

		if(MKSKIPPED.get(peerUsername).containsKey(numberS)) {

			messageKey = MKSKIPPED.get(peerUsername).get(numberS);

			MKSKIPPED.get(peerUsername).remove(numberS);

			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			SecretKeySpec keySpec = new SecretKeySpec(messageKey, "AES");
			GCMParameterSpec paramSpec = new GCMParameterSpec(128, iv);

			cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);
			byte[] cleanText = cipher.doFinal(ciphertext);

			return new String(cleanText, Charset.defaultCharset());
		}

		if(Nr.get(peerUsername)+maxSkip < numberS) {
			throw new Exception();
		}

		//skip message keys

		if(Nr.get(peerUsername)+1<numberS) {

			while (Nr.get(peerUsername) + 1 < numberS) {

				//hkdf
				hkdf = Hkdf.computeHkdf("HMACSHA256", receiving.get(peerUsername), null, null, 64);

				chainKey = Arrays.copyOfRange(hkdf, 0, 32);
				messageKey = Arrays.copyOfRange(hkdf, 32, 64);

				receiving.put(peerUsername, chainKey);
				MKSKIPPED.get(peerUsername).put(Nr.get(peerUsername) + 1, messageKey);
				Nr.put(peerUsername, Nr.get(peerUsername) + 1);
			}

			//hkdf
			hkdf = Hkdf.computeHkdf("HMACSHA256", receiving.get(peerUsername), null, null, 64);

			chainKey = Arrays.copyOfRange(hkdf, 0, 32);
			messageKey = Arrays.copyOfRange(hkdf, 32, 64);
		}


		receiving.put(peerUsername,chainKey);
		Nr.put(peerUsername, Nr.get(peerUsername)+1);

		//encrypting
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(messageKey, "AES");
		GCMParameterSpec paramSpec = new GCMParameterSpec(128, iv);

		cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);
		byte[] cleanText = cipher.doFinal(ciphertext);

		return new String(cleanText, Charset.defaultCharset());
	}
}
