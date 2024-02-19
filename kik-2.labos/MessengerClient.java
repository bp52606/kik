package hr.fer.kik;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.PublicKeyVerifyFactory;
import com.google.crypto.tink.subtle.Hkdf;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class MessengerClient {

	private String username;
	private KeysetHandle caPubKey;

	private KeyPair DHs;

	private PublicKey DHr;

	private Map<String, PublicKey> clientInformation = new LinkedHashMap<>();

	private Map<String, KeyPair> clientKeyPair = new LinkedHashMap<>();

	private Map<String, byte[]> CKs = new LinkedHashMap<>();

	private Map<String, byte[]> CKr = new LinkedHashMap<>();

	private Map<String, byte[]> rootKeys = new LinkedHashMap<>();


	public MessengerClient(String username, KeysetHandle caPubKey) {
		super();
		this.username = username;
		this.caPubKey = caPubKey;
		this.clientInformation = new LinkedHashMap<>();
	}

	public byte[] generateCertificate() throws NoSuchAlgorithmException, InvalidKeyException {
        // Generira par Diffie-Hellman ključeva i vraća certifikacijski objekt

        // Metoda generira inicijalni Diffie-Hellman par kljuceva;
        // serijalizirani javni kljuc se zajedno s imenom klijenta postavlja u
        // certifikacijski objekt kojeg metoda vraća. Certifikacijski objekt
        // moze biti proizvoljan. Za serijalizaciju kljuca mozete koristiti PEM
        // ili DER format.

        // Certifikacijski objekt koji metoda vrati bit će potpisan od strane CA
        // te će tako dobiveni certifikat biti proslijeđen drugim klijentima.

		// dummy implementation

		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DiffieHellman");

		keyGenerator.initialize(512);

		this.DHs = keyGenerator.genKeyPair();

		this.DHr = this.DHs.getPublic();

		byte[] transfer = new byte[this.username.getBytes().length+ this.DHr.getEncoded().length+Integer.BYTES];

		int length = this.DHr.getEncoded().length;

		System.arraycopy(ByteBuffer.allocate(4).putInt(length).array(), 0, transfer, 0, Integer.BYTES);
		System.arraycopy(this.DHr.getEncoded(), 0, transfer, Integer.BYTES, this.DHr.getEncoded().length);
		System.arraycopy(this.username.getBytes(), 0, transfer, this.DHr.getEncoded().length+Integer.BYTES, this.username.getBytes().length);

		return transfer;
	}

	public void receiveCertificate(byte[] cert, byte[] signature) throws GeneralSecurityException {
        // Verificira certifikat klijenta i sprema informacije o klijentu (ime i
        // javni ključ)

        // Argumenti:
        // cert      -- certifikacijski objekt
        // signature -- digitalni potpis od `cert`

        // Metoda prima certifikacijski objekt (koji sadrži inicijalni
        // Diffie-Hellman javni ključ i ime klijenta) i njegov potpis kojeg
        // verificira koristeći javni ključ od CA i, ako je verifikacija
        // uspješna, sprema informacije o klijentu (ime i javni ključ). Javni
        // ključ od CA je spremljen prilikom inicijalizacije objekta.

		// needs implementation

		PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(this.caPubKey);
		verifier.verify(signature, cert);

		byte[] length = Arrays.copyOfRange(cert, 0, Integer.BYTES);

		ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
		buffer.put(length);
		buffer.rewind();
		int size = buffer.getInt();

		byte[] dhr = Arrays.copyOfRange(cert, Integer.BYTES,Integer.BYTES+size);
		byte[] username = Arrays.copyOfRange(cert, Integer.BYTES+size, cert.length);

		String userName = new String(username);

		KeyFactory keyFactory = KeyFactory.getInstance("DH"); // Change to your algorithm if different

		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(dhr);

		PublicKey publicKey = keyFactory.generatePublic(keySpec);

		this.clientInformation.put(userName, publicKey);

		this.clientKeyPair.put(userName, new KeyPair(this.DHs.getPublic(), this.DHs.getPrivate()));

		KeyAgreement ka = KeyAgreement.getInstance("DH");
		ka.init(this.DHs.getPrivate());
		ka.doPhase(publicKey, true);

		byte[] sharedSecret = ka.generateSecret();

		this.rootKeys.put(userName,sharedSecret);

	}

	public byte[] sendMessage(String peerUsername, String message) throws GeneralSecurityException {
        // Slanje poruke klijentu

        // Argumenti:
        // message  -- poruka koju ćemo poslati
        // username -- klijent kojem šaljemo poruku `message`

        // Metoda šalje kriptiranu poruku sa zaglavljem klijentu s imenom
        // `username`.  Pretpostavite da već posjedujete certifikacijski objekt
        // od klijenta (dobiven pomoću `receive_certificate`) i da klijent
        // posjeduje vaš.  Ako već prije niste komunicirali, uspostavite sesiju
        // tako da generirate nužne `double ratchet` ključeve prema
        // specifikaciji.

        // Svaki put kada šaljete poruku napravite `ratchet` korak u `sending`
        // lanacu (i `root` lanacu ako je potrebno prema specifikaciji).  S
        // novim `sending` ključem kriptirajte poruku koristeći simetrični
        // kriptosustav AES-GCM tako da zaglavlje poruke bude autentificirano.
        // Ovo znači da u zaglavlju poruke trebate proslijediti odgovarajući
        // inicijalizacijski vektor.  Zaglavlje treba sadržavati podatke
        // potrebne klijentu da derivira novi ključ i dekriptira poruku.  Svaka
        // poruka mora biti kriptirana novim `sending` ključem.

        // Metoda treba vratiti kriptiranu poruku zajedno sa zaglavljem.

		if(!clientInformation.containsKey(peerUsername)) {
			throw new IllegalArgumentException();
		}

		if(!CKs.containsKey(peerUsername)){

			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DiffieHellman");
			keyGenerator.initialize(512);
			KeyPair keyPair = keyGenerator.genKeyPair();

			clientKeyPair.put(peerUsername, keyPair);

			KeyAgreement ka = KeyAgreement.getInstance("DH");
			ka.init(clientKeyPair.get(peerUsername).getPrivate());
			ka.doPhase(clientInformation.get(peerUsername), true);

			byte[] sharedSecret = ka.generateSecret();

			//hkdf
			byte [] hkdf = Hkdf.computeHkdf("HMACSHA256",sharedSecret,rootKeys.get(peerUsername),null,80);

			byte[] rootKey = Arrays.copyOfRange(hkdf, 0, 32);
			byte[] chainKey = Arrays.copyOfRange(hkdf, 32, 64);
			byte[] iv = Arrays.copyOfRange(hkdf, 64, 80);

			rootKeys.put(peerUsername, rootKey);
			CKs.put(peerUsername, chainKey);

		}


		byte [] hkdf = Hkdf.computeHkdf("HMACSHA256",CKs.get(peerUsername),null,null,80);

		byte[] messageKey = Arrays.copyOfRange(hkdf, 0, 32);
		byte[] chainKey = Arrays.copyOfRange(hkdf, 32, 64);
		byte[] iv = Arrays.copyOfRange(hkdf, 64, 80);

		CKs.put(peerUsername, chainKey);

		//encrypting
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(messageKey, "AES");
		GCMParameterSpec paramSpec = new GCMParameterSpec(128, iv);

		cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);
		byte[] ciphertext = cipher.doFinal(message.getBytes());

		PublicKey pk = this.clientKeyPair.get(peerUsername).getPublic();

		int length = pk.getEncoded().length;

		byte[] transfer = new byte[iv.length+ciphertext.length+length+4];
		System.arraycopy(iv, 0, transfer, 0, iv.length);
		System.arraycopy(ByteBuffer.allocate(4).putInt(length).array(), 0, transfer, iv.length, Integer.BYTES);
		System.arraycopy(pk.getEncoded(), 0, transfer, iv.length+Integer.BYTES,length);
		System.arraycopy(ciphertext, 0, transfer, iv.length+length+Integer.BYTES, ciphertext.length);


		// dummy implementation
		return transfer;
	}

	public String receiveMessage(String peerUsername, byte[] message) throws GeneralSecurityException {
        // Primanje poruke od korisnika

        // Argumenti:
        // message  -- poruka koju smo primili
        // username -- klijent koji je poslao poruku

        // Metoda prima kriptiranu poruku od klijenta s imenom `username`.
        // Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        // (dobiven pomoću `receive_certificate`) i da je klijent izračunao
        // inicijalni `root` ključ uz pomoć javnog Diffie-Hellman ključa iz
        // vašeg certifikata.  Ako već prije niste komunicirali, uspostavite
        // sesiju tako da generirate nužne `double ratchet` ključeve prema
        // specifikaciji.

        // Svaki put kada primite poruku napravite `ratchet` korak u `receiving`
        // lanacu (i `root` lanacu ako je potrebno prema specifikaciji)
        // koristeći informacije dostupne u zaglavlju i dekriptirajte poruku uz
        // pomoć novog `receiving` ključa. Ako detektirate da je integritet
        // poruke narušen, zaustavite izvršavanje programa i generirajte
        // iznimku.

        // Metoda treba vratiti dekriptiranu poruku.

		byte[] iv = Arrays.copyOfRange(message, 0, 16);
		byte[] ns = Arrays.copyOfRange(message, 16, 20);

		ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
		buffer.put(ns);
		buffer.rewind();
		int numberS = buffer.getInt();

		byte[] dhr = Arrays.copyOfRange(message, 20,20+numberS);

		byte[] ciphertext  = Arrays.copyOfRange(message, 20+numberS, message.length);


		KeyFactory keyFactory = KeyFactory.getInstance("DH"); // Change to your algorithm if different

		X509EncodedKeySpec keySpeci = new X509EncodedKeySpec(dhr);

		PublicKey publicKey = keyFactory.generatePublic(keySpeci);

		if(!this.CKr.containsKey(peerUsername) || !publicKey.equals(clientInformation.get(peerUsername))) {
			clientInformation.put(peerUsername,publicKey);

			KeyAgreement ka = KeyAgreement.getInstance("DH");
			ka.init(clientKeyPair.get(peerUsername).getPrivate());
			ka.doPhase(publicKey, true);

			byte[] sharedSecret = ka.generateSecret();

			byte [] hkdf = Hkdf.computeHkdf("HMACSHA256",sharedSecret,this.rootKeys.get(peerUsername),null,80);

			byte[] rootKey = Arrays.copyOfRange(hkdf, 0, 32);
			byte[] chainKey = Arrays.copyOfRange(hkdf, 32, 64);

			rootKeys.put(peerUsername, rootKey);
			CKr.put(peerUsername, chainKey);

			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DiffieHellman");
			keyGenerator.initialize(512);
			KeyPair keyPair = keyGenerator.genKeyPair();

			clientKeyPair.put(peerUsername, keyPair);

			KeyAgreement kag = KeyAgreement.getInstance("DH");
			kag.init(keyPair.getPrivate());
			kag.doPhase(clientInformation.get(peerUsername), true);

			sharedSecret = kag.generateSecret();

			//hkdf
			hkdf = Hkdf.computeHkdf("HMACSHA256",sharedSecret,this.rootKeys.get(peerUsername),null,80);

			rootKey = Arrays.copyOfRange(hkdf, 0, 32);
			chainKey = Arrays.copyOfRange(hkdf, 32, 64);

			rootKeys.put(peerUsername, rootKey);
			CKs.put(peerUsername, chainKey);

		}


		//hkdf
		byte [] hkdf = Hkdf.computeHkdf("HMACSHA256",CKr.get(peerUsername),null,null,80);

		byte[] messageKey = Arrays.copyOfRange(hkdf, 0, 32);
		byte[] chainKey = Arrays.copyOfRange(hkdf, 32, 64);

		CKr.put(peerUsername, chainKey);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(messageKey, "AES");
		GCMParameterSpec paramSpec = new GCMParameterSpec(128, iv);

		cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);
		byte[] cleanText = cipher.doFinal(ciphertext);


		return new String(cleanText);
	}
}
