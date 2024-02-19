package hr.fer.kik;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.PublicKeySign;


import com.google.crypto.tink.signature.SignatureConfig;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;

public class MessengerClientTest {

	private KeysetHandle caPublicKeysetHandle;
	private MessengerClient alice;
	private MessengerClient bob;
	private MessengerClient eve;

	@Before
	public void setUp() throws Exception {

		Config.register(SignatureConfig.LATEST);

		KeysetHandle caPrivateKeysetHandle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
		caPublicKeysetHandle = caPrivateKeysetHandle.getPublicKeysetHandle();

		alice = new MessengerClient("Alice", caPublicKeysetHandle);
		bob = new MessengerClient("Bob", caPublicKeysetHandle);
		eve = new MessengerClient("Eve", caPublicKeysetHandle);

		byte[] aliceCert = alice.generateCertificate();
		byte[] bobCert = bob.generateCertificate();
		byte[] eveCert = eve.generateCertificate();

		PublicKeySign signer = caPrivateKeysetHandle.getPrimitive(PublicKeySign.class);
		byte[] aliceCertSignature = signer.sign(aliceCert);
		byte[] bobCertSignature = signer.sign(bobCert);
		byte[] eveCertSignature = signer.sign(eveCert);

		alice.receiveCertificate(bobCert, bobCertSignature);
		alice.receiveCertificate(eveCert, eveCertSignature);

		bob.receiveCertificate(aliceCert, aliceCertSignature);
		bob.receiveCertificate(eveCert, eveCertSignature);

		eve.receiveCertificate(aliceCert, aliceCertSignature);
		eve.receiveCertificate(bobCert, bobCertSignature);
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testSendMessageWithoutError() throws Exception {
		alice.sendMessage("Bob", "Hi Bob!");
	}

	@Test
	public void testEncryptedMessageCanBeDecrypted() throws Exception {
		String plaintext = "Hi Bob!";
		byte[] message = alice.sendMessage("Bob", plaintext);
		String result = bob.receiveMessage("Alice", message);
		assertEquals(plaintext, result);
	}

	@Test
	public void testConversationBetweenMultipleUsers() throws Exception {
		String plaintext = "Hi Alice!";
		byte[] message = bob.sendMessage("Alice", plaintext);
		String result = alice.receiveMessage("Bob", message);
		assertEquals(plaintext, result);

		plaintext = "Hello Bob";
		message = alice.sendMessage("Bob", plaintext);
		result = bob.receiveMessage("Alice", message);
		assertEquals(plaintext, result);

		plaintext = "What are you doing?";
		message = bob.sendMessage("Alice", plaintext);
		result = alice.receiveMessage("Bob", message);
		assertEquals(plaintext, result);

		plaintext = "I'm woking on my homework";
		message = alice.sendMessage("Bob", plaintext);
		result = bob.receiveMessage("Alice", message);
		assertEquals(plaintext, result);

		plaintext = "Alice is doing her homework. What are you doing Eve?";
		message = bob.sendMessage("Eve", plaintext);
		result = eve.receiveMessage("Bob", message);
		assertEquals(plaintext, result);

		plaintext = "Hi Bob! I'm studying for the exam";
		message = eve.sendMessage("Bob", plaintext);
		result = bob.receiveMessage("Eve", message);
		assertEquals(plaintext, result);

		plaintext = "How's the homework going Alice";
		message = eve.sendMessage("Alice", plaintext);
		result = alice.receiveMessage("Eve", message);
		assertEquals(plaintext, result);

		plaintext = "I just finished it";
		message = alice.sendMessage("Eve", plaintext);
		result = eve.receiveMessage("Alice", message);
		assertEquals(plaintext, result);
	}

	@Test
	public void testUserCanSendStreamOfMessagesWithoutResponse() throws Exception {
		String plaintext = "Hi Bob!";
		byte[] message = alice.sendMessage("Bob", plaintext);
		String result = bob.receiveMessage("Alice", message);
		assertEquals(plaintext, result);

		plaintext = "Hi Bob!";
		message = alice.sendMessage("Bob", plaintext);
		result = bob.receiveMessage("Alice", message);
		assertEquals(plaintext, result);

		plaintext = "Hi Bob!";
		message = alice.sendMessage("Bob", plaintext);
		result = bob.receiveMessage("Alice", message);
		assertEquals(plaintext, result);

		plaintext = "Hi Bob!";
		message = alice.sendMessage("Bob", plaintext);
		result = bob.receiveMessage("Alice", message);
		assertEquals(plaintext, result);
	}

	@Test
	public void testUserCanSendStreamOfMessagesWithInfrequentResponses() throws Exception {
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 4; j++) {
				String plaintext = Integer.toString(j) + " Hi Bob!";
				byte[] message = alice.sendMessage("Bob", plaintext);
				String result = bob.receiveMessage("Alice", message);
				assertEquals(plaintext, result);
			}
			String plaintext = Integer.toString(i) + " Hello Alice!";
			byte[] message = bob.sendMessage("Alice", plaintext);
			String result = alice.receiveMessage("Bob", message);
			assertEquals(plaintext, result);
		}
	}

	@Test
	public void testRejectMessageFromUnknownUser() throws Exception {
		String plaintext = "Hi Alice!";
		final byte[] message = bob.sendMessage("Alice", plaintext);
		assertThrows(Exception.class, new ThrowingRunnable() {
			public void run() throws Throwable {
				alice.receiveMessage("Unknown", message);
			}
		});
	}

	@Test
	public void testReplayAttacksAreDetected() throws Exception {
		String plaintext = "Hi Alice!";
		final byte[] message = bob.sendMessage("Alice", plaintext);
		String result = alice.receiveMessage("Bob", message);
		assertThrows(Exception.class, new ThrowingRunnable() {
			public void run() throws Throwable {
				alice.receiveMessage("Bob", message);
			}
		});
	}
}
