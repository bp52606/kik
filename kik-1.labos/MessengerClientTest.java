package hr.fer.kik;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.security.SecureRandom;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;

public class MessengerClientTest {

	private SecureRandom secureRandom;
	private byte[] key1;
	private byte[] key2;
	private byte[] key3;
	private byte[] key4;
	private byte[] key5;
	private byte[] key6;
	private MessengerClient alice;
	private MessengerClient bob;
	private MessengerClient eve;

	@Before
	public void setUp() throws Exception {
		secureRandom = SecureRandom.getInstance("Windows-PRNG");
		key1 = new byte[32];
		key2 = new byte[32];
		key3 = new byte[32];
		key4 = new byte[32];
		key5 = new byte[32];
		key6 = new byte[32];
		secureRandom.nextBytes(key1);
		secureRandom.nextBytes(key2);
		secureRandom.nextBytes(key3);
		secureRandom.nextBytes(key4);
		secureRandom.nextBytes(key5);
		secureRandom.nextBytes(key6);
		alice = new MessengerClient("Alice", 10);
		bob = new MessengerClient("Bob", 10);
		alice.addConnection("Bob", key1, key2);
		bob.addConnection("Alice", key2, key1);
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
		eve = new MessengerClient("Eve", 10);
		alice.addConnection("Eve", key3, key4);
		eve.addConnection("Alice", key4, key3);
		bob.addConnection("Eve", key5, key6);
		eve.addConnection("Bob", key6, key5);
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

	@Test
	public void testOutOfOrderMessage() throws Exception {
		String plaintext1 = "Hi Bob!";
		byte[] message1 = alice.sendMessage("Bob", plaintext1);
		String plaintext2 = "Bob?";
		byte[] message2 = alice.sendMessage("Bob", plaintext2);
		String plaintext3 = "BOB";
		byte[] message3 = alice.sendMessage("Bob", plaintext3);

		String result = bob.receiveMessage("Alice", message1);
		assertEquals(plaintext1, result);

		result = bob.receiveMessage("Alice", message3);
		assertEquals(plaintext3, result);

		result = bob.receiveMessage("Alice", message2);
		assertEquals(plaintext2, result);
	}

	@Test
	public void testMoreOutOfOrderMessage() throws Exception {
		MessengerClient colonel = new MessengerClient("Colonel", 10);
		MessengerClient snake = new MessengerClient("Snake", 10);

		colonel.addConnection("Snake", key1, key2);
		snake.addConnection("Colonel", key2, key1);

		String plaintext1 = "Snake?";
		byte[] message1 = colonel.sendMessage("Snake", plaintext1);

		String plaintext2 = "Snake!?";
		byte[] message2 = colonel.sendMessage("Snake", plaintext2);

		String plaintext3 = "SNAAAAAAAAAAAKE!";
		byte[] message3 = colonel.sendMessage("Snake", plaintext3);

		String result = snake.receiveMessage("Colonel", message3);
		assertEquals(plaintext3, result);

		result = snake.receiveMessage("Colonel", message2);
		assertEquals(plaintext2, result);

		result = snake.receiveMessage("Colonel", message1);
		assertEquals(plaintext1, result);
	}
}
