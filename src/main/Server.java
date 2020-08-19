package main;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.collections4.map.HashedMap;
import org.apache.commons.collections4.queue.CircularFifoQueue;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import main.Message.MessageType;

/**
 * Class that simulates the behavior of a stock-server that processes client
 * requests.
 * 
 * Server retrieves buy/sell orders for stock from clients. Clients can be
 * registered from the server with their public key. This public key is needed
 * to be able to check the validity of all following signed messages that the
 * client sends. The validity of signed messages will be checked and valid
 * incoming orders will be stored encrypted such that no unauthorized party can
 * see unencrypted order.
 */
public class Server extends Thread {
	// Queue to store orders of a client with a specific ID
	HashedMap<Integer, CircularFifoQueue<byte[]>> queues = new HashedMap<Integer, CircularFifoQueue<byte[]>>();
	// maximum timeout of server used in "run" Method
	private static int sendFrequency = 5000;

	// Key for encrypt orders before storing. Gets initialized with the first run of
	// AppMain.java
	static byte[] masterKey;

	// all registered clients with their Keys
	List<byte[]> clients = Collections.synchronizedList(new ArrayList<byte[]>());

	/**
	 * Server retrieves key for later signature validation from client
	 * 
	 * @param key publicKey of client
	 * @return int : client ID
	 */
	public synchronized int registerClient(byte[] key) {

		if (clients.indexOf(key) == -1) {
			clients.add(key);
		}

		int id = clients.indexOf(key);

		// new Queue of the client to store his later incoming orders
		queues.put(id, new CircularFifoQueue<byte[]>(100));
		return id;
	}

	/**
	 * Method to check signature validation of a incoming message.
	 * 
	 * @param clientID
	 * @param order
	 * @param signature
	 * @return boolean resultValidation: shows if signature was valid
	 * @throws CoseException
	 */
	private boolean checkSignature(int clientID, byte[] order, byte[] signature) {
		// result of the validation. Default : false
		boolean resultValidation = false;

		byte[] publicKey = clients.get(clientID);
		PublicKey key = null;
		try {

			key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		// TODO Perform validation of the given "signature" with
		// the corresponding public key "key"  of the client. Store the result in
		// "resultValidation"
		
		// Catch possible occurring exceptions

		return resultValidation;

	}

	/**
	 * Method for symmetric encrypting incoming order of client
	 * 
	 * @param clientId
	 * @param order    order send by client
	 * @return boolean : shows if encryption could be done successfully
	 * @throws CoseException
	 */
	private boolean saveOrderEncrypted(byte[] order, int clientId) {

		byte[] encryptedOrder = null;
		SecretKey key = new SecretKeySpec(masterKey, "AES");

		// TODO Perform a symmetric encryption of the given "order" with the already
		// defined "key". Store the ciphertext in the already defined variable
		// "encryptedOrder".
		
		// Catch possible occurring exceptions

		
		
		
		p("encryptedOrder is (base64 encoded): "
				+ (encryptedOrder != null ? Base64.getEncoder().encodeToString(encryptedOrder) : "null"));
		// Add encrypted order in queue of client
		if (encryptedOrder == null) {
			return false;
		} else {
			return queues.get(clientId).add(encryptedOrder);
		}
	}

	/**
	 * Method for decrypting stored encrypted order if clients requests his already
	 * send orders
	 * 
	 * @param encryptedOrder encrypted order
	 * @return String : plaintext of decrypted order
	 * @throws CoseException
	 */
	private String decryptOrder(byte[] encryptedOrder) {
		SecretKey key = new SecretKeySpec(masterKey, 0, masterKey.length, "AES");
		String decryptedOrder = null;

		// TODO Perform a symmetric decryption of the given "encryptedOrder" with the
		// already defined "key". Store the plaintext in the already defined String
		// variable "decryptedOrder"
		
		// Catch possible occurring exceptions

		return decryptedOrder;
	}

	/**
	 * Generation of key for later encryption of orders
	 * 
	 * @return byte[] key bytes
	 */
	public static byte[] generateKey() {
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			SecretKey key = keyGen.generateKey();
			return key.getEncoded();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Message get processed depending on its MessageType and validation result.
	 * 
	 * @param type: BUY/SELL stock or GETORDERS
	 * @param clientId
	 * @param isCorrectMessage: shows if message signature was correct
	 * @param signedMessage: message sent from the client to server
	 * @return String
	 * @throws JsonProcessingException
	 */
	private String parseMessage(MessageType type, int clientId, boolean isCorrectMessage, SignedMessage signedMessage)
			throws JsonProcessingException {
		switch (type) {
		case GetOrders:
			CircularFifoQueue<byte[]> q = queues.get(clientId);
			String answer = "";

			if (q.size() == 0) {
				return "no orders in queue";
			}
			for (int i = 0; i < q.size(); i++) {
				byte[] encryptedOrder = q.get(i);
				String decrypted = "";
				decrypted = decryptOrder(encryptedOrder);
				answer = answer + Message.createServerSendOrdersMessage(decrypted) + "\n";
			}
			return answer;
		case BuyStock:
		case SellStock:
			boolean encryptionResult = saveOrderEncrypted(signedMessage.getContent().getBytes(), clientId);
			if (encryptionResult) {
				return Message.createServerResponseMessage(isCorrectMessage);
			} else {
				return "{\"Failure during encryption\"}";
			}
		default:
			return new String("{\"Failure\"}");
		}
	}

	/**
	 * Processes incoming orders. Values of messages are read out and validation
	 * process gets started. Server sends back a response to client showing if
	 * incoming order signature could be validated
	 * 
	 * @param message: incoming from interaction of client with server
	 * @return String
	 */
	public String acceptMessage(String message) {

		boolean isCorrectMessage = false;
		MessageType type = null;
		int clientId = 0;
		ObjectMapper mapper = new ObjectMapper();
		try {
			SignedMessage signedMessage = mapper.readValue(message, SignedMessage.class);
			clientId = signedMessage.getClientId();

			byte[] signature = signedMessage.getSignature();

			isCorrectMessage = checkSignature(clientId, signedMessage.getContent().getBytes(), signature);
			p("message signature is " + (isCorrectMessage ? "valid" : "not valid"));
			if (isCorrectMessage == true) {

				Message theMessage = mapper.readValue(signedMessage.getContent(), Message.class);
				type = theMessage.getMessageType();

				p(theMessage.getMessageType().toString());

				return parseMessage(type, clientId, isCorrectMessage, signedMessage);

			} else {
				return Message.createServerResponseMessage(isCorrectMessage);
			}
		} catch (JsonProcessingException e) {
			p("Exception " + e.getLocalizedMessage());
			return new String("{\"Failure\"}");
		}
	}

	/**
	 * Auxiliary method for showing some responses/requests in the communication
	 * between client and server
	 * 
	 * @param s
	 */
	private void p(String s) {
		System.out.println(Instant.now().toString() + " server: " + s);
	}

	@Override
	public void run() {
		
		p("Server started");
		
		try {
			Thread.sleep((long) (Math.random() * sendFrequency + 1));
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		
	}

}
