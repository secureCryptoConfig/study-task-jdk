package main;

import java.util.HashMap;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Class which realizes the message creation. These messages are used for the interaction between
 * client and server.
 */
@JsonAutoDetect(fieldVisibility = Visibility.ANY)
public class Message {

	// Shows which party sends the message
	enum SenderType {
		Server, Client
	}

	// Shows different kinds of messages that can be used
	enum MessageType {
		BuyStock, SellStock, ServerResponse, GetOrders, ServerSendOrders
	}

	private SenderType senderType;

	public SenderType getSenderType() {
		return senderType;
	}

	public void setSenderType(SenderType senderType) {
		this.senderType = senderType;
	}

	public MessageType getMessageType() {
		return messageType;
	}

	public void setMessageType(MessageType messageType) {
		this.messageType = messageType;
	}

	public HashMap<String, String> getMessageParameters() {
		return messageParameters;
	}

	public void setMessageParameters(HashMap<String, String> messageParameters) {
		this.messageParameters = messageParameters;
	}

	private MessageType messageType;
	private HashMap<String, String> messageParameters = new HashMap<String, String>();

	public Message() {

	}

	private Message(SenderType senderType, MessageType messageType, HashMap<String, String> messageParameters) {
		this.senderType = senderType;
		this.messageType = messageType;
		this.messageParameters = messageParameters;
	}

	public static String createMessage(SenderType senderType, MessageType messageType,
			HashMap<String, String> messageParameters) throws JsonProcessingException {
		ObjectMapper mapper = new ObjectMapper();

		return mapper.writeValueAsString(new Message(senderType, messageType, messageParameters));
	}

	public static String createBuyStockMessage(String stockISIN, String amount) throws JsonProcessingException {
		HashMap<String, String> messageParameters = new HashMap<String, String>();

		messageParameters.put("stockISIN", stockISIN);
		messageParameters.put("amount", amount);

		return createMessage(SenderType.Client, MessageType.BuyStock, messageParameters);
	}

	public static String createServerSendOrdersMessage(String order) throws JsonProcessingException {
		HashMap<String, String> messageParameters = new HashMap<String, String>();
		messageParameters.put("order", order);
		return createMessage(SenderType.Server, MessageType.ServerSendOrders, messageParameters);
	}
	
	public static String createGetOrdersMessage() throws JsonProcessingException {
		HashMap<String, String> messageParameters = new HashMap<String, String>();

		return createMessage(SenderType.Client, MessageType.GetOrders, messageParameters);
	}
	
	public static String createSellStockMessage(String stockISIN, String amount) throws JsonProcessingException {
		HashMap<String, String> messageParameters = new HashMap<String, String>();

		messageParameters.put("stockISIN", stockISIN);
		messageParameters.put("amount", amount);

		return createMessage(SenderType.Client, MessageType.SellStock, messageParameters);
	}

	public static String createServerResponseMessage(boolean result) throws JsonProcessingException {
		HashMap<String, String> messageParameters = new HashMap<String, String>();

		messageParameters.put("result", String.valueOf(result));

		return createMessage(SenderType.Server, MessageType.ServerResponse, messageParameters);
	}

}
