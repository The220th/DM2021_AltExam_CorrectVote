package vote.Common;

import java.lang.*;
import java.util.*;
import java.io.Serializable;
import CipherLib.ByteWorker;

public class Message implements Serializable
{
	public static final int OTHER = -1;
	public static final int VOTE_INFO = 3;
	public static final int GET_VOTE_INFO = 4;
	public static final int ALGORITHM_ERROR = 6;
	public static final int ALGORITHM = 13;
	public static final int OVER_AND_OUT = 15;
	public static final int GET_NAMES_TABLE = 23;
	public static final int GET_BULLETIN_TABLE = 24;
	public static final int SEND_NAMES_TABLE = 25;
	public static final int SEND_BULLETIN_TABLE = 26;

	private int type;

	private int intVal;

	private String msg;

	private byte[] byteArr;

	public Message()
	{
		this.type = Message.OTHER;
		this.intVal = -1;
		this.msg = "";
		this.byteArr = null;
	}

	public static Message makeMessage()
	{
		return new Message();
	}

	public int getType()
	{
		return this.type;
	}

	public int getInt()
	{
		return this.intVal;
	}

	public String getString()
	{
		return this.msg;
	}

	/**
	* По умолчанию возвращает НЕ копию
	*/
	public byte[] getBytes()
	{
		return this.byteArr;
	}

	public byte[] getBytes(boolean COPY)
	{
		if(COPY == false)
			return this.getBytes();
		else
			return ByteWorker.copyAs_byte(this.getBytes());
	}

	public Message setType(int type)
	{
		this.type = type;
		return this;
	}

	public Message setInt(int what)
	{
		this.intVal = what;
		return this;
	}

	public Message setString(String what)
	{
		this.msg = what;
		return this;
	}

	/**
	* По умолчанию НЕ копируется
	*/
	public Message setBytes(byte[] bytes)
	{
		this.byteArr = bytes;
		return this;
	}

	public Message setBytes(byte[] bytes, boolean COPY)
	{
		if(COPY == false)
			return this.setBytes(bytes);
		else
			return this.setBytes(ByteWorker.copyAs_byte(bytes));
	}

	public String toString()
	{
		return "Type: " + this.type + ", int: " + this.intVal + ", String: " + this.msg + ", bytes: " + (this.byteArr==null?null:ByteWorker.Bytes2String(this.byteArr)) + ". ";
	}
}