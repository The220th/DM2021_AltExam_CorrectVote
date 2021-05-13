package vote.Counter;

import java.lang.*;
import java.util.*;
import java.io.*;

import vote.Common.*;
import vote.Counter.*;

import java.net.Socket;

import CipherLib.RSA4096;
import CipherLib.AES256;
import CipherLib.ByteWorker;



public class ClientHundler extends Thread
{
    private Socket socket;
    private ObjectInputStream objIn;
    private ObjectOutputStream objOut;
    private int hundler_id;
    private static int num = 0;

    public ClientHundler(Socket socket) throws IOException
    {
        this.socket = socket;
        objIn = new ObjectInputStream(socket.getInputStream());
		objOut = new ObjectOutputStream(socket.getOutputStream());
        hundler_id = ClientHundler.num++;
        start(); // == Thread.start()
    }

    @Override
    public void run()
    {
        Message msg;
        try
        {
            while(true)
            {
                msg = (Message)objIn.readObject();
                if(msg.getType() == Message.ALGORITHM)
                {
                	if(msg.getInt() == 13)
                		step13_decrypt_and_publish(msg);
                }
                if(msg.getType() == Message.OVER_AND_OUT)
                {
                	break;
                }
            }
        }
        catch (IOException e)
        {
        	System.err.println("Problem with: " + hundler_id);
        	e.printStackTrace();
        	CounterHundler.removeClientHundler(this);
        }
        catch (ClassNotFoundException ignored)
        {
        	ignored.printStackTrace();
        }
        finally
        {
        	closeConnection();
        }
    }

    private synchronized void send(Message msg)
    {
        try
        {
        	objOut.writeObject(msg);
            objOut.flush();
        }
        catch(IOException e)
        {
        	System.err.println("Problem with: " + hundler_id);
        	e.printStackTrace();
        	CounterHundler.removeClientHundler(this);
        }
    }

    private void step13_decrypt_and_publish(Message msg4step13)
    {
    	// {name_sigV, M_bl}_en = decrypt({name_sigV, M_bl}_en_enC, C_privKey)
    	byte[] name_sigV_and_M_bl_en = RSA4096.decrypt(msg4step13.getBytes(), CounterHundler.getPrivKey());
    	ArrayList<String> nameItem = new ArrayList<String>();
    	nameItem.add(ByteWorker.Bytes2String(name_sigV_and_M_bl_en));
    	CounterHundler.addNameItem(nameItem);
    	String[][] sArray = CounterHundler.getNamesTable();
    	Message msg = Message.makeMessage().setBytes(ObjectConverter.obj2bytes(sArray));
    	this.send(msg);
    	System.out.println(sArray[0][0]);
    }

    private void closeConnection()
	{
        CounterHundler.removeClientHundler(this);
		try
		{
			socket.shutdownInput();
			socket.shutdownOutput();
			if(objIn != null)
				objIn.close();
			if(objOut != null)
				objOut.close();
			socket.close();
	        System.out.println("Socket " + this.hundler_id + " was closed...");
    	}
        catch(IOException e)
        {
            e.printStackTrace();
        }
        catch(Exception e)
        {
        	e.printStackTrace();
        }
	} 
}