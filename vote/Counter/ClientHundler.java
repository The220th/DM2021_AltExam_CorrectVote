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
                	if(msg.getInt() == 17)
                		step17_decrypt_and_decrypt_and_publish(msg);
                }
                if(msg.getType() == Message.GET_VOTE_INFO)
                	tellVoteInfo();
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

    private void tellVoteInfo()
    {
    	Message msg = Message.makeMessage().setType(Message.VOTE_INFO);
    	msg.setString(CounterHundler.getVoteInfo());
    	this.send(msg);
    }

    private void step13_decrypt_and_publish(Message msg4step13)
    {
    	//13. {name_sigV, M_bl}_en = decrypt({name_sigV, M_bl}_en_enC, C_privKey)
    	byte[] name_sigV_and_M_bl_en = RSA4096.decrypt(msg4step13.getBytes(), CounterHundler.getPrivKey());
    	
    	//14. Публикует {name_sigV, M_bl}_en в специальном списке.
    	ArrayList<String> nameItem = new ArrayList<String>();
    	nameItem.add(ByteWorker.Bytes2String(name_sigV_and_M_bl_en));
    	CounterHundler.addNameItem(nameItem);
    	String[][] sArray = CounterHundler.getNamesTable();
    	Message msg = Message.makeMessage().setType(Message.ALGORITHM).setBytes(ObjectConverter.obj2bytes(sArray));
    	this.send(msg);
    }

	private void step17_decrypt_and_decrypt_and_publish(Message msg4step17)
	{
		//*17. key+номерстроки = decrypt(key_enC+номерстроки, C_privKey).
		byte[] key_and_name_i = RSA4096.decrypt(msg4step17.getBytes(), CounterHundler.getPrivKey());
		byte[][] buffBA = ByteWorker.Array2Arrays(key_and_name_i);
		byte[] aesKey = buffBA[0];
		int lineIndex = ByteWorker.Bytes2Int(buffBA[1]);

		//18. {name_sigV, M_bl} = decrypt({name_sigV, M_bl}_en, key).
		ArrayList<String> nameItem = CounterHundler.getNameItem(lineIndex);
		byte[] name_sigV_and_M_bl = ByteWorker.String2Bytes(nameItem.get(0));
		AES256 aes = new AES256();
		aes.setKey(aesKey);
		name_sigV_and_M_bl = aes.decrypt(name_sigV_and_M_bl);
		buffBA = ByteWorker.Array2Arrays(name_sigV_and_M_bl);
		byte[] name_sigV = buffBA[0];
		byte[] M_bl = buffBA[1];

		if(CounterHundler.checkNameItemEquals(ByteWorker.Bytes2String(name_sigV)))
		{
			//19. name = unsign(name_sigV, V_pubKey).
			byte[] name = RSA4096.unsign(name_sigV, CounterHundler.getValidatorPubKey());
			if( CounterHundler.getVoteMark().equals( CounterHundler.getVoteMark(new String(name)) ) )
			{
				//20. Подписывает M_bl_sigC = sign(M_bl, C_privKey).
				byte[] M_bl_sigC = RSA4096.blindSign(M_bl, CounterHundler.getPrivKey());

				//21. Публикует рядом с {name_sigV, M_bl}_en ещё и {M_bl_sigC, name_sigV, name}.
				if(nameItem.size() == 1)
				{
					CounterHundler.editNameItem(nameItem, ByteWorker.Bytes2String(M_bl_sigC));
					CounterHundler.editNameItem(nameItem, ByteWorker.Bytes2String(name_sigV));
					CounterHundler.editNameItem(nameItem, new String(name));
				}
				String[][] sArray = CounterHundler.getNamesTable();
	    		Message msg = Message.makeMessage().setType(Message.ALGORITHM).setBytes(ObjectConverter.obj2bytes(sArray));
	    		this.send(msg);
			}
			else
			{
				Message errMsg = Message.makeMessage().setType(Message.ALGORITHM_ERROR).setString("Sign is not correct");
				this.send(errMsg);
			}
		}
		else
		{
			Message errMsg = Message.makeMessage().setType(Message.ALGORITHM_ERROR).setString("This record is already exists");
			this.send(errMsg);
		}
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