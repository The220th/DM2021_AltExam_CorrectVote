package vote.Counter;

import java.lang.*;
import java.util.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.File;

import CipherLib.RSA4096;
import CipherLib.ByteWorker;

class CounterHundler
{
    public static final int PORT = 5051;
    private static ArrayList<ClientHundler> clientsList;

    /*
    1: 0 - {name_sigV, M_bl}_en
    2: 1 - M_bl_sigC
    2: 2 - name_sigV
    2: 3 - name
    */
    private static List<ArrayList<String>> names;

    private static Scanner inCon;

    private static final String keysPath = "counterKeys";
    private static final String validatorKeysPath = "validatorPubKey";

    private static final String voteMark = "HT3ABTS";
    private static String[] votingOptions;

    private static byte[] pubKey;
    private static byte[] privKey;
    private static byte[] validatorPubKey;

    private static Object syncNamesObject;

    static
    {
    	votingOptions = new String[3];
    	votingOptions[0] = "Pizza"; votingOptions[1] = "Pasta"; votingOptions[2] = "Math";
    	inCon = new Scanner(System.in);
    	syncNamesObject = new Object();
    	clientsList = new ArrayList<ClientHundler>();
    	names = new ArrayList<ArrayList<String>>();
    	CounterHundler.step1_initKeys(CounterHundler.keysPath);
    	CounterHundler.initValidatorPubKey(CounterHundler.validatorKeysPath);
    	System.out.println("Mark of this vote:\"" + voteMark + "\".");
    }

    public static void main(String[] args) throws IOException
    {
        ServerSocket server = new ServerSocket(PORT);
        ClientHundler buffCH;
        Socket socket;
        try
        {
        	System.out.println("Server is listenning...");
            while(true)
            {
                socket = server.accept();
                try
                {
                	System.out.println("New connection");
                	buffCH = new ClientHundler(socket);
                    clientsList.add(buffCH);
                }
                catch(IOException e)
                {
                	e.printStackTrace();
                    socket.close();
                }
            }
        }
        finally
        {
            server.close();
        }
    }

    private static void step1_initKeys(String filePathString)
    {
		File file = new File(filePathString);

		byte[] buffer = null;
		byte[][] buffBA;

		if(file.exists() && !file.isDirectory())
		{
			try(FileInputStream fin = new FileInputStream(filePathString))
	        {
				buffer = new byte[fin.available()];
	            fin.read(buffer, 0, buffer.length);   
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}
			buffBA = ByteWorker.Array2Arrays(buffer);
			pubKey = buffBA[0];
			privKey = buffBA[1];
		}
		else
		{
			RSA4096 rsa = new RSA4096();
			rsa.genKeys();
			pubKey = rsa.getPubKey();
			privKey = rsa.getPrivKey();

			buffBA = new byte[2][];
			buffBA[0] = pubKey;
			buffBA[1] = privKey;

	        try(FileOutputStream fos = new FileOutputStream(filePathString))
	        {
	            buffer = ByteWorker.Arrays2Array(buffBA);
	            fos.write(buffer, 0, buffer.length);
	        }
	        catch(IOException e)
	        {
	            e.printStackTrace();
	        }
		}
	    System.out.println("=====\nPubKey = " + ByteWorker.Bytes2String(pubKey) + "\n=====");
    }

    private static void initValidatorPubKey(String filePathString)
    {
		File file = new File(filePathString);

		byte[] buffer = null;
		byte[][] buffBA;

		if(file.exists() && !file.isDirectory())
		{
			try(FileInputStream fin = new FileInputStream(filePathString))
	        {
				buffer = new byte[fin.available()];
	            fin.read(buffer, 0, buffer.length);   
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}
			validatorPubKey = buffer;
		}
		else
		{
			System.out.println("Input validatorPubKey:");
			validatorPubKey = ByteWorker.String2Bytes(inCon.nextLine());

	        try(FileOutputStream fos = new FileOutputStream(filePathString))
	        {
	            buffer = validatorPubKey;
	            fos.write(buffer, 0, buffer.length);
	        }
	        catch(IOException e)
	        {
	            e.printStackTrace();
	        }
	     }
    }

    public synchronized static byte[] getPrivKey()
    {
    	return CounterHundler.privKey;
    }

    public synchronized static byte[] getPubKey()
    {
    	return CounterHundler.pubKey;
    }

    public synchronized static byte[] getValidatorPubKey()
    {
    	return CounterHundler.validatorPubKey;
    }

    public static void addNameItem(ArrayList<String> nameItem)
    {
    	synchronized(syncNamesObject)
    	{
	    	boolean UNIQ;
	    	UNIQ = true;
	    	for(ArrayList<String> item : names)
	    		if(item.get(0).equals(nameItem.get(0)))
	    		{
	    			UNIQ = false;
	    			break;
	    		}
	    	if(UNIQ)
	    		names.add(nameItem);
    	}
    }

    public static boolean checkNameItemEquals(String name_sigV_2Check)
    {
    	boolean UNIC;
    	UNIC = true;
    	synchronized(syncNamesObject)
    	{
    		for(ArrayList<String> item : names)
    			if(item.size() == 4)
    				if(item.get(2).equals(name_sigV_2Check))
    				{
    					UNIC = false;
    					break;
    				}
    		return UNIC;
    	}
    }

    public static void editNameItem(ArrayList<String> what, String whatAppend)
    {
    	synchronized(syncNamesObject)
    	{
    		what.add(whatAppend);
    	}
    }

    public static ArrayList<String> getNameItem(int index)
    {
    	return names.get(index);
    }

    public static String[][] getNamesTable()
    {
    	synchronized(syncNamesObject)
    	{
	    	String[][] res = new String[names.size()][];
	    	int i, j;
	    	i = 0;
	    	for(ArrayList<String> item : names)
	    	{
	    		res[i] = new String[item.size()];
	    		j = 0;
	    		for(String itemitem : item)
	    		{
	    			res[i][j++] = itemitem;
	    		}
	    		++i;
	    	}
	    	return res;
    	}
    }

    public static String getVoteInfo()
    {
    	String res = "";
    	res += "\n===============\n";
    	res += "Vote " + voteMark + "::: " + "Options: \n";
    	for(int i = 0; i < votingOptions.length; ++i)
    		res += "\t" + (i+1) + ") " + votingOptions[i] + ". \n";
    	res += "===============\n";
    	return res;
    }

    public static String getVoteMark()
    {
    	return CounterHundler.voteMark;
    }

    public static String getVoteMark(String from)
    {
    	int index = from.indexOf(":::");
    	if(index == -1)
    		return null;
    	else
    		return from.substring(0, index);
    }

    public synchronized static ClientHundler getClientHundler(int index)
    {
    	return clientsList.get(index);
    }

    public synchronized static void removeClientHundler(ClientHundler which)
    {
    	clientsList.remove(which);
    }
}