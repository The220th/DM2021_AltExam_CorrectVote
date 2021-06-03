package vote.Counter;

import java.lang.*;
import java.util.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.File;

import CipherLib.RSA4096;
import CipherLib.ByteWorker;
import CipherLib.Tools;

public class CounterHundler
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
    /*
    1: 0 - M
    1: 1 - пустое место, если метки совпали
    1: 2 - M_enCheck
    1: 3 - B_en2
    2: 4 - B
    */
    private static List<ArrayList<String>> bulletins;

    private static Scanner inCon;

    private static final String keysPath = "counterKeys";
    private static final String validatorKeysPath = "validatorPubKey";
    private static final String namesAndBulletinTablesPath = "namesAndBulletinTables";
    //Comment this String sitePath and uncomment String sitePath = "" to remove site
    //private static final String sitePath = "../testSite/content/test/test.md";
    private static String sitePath = "";

    private static String voteMark;
    private static String[] votingOptions;
	private static String voteHEAD;

    private static byte[] pubKey;
    private static byte[] privKey;
    private static byte[] validatorPubKey;

    private static Object syncNamesObject;
    private static Object syncBulletinsObject;

    static
    {
    	//votingOptions = new String[3];
    	//votingOptions[0] = "Pizza"; votingOptions[1] = "Pasta"; votingOptions[2] = "Math";
    	loadProperties();
		inCon = new Scanner(System.in);
    	syncNamesObject = new Object();
    	syncBulletinsObject = new Object();
    	clientsList = new ArrayList<ClientHundler>();
    	CounterHundler.loadTablesAndMarkFromFileIfExists(namesAndBulletinTablesPath);
    	CounterHundler.step1_initKeys(CounterHundler.keysPath);
    	CounterHundler.initValidatorPubKey(CounterHundler.validatorKeysPath);
    	System.out.println("Mark of this vote: \"" + voteMark + "\".");
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

	private static void loadProperties()
	{
		try(FileInputStream fis = new FileInputStream("config.properties"))
		{
			Properties property = new Properties();
            property.load(fis);

			voteHEAD = property.getProperty("s.votehead", "");
            sitePath = property.getProperty("s.sitepath", "");
			int i = 1;
			while(property.getProperty("s.vote"+i, "").equals("") == false)
			{
				++i;
			}
			votingOptions = new String[i-1];
			for(int j = 1; j < i; ++j)
			{
				votingOptions[j-1] = property.getProperty("s.vote"+j, "");
			}
        }
		catch (IOException e)
		{
            System.err.println("Error. \"config.properties\" does not exists");
        }
	}

    private static void step1_initKeys(String filePathString)
    {
		File file = new File(filePathString);

		byte[] buffer = null;
		byte[][] buffBA;

		CounterHundler.logs("Check if public and private keys are already generated...");

		if(file.exists() && !file.isDirectory())
		{
			CounterHundler.logs("They are! Loading them...");
			try(FileInputStream fin = new FileInputStream(filePathString))
	        {
				buffer = new byte[fin.available()];
	            fin.read(buffer, 0, buffer.length);   
	            CounterHundler.logs("Loaded successfully, now assign them...");
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}
			buffBA = ByteWorker.Array2Arrays(buffer);
			pubKey = buffBA[0];
			privKey = buffBA[1];
			CounterHundler.logs("Keys were assigned. Initialization of keys done!");
		}
		else
		{
			CounterHundler.logs("Generating private and public keys...");
			RSA4096 rsa = new RSA4096();
			rsa.genKeys();
			pubKey = rsa.getPubKey();
			privKey = rsa.getPrivKey();

			CounterHundler.logs("Assigned them, now i'm gonna save them to file!");
			buffBA = new byte[2][];
			buffBA[0] = pubKey;
			buffBA[1] = privKey;

	        try(FileOutputStream fos = new FileOutputStream(filePathString))
	        {
	            buffer = ByteWorker.Arrays2Array(buffBA);
	            fos.write(buffer, 0, buffer.length);
	            CounterHundler.logs("I saved keys!");
	        }
	        catch(IOException e)
	        {
	            CounterHundler.logs("Something went wrong during saving keys to the file! Its path: " + filePathString);
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

		CounterHundler.logs("Check if validatorPubKey already exists...");
		if(file.exists() && !file.isDirectory())
		{
			CounterHundler.logs("It does! Gonna read key from the file");
			try(FileInputStream fin = new FileInputStream(filePathString))
	        {
				buffer = new byte[fin.available()];
	            fin.read(buffer, 0, buffer.length);   
	            CounterHundler.logs("Read successfully!");
			}
			catch(IOException e)
			{
				CounterHundler.logs("Couldn't read from this file: " + filePathString);
				e.printStackTrace();
			}
			validatorPubKey = buffer;
			CounterHundler.logs("Assigned validatorPubKey.");
		}
		else
		{
			CounterHundler.logs("It doesn't.");
			System.out.println("Input validatorPubKey:");
			validatorPubKey = ByteWorker.String2Bytes(inCon.nextLine());
	        try(FileOutputStream fos = new FileOutputStream(filePathString))
	        {
	            buffer = validatorPubKey;
	            fos.write(buffer, 0, buffer.length);
	            CounterHundler.logs("Successfully wrote validatorPubKey to the file!");
	        }
	        catch(IOException e)
	        {
	        	CounterHundler.logs("Couldn't read from this file: " + filePathString);
	            e.printStackTrace();
	        }
	     }
    }

    public synchronized static byte[] getPrivKey()
    {
    	CounterHundler.logs("Someone want my private key... Well... Why not? Sending it...");
    	return CounterHundler.privKey;
    }

    public synchronized static byte[] getPubKey()
    {
    	CounterHundler.logs("Someone want my public key... Sending it...");
    	return CounterHundler.pubKey;
    }

    public synchronized static byte[] getValidatorPubKey()
    {
    	CounterHundler.logs("Someone want validatorPubKey, sending it...");
    	return CounterHundler.validatorPubKey;
    }

    public static void addBulletinVote(ArrayList<String> bulletinItem)
    {
    	CounterHundler.logs("Adding bulletin to the list...");
    	synchronized(syncBulletinsObject)
    	{
    		boolean UNIQ;
    		UNIQ = true;
    		for(ArrayList<String> item : bulletins)
    			if(item.get(0).equals(bulletinItem.get(0)))
    			{
    				UNIQ = false;
    				break;
    			}
    		if(UNIQ)
    			bulletins.add(bulletinItem);
    	}
    	CounterHundler.logs("Saving names and bulletins...");
    	CounterHundler.saveTablesAndMark2File(namesAndBulletinTablesPath);
    	CounterHundler.logs("The bulletin added, names and bulletins saved!");
    }

    public static void editBulletinItem(ArrayList<String> what, String whatAppend)
    {
    	CounterHundler.logs("Some bulletin edited, refreshing data...");
    	synchronized(syncBulletinsObject)
    	{
    		what.add(whatAppend);
    	}
    	CounterHundler.saveTablesAndMark2File(namesAndBulletinTablesPath);
    	flushChangesOnSite();
    	CounterHundler.logs("Changes flushed on site, tables and mark saved!");
	}
	
	public static void editVoterChoice(ArrayList<String> what, String[] whatWrite)
	{
		CounterHundler.logs("Some voter edited his/her choice, refreshing data...");
    	synchronized(syncBulletinsObject)
    	{
			what.set(3, whatWrite[0]);
			what.set(4, whatWrite[1]);
    	}
    	CounterHundler.saveTablesAndMark2File(namesAndBulletinTablesPath);
    	flushChangesOnSite();
    	CounterHundler.logs("Changes flushed on site, tables and mark saved!");
	}

    public static ArrayList<String> getBulletinItem(int index)
    {
    	CounterHundler.logs("Sending bulletin by index...");
    	synchronized(syncBulletinsObject)
    	{
    		return bulletins.get(index);
    	}
    }

    public static ArrayList<String> getBulletinItem(String mark)
    {
    	CounterHundler.logs("Sending bulletin by mark...");
    	synchronized(syncBulletinsObject)
    	{
    		for(ArrayList<String> item : bulletins)
    			if(item.get(0).equals(mark))
    				return item;
    		return null;
    	}
    }

    public static String[][] getBulletinsTable()
    {
    	CounterHundler.logs("Sending bulletins table...");
    	synchronized(syncBulletinsObject)
    	{
	    	String[][] res = new String[bulletins.size()][];
	    	int i, j;
	    	i = 0;
	    	for(ArrayList<String> item : bulletins)
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

    public static void addNameItem(ArrayList<String> nameItem)
    {
    	CounterHundler.logs("Got new name, adding one...");
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
    	CounterHundler.saveTablesAndMark2File(namesAndBulletinTablesPath);
    	CounterHundler.logs("Changes saved!");
    }

    public static boolean checkNameItemEquals(String name_sigV_2Check)
    {
    	CounterHundler.logs("Check if signed name exists...");
    	boolean UNIC;
    	UNIC = true;
    	synchronized(syncNamesObject)
    	{
    		for(ArrayList<String> item : names)
    			if(item.size() == 4)
    				if(item.get(2).equals(name_sigV_2Check))
    				{
    					CounterHundler.logs("It exists.");
    					UNIC = false;
    					break;
    				}
    		CounterHundler.logs("It doesn't.");
    		return UNIC;
    	}
    }

    public static void editNameItem(ArrayList<String> what, String whatAppend)
    {
    	CounterHundler.logs("Some name was edited, refreshing data...");
    	synchronized(syncNamesObject)
    	{
    		what.add(whatAppend);
    	}
    	CounterHundler.saveTablesAndMark2File(namesAndBulletinTablesPath);
    	CounterHundler.logs("New data saved!");
    }

    public static ArrayList<String> getNameItem(int index)
    {
    	CounterHundler.logs("Sending name by index...");
    	synchronized(syncNamesObject)
    	{
    		return names.get(index);
    	}
    }

    public static String[][] getNamesTable()
    {
    	CounterHundler.logs("Sending names table...");
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
    	CounterHundler.logs("Sending vote info...");
    	String res = "";
    	res += "\n===============\n";
		res += voteHEAD + "\n";
    	res += "Vote " + voteMark + "::: " + "Options: \n";
    	for(int i = 0; i < votingOptions.length; ++i)
    		res += "\t" + (i+1) + ") " + votingOptions[i] + ". \n";
    	res += "===============\n";
    	return res;
    }

    public static String getVoteMark()
    {
    	CounterHundler.logs("Sending voteMark...");
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

    @SuppressWarnings( "deprecation" )
    private static void flushChangesOnSite()
    {
		try
		{
			if(!sitePath.equals(""))
			{
				int amoung = 0;
				Date d = new Date();
				StringBuilder sb = new StringBuilder();
				sb.append("---\n");
				sb.append("title: \"Текущие результаты голосования\"\n");
				//sb.append("date: 2021-" + (d.getMonth()+1>9?d.getMonth()+1:"0"+(d.getMonth()+1)) + "-" + (d.getDate()>9?d.getDate():"0"+d.getDate()) + "T22:06:10+03:00\n");
				sb.append("date: 2021-04-14T22:06:10+03:00\n");
				sb.append("draft: false\n");
				sb.append("katex: false\n");
				sb.append("---\n");
				sb.append("\n");

				int[] reses = new int[votingOptions.length];
				synchronized(syncBulletinsObject)
				{
					for(int li = 0; li < reses.length; ++li)
						reses[li] = 0;
					int chooseed;
					String libuffS;
					for(ArrayList<String> item : bulletins)
					{
						if(item.size() == 5)
						{
							libuffS = item.get(4);
							libuffS = libuffS.substring(libuffS.indexOf("\"")+1, libuffS.lastIndexOf("\""));
							chooseed = Integer.parseInt(libuffS);
							reses[chooseed-1]++;
							++amoung;
						}
					}
				}

				sb.append("Кол-во голосов: " + amoung + "\n\n");
				sb.append(voteHEAD + "\n\n");
				for(int li = 0; li < votingOptions.length; ++li)
				{
					sb.append(votingOptions[li] + ": " + reses[li] + "\n\n");
				}
				sb.append("\n");
				sb.append("<div style=\"margin-left:-5px; margin-right:-5px;overflow-x:auto;\">\n");
				sb.append("<div style=\"float: left;\n");
				sb.append("width: 50%;\n");
				sb.append("padding: 5px;\">\n");
				sb.append("<table>\n");
				sb.append("<thead>\n");
				sb.append("<th>Name</th>\n");
				sb.append("</thead>\n");
				synchronized(syncNamesObject)
				{
					List<ArrayList<String>> buffNames = new ArrayList<ArrayList<String>>(names);
					Collections.shuffle(buffNames);
					for(ArrayList<String> item : buffNames)
					{
						if(item.size() == 4)
						{
							sb.append("<tr>\n");
							sb.append("<td>");
							sb.append(item.get(3));
							sb.append("</td>\n");
							sb.append("</tr>\n");
						}
					}
					sb.append("</table>\n");
					sb.append("</div>\n");
				}
				sb.append("</table>\n");
				sb.append("<div style=\"float: left;\n");
				sb.append("width: 50%;\n");
				sb.append("padding: 5px;\">\n");
				sb.append("<table>\n");
				sb.append("<thead>\n");
				sb.append("<th>Mark</th>\n");
				sb.append("<th>Bulletin</th>\n");
				sb.append("</thead>\n");
				synchronized(syncBulletinsObject)
				{
					List<ArrayList<String>> buffBulletins = new ArrayList<ArrayList<String>>(bulletins);
					Collections.shuffle(buffBulletins);
					for(ArrayList<String> item : buffBulletins)
					{
						if(item.size() == 5)
						{
							sb.append("<tr>\n");
							sb.append("<td>");
							sb.append(item.get(0));
							sb.append("</td>\n");
							sb.append("<td>");
							sb.append(item.get(4));
							sb.append("</td>\n");
							sb.append("</tr>\n");
						}
					}
					sb.append("</table>\n");
					sb.append("</div>\n");
				}
				sb.append("</div>\n");
				byte[] buffer = sb.toString().getBytes();

				try(FileOutputStream fos = new FileOutputStream(sitePath))
				{
					fos.write(buffer, 0, buffer.length);
				}
				catch(IOException e)
				{
					e.printStackTrace();
				}

			}
		}
		catch(Exception e)
		{
			CounterHundler.logs("Problems with site flushing.");
		}
    }

    private static void saveTablesAndMark2File(String path2file)
    {
    	//saving vote mark to file path2file
    	CounterHundler.logs("It's time to save data... The first item to be appended to string is voteMark.");
		StringBuilder sb = new StringBuilder();
		sb.append(voteMark);
		sb.append('\n');
		CounterHundler.logs("voteMark appended, it's names' turn now!");
		synchronized(syncNamesObject)
		{
			//saving names table to file path2file
			sb.append("==names\n");
			for(int i = 0; i < names.size(); ++i)
			{
				for(int j = 0; j < names.get(i).size(); ++j)
				{
					sb.append(names.get(i).get(j));
					sb.append(";");
				}
				sb.append('\n');
			}
		}
		CounterHundler.logs("Names successfully appended. The last item - bulletins...");
		synchronized(syncBulletinsObject)
		{
			//saving bulletins table to file path2file
			sb.append("==bulletins\n");
			for(int i = 0; i < bulletins.size(); ++i)
			{
				for(int j = 0; j < bulletins.get(i).size(); ++j)
				{
					sb.append(bulletins.get(i).get(j));
					sb.append(";");
				}
				sb.append('\n');
			}
		}
		CounterHundler.logs("Everything is appended, writting to file now...");
		byte[] buffer = sb.toString().getBytes();
		try(FileOutputStream fos = new FileOutputStream(path2file))
		{
			fos.write(buffer, 0, buffer.length);
			CounterHundler.logs("Wrote to file. Save is done!");
		}
		catch(IOException e)
		{
			e.printStackTrace();
		}
    }

    private static void loadTablesAndMarkFromFileIfExists(String path2file)
    {
    	File file = new File(path2file);
    	CounterHundler.logs("Check if file to be loaded exists...");
    	if( !(file.exists() && !file.isDirectory()) )
    	{
    		//file не существует, тогда создать заново
    		CounterHundler.logs("No file, creating new lists for names and bulletins and generating voteMark.");
    		names = new ArrayList<ArrayList<String>>();
    		bulletins = new ArrayList<ArrayList<String>>();
    		voteMark = Tools.genRndString(7);
    		CounterHundler.logs("Generated this voteMark: " + new String(voteMark));
    	}
    	else
    	{
    		CounterHundler.logs("File exists. Create new lists for names and bulletins, read file then.");
    		//иначе загрузить из файла path2file
			names = new ArrayList<ArrayList<String>>();
    		bulletins = new ArrayList<ArrayList<String>>();
    		//load vote mark from file path2file
			byte[] buffer = null;
			try(FileInputStream fin = new FileInputStream(path2file))
	        {
				buffer = new byte[fin.available()];
	            fin.read(buffer, 0, buffer.length);   
	            CounterHundler.logs("Read file successfully.");
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}
			CounterHundler.logs("Getting voteMark from long string...");
			String sBuffer = new String(buffer);
			int index = sBuffer.indexOf('\n');
			String subBuffer = sBuffer.substring(0, index);
			sBuffer = sBuffer.substring(index+11, sBuffer.length());
			voteMark = subBuffer;
			CounterHundler.logs("Got voteMark. Gonna fill names now...");
			synchronized(syncNamesObject)
		    {
				//String[5] filler;
		    	//loading names table from file path2file
				//while(sBuffer[0] != '=' && sBuffer[2] != 'b')
				for(int i = 0; sBuffer.charAt(0) != '=' && sBuffer.charAt(2) != 'b'; ++i)
				{
					index = sBuffer.indexOf('\n');
					subBuffer = sBuffer.substring(0, index);
					sBuffer = sBuffer.substring(index+1, sBuffer.length());
					String[] filler = subBuffer.split(";");
					ArrayList<String> alBuff = new ArrayList<String>();
					for(String s : filler)
						alBuff.add(s);
					names.add(alBuff);
				}
		    }
		    CounterHundler.logs("Names list was filled! Now bulletins...");
			sBuffer = sBuffer.substring(12, sBuffer.length());
		    synchronized(syncBulletinsObject)
		    {
				//loading bulletins table from file path2file
				while(sBuffer.length() > 0)
				{
					index = sBuffer.indexOf('\n');
					subBuffer = sBuffer.substring(0, index);
					sBuffer = sBuffer.substring(index+1, sBuffer.length());
					String[] filler = subBuffer.split(";");
					ArrayList<String> alBuff = new ArrayList<String>();
					for(String s : filler)
						alBuff.add(s);
					bulletins.add(alBuff);
				}
		    }
		    CounterHundler.logs("Bulletins were loaded. Flush changes on site");
		    //запушить на сайт, после загрузки
		    flushChangesOnSite();
		    CounterHundler.logs("Loading data is done!");
    	}
    }

    public synchronized static ClientHundler getClientHundler(int index)
    {
    	return clientsList.get(index);
    }

    public synchronized static void removeClientHundler(ClientHundler which)
    {
    	clientsList.remove(which);
    }

    @SuppressWarnings( "deprecation" )
	private static void logs(String logStr)
	{
		Date d = new Date();
		String toOut = "[" + (d.getYear()+1900) + ".";
		toOut += (d.getMonth()+1>9?d.getMonth()+1:"0"+(d.getMonth()+1)) + ".";
		toOut += (d.getDate()>9?d.getDate():"0"+d.getDate()) + " ";
		toOut += (d.getHours()>9?d.getHours():"0"+d.getHours()) + ":";
		toOut += (d.getMinutes()>9?d.getMinutes():"0"+d.getMinutes()) + ":";
		toOut += (d.getSeconds()>9?d.getSeconds():"0"+d.getSeconds()) + "] " + logStr;
		System.out.println(toOut);
	}
}
