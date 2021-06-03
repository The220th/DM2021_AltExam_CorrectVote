package vote.Validator;

import java.lang.*;
import java.util.*;
import java.io.*;
import java.io.File;

import CipherLib.RSA4096;
import CipherLib.ByteWorker;

public class ValidatorHundler
{
    private static final String keysPath = "validatorKeys";
    private static byte[] pubKey;
    private static byte[] privKey;
    private static Scanner in;

    static
    {
    	in = new Scanner(System.in);
    	ValidatorHundler.initKeys(ValidatorHundler.keysPath);
    }

    public static void main(String[] args) throws IOException
    {
    	System.out.print("Input vote mark: \n> ");
    	String votemark = in.nextLine();

        System.out.print("Input name for sign: \n> ");
        String inputed = in.nextLine();

        inputed = votemark + ":::" + inputed;

        System.out.println("==========\nThe message: \"" + inputed + "\" - will be signed.\n==========\n");

        ValidatorHundler.logs("Signing votemark with name...");
        byte[] signed = RSA4096.sign(inputed.getBytes(), privKey);

        System.out.println("Signed message: ");
        System.out.println(ByteWorker.Bytes2String(signed));
    }

    private static void initKeys(String filePathString)
    {
		File file = new File(filePathString);

		byte[] buffer = null;
		byte[][] buffBA;
		ValidatorHundler.logs("Check if file with keys exists...");

		if(file.exists() && !file.isDirectory())
		{
			ValidatorHundler.logs("It exists, reading data...");
			try(FileInputStream fin = new FileInputStream(filePathString))
	        {
				buffer = new byte[fin.available()];
	            fin.read(buffer, 0, buffer.length);   
	            ValidatorHundler.logs("Read file successfully. Setting pubKey and privKey...");
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}
			buffBA = ByteWorker.Array2Arrays(buffer);
			pubKey = buffBA[0];
			ValidatorHundler.logs("pubKey was set...");
			privKey = buffBA[1];
			ValidatorHundler.logs("privKey was set as well.");
		}
		else
		{
			ValidatorHundler.logs("It doesn't. Generating private and public keys...");
			RSA4096 rsa = new RSA4096();
			rsa.genKeys();
			ValidatorHundler.logs("Getting pubKey...");
			pubKey = rsa.getPubKey();
			ValidatorHundler.logs("Getting privKey...");
			privKey = rsa.getPrivKey();

			ValidatorHundler.logs("Assigned keys, need to write them to file.");
			buffBA = new byte[2][];
			buffBA[0] = pubKey;
			buffBA[1] = privKey;

	        try(FileOutputStream fos = new FileOutputStream(filePathString))
	        {
	            buffer = ByteWorker.Arrays2Array(buffBA);
	            fos.write(buffer, 0, buffer.length);
	            ValidatorHundler.logs("Wrote them to file. Well done, Validator!");
	        }
	        catch(IOException e)
	        {
	        	ValidatorHundler.logs("Something's wrong with writting to the file with this path: " + filePathString);
	            e.printStackTrace();
	        }
		}
	    System.out.println("=====\nPubKey = " + ByteWorker.Bytes2String(pubKey) + "\n=====");
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