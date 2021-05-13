package vote.Validator;

import java.lang.*;
import java.util.*;
import java.io.*;
import java.io.File;

import CipherLib.RSA4096;
import CipherLib.ByteWorker;

class ValidatorHundler
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
        System.out.print("Input msg for sign: \n> ");
        String inputed = in.nextLine();

        System.out.println("==========\nThe message: \"" + inputed + "\" - will be signed.\n==========\n");

        byte[] signed = RSA4096.sign(inputed.getBytes(), privKey);

        System.out.println("Signed message: ");
        System.out.println(ByteWorker.Bytes2String(signed));
    }

    private static void initKeys(String filePathString)
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
}