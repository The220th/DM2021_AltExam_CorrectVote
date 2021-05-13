package vote.Common;

import java.lang.*;
import java.util.*;
import java.io.*;


public class ObjectConverter
{
	/**
	* All in obj must be serializable
	*/
	public static byte[] obj2bytes(Serializable obj)
	{
		byte[] res = null;
		
		try(ByteArrayOutputStream bos = new ByteArrayOutputStream(); ObjectOutputStream oos = new ObjectOutputStream(bos))
        {
            oos.writeObject(obj);
            oos.flush();
            res = bos.toByteArray();
        }
        catch(Exception ex)
        {
            System.out.println(ex.getMessage());
        } 
        return res;
	}

	public static Object bytes2obj(byte[] objBytes)
	{
		Object res = null;
		
		try(ByteArrayInputStream bis = new ByteArrayInputStream(objBytes); ObjectInputStream ois = new ObjectInputStream(bis))
		{
			res = ois.readObject();
		}
		catch(Exception ex)
		{
			System.out.println(ex.getMessage());
		}
		return res;
	}

	/**
	* All in obj must be serializable
	*/
	public static String obj2str(Serializable obj)
	{
		return Base64.getEncoder().encodeToString(obj2bytes(obj));
	}

	public static Object str2obj(String objStr)
	{
		return bytes2obj(Base64.getDecoder().decode(objStr));
	}

	public static byte[] getHash(Serializable obj)
	{
		java.security.MessageDigest md = null;
        byte[] res = null;
        try
        {
            md = java.security.MessageDigest.getInstance("SHA-256");
            res = md.digest(obj2bytes(obj));
        }
        catch(Exception e)
        {
            System.out.println("WOK in ObjectConverter.getHash()\n ");
            e.printStackTrace();
        }
        return res;
	}

	public static String getStrHash(Serializable obj)
	{
		return Base64.getEncoder().encodeToString(getHash(obj));
	}
}