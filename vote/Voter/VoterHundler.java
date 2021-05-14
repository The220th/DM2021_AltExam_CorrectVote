package vote.Voter;

import java.lang.*;
import java.util.*;
import java.io.*;

import vote.Common.*;

import java.net.Socket;
import java.math.BigInteger;

import CipherLib.RSA4096;
import CipherLib.AES256;
import CipherLib.ByteWorker;
import CipherLib.Tools;

/*
1. Счётчик генерирует ключи: C_pubKey и C_privKey. Публичный ключ рассказывает всем.

2. Регистратор генерирует ключи: V_pubKey и V_privKey. Публичный ключ рассказывается всем.

3. Регистратор выкладывает списки потенциальных голосующих, тех кому можно голосовать.

4. Голосующие сообщают регистратору о желании голосовать. Приходят к регистратору и подтверждают личность.

5. Регистратор подписывает имя голосующего name: name_sigV = sign(name, V_privKey). Отдаёт голосующему name_sigV.

6. После этого регистратор выкладывает списки тех, кто голосует.

	Голосующий:

*7. Генерирует себе метку M.

8. Скрывает её с помощью числа r: M_bl = blind(M, r, C_pubKey).

9. Генерирует ключ key для симметричного шифрования.

10. Шифрует name_sigV и метку: {name_sigV, M_bl}_en = encrypt({name_sigV, M_bl}, key)

11. Шифрует сообщение для отправки: {name_sigV, M_bl}_en_enC = encrypt({name_sigV, M_bl}_en, C_pubKey).

12. Отсылает счётчику {name_sigV, M_bl}_en_enC.

	Счётчик:

*13. Получает сообщение и дешифрует: {name_sigV, M_bl}_en = decrypt({name_sigV, M_bl}_en_enC, C_privKey).

14. Публикует {name_sigV, M_bl}_en в специальном списке.

*14.a.	Голосующий видит опубликованное {name_sigV, M_bl}_en и:

15. Шифрует ключ для отправки: key_enC+номерстроки = encrypt(key, C_pubKey).

16. Высылает key_enC+номерстроки.

    Счётчик:

*17. Дешифрует: key+номерстроки = decrypt(key_enC+номерстроки, C_privKey).

18. Дешифрует сообщение голосующего в открытом списке: {name_sigV, M_bl} = decrypt({name_sigV, M_bl}_en, key).

19. Проверяет подпись регистратора: name = unsign(name_sigV, V_pubKey).

20. Подписывает M_bl_sigC = sign(M_bl, C_privKey).

21. Публикует рядом с {name_sigV, M_bl}_en ещё и {M_bl_sigC, name_sigV, name}.

    Голосующий:

*22. Видит опубликованное M_bl_sigC и снимает закрывающее число r: M_sigC = unblind(M_bl_sigC, r).

23. Делает выбор в бюллетене B.

24. Генерирует ещё один (другой) ключ для симметричного шифрования key2.

25. Шифрует бюллетень B_en2 = encrypt(B, key2).

26. Генерирует ещё один ключ для симметричного шифрования keyCheck и шифрует: M_enCheck = encrypt(M, keyCheck).

27. Шифрует для отправки: {M_sigC, M_enCheck, B_en2}_enC = encrypt({M_sigC, M_enCheck, B_en2}, C_pubKey).

28. Генерирует число k.

29. Ждёт k сек.

30. Отсылает счётчику {M_sigC, M_enCheck, B_en2}_enC.

    Счётчик:

31. Принимает сообщение и дешифрует: {M_sigC, M_enCheck, B_en2} = decrypt({M_sigC, M_enCheck, B_en2}_enC, C_privKey).

32. Проверяет свою подпись: M = unsign(M_sigC, C_privKey).

33. Публикует в специальном списке {M, M_enCheck, B_en2}.

    Голосующий:

34. Видит опубликованное {M, M_enCheck, B_en2} и понимает, что время действовать дальше.

35. Шифрует для отправки: {M, key2}_enC = encrypt({M, key2}, C_pubKey).

36. Отправляет {M, key2}_enC счётчику.

    Счётчик:

37. Принимает и дешифрует сообщение: {M, key2} = decrypt({M, key2}_enC, C_privKey).

38. Дешифрует бюллетень: B = decrypt(B_en2, key2).

39. Публикует рядом с {M, M_enCheck, B_en2} ещё и B.

40. Считает голоса и подводит итоги.
*/


class VoterHundler
{
    private static Socket clientSocket;
    private static ObjectInputStream objIn;
    private static ObjectOutputStream objOut;

    private static final String Counter_and_Validator_PathKeyString = "CounterAndValidatorPubKeys";
    private static byte[] counterPubKey;
    private static byte[] validatorPubKey;

    private static AES256 aesCipher;

    private static byte[] name_sigV;
    private static byte[] M_mark;
    private static byte[] r_hide;
    private static byte[] M_bl_mark;
    private static byte[] simKey4step9;
    private static byte[] name_sigV_and_M_bl_en;
    private static byte[] name_sigV_and_M_bl_en_enC;
    private static byte[] simKey4step9_enC;
    private static byte[] M_sign_mark;
    private static int name_i;

    private static Scanner inCon;

    static
    {
    	aesCipher = new AES256();
		inCon = new Scanner(System.in);
		VoterHundler.init_counters_and_validator_keys(VoterHundler.Counter_and_Validator_PathKeyString);
    }

	public static void main(String[] args)
	{
        try
        {
            clientSocket = new Socket("localhost", 5051);

            VoterHundler.logs("Socket was created");

            System.out.println(VoterHundler.giveInfoAboutVote());

            step5_init_name_sigV();
            
        }
        catch(Exception e)
        {
        	e.printStackTrace();
        }
        finally
        {
            VoterHundler.closeConnection();
        }
	}

	private static void step5_init_name_sigV()
	{
		VoterHundler.logs("Getting name_sigV. User input...");
		System.out.print("Enter your name, signed by the validator: \n> ");
		name_sigV = ByteWorker.String2Bytes(inCon.nextLine());
		VoterHundler.logs("Checking sign of validator...");
		byte[] unsigned = RSA4096.unsign(name_sigV, validatorPubKey);
		VoterHundler.logs("Validator signs: \"" + new String(unsigned) + "\".");
		step7_genM();
	}

	private static void step7_genM()
	{
		//7. gen M
		VoterHundler.logs("Begin generated mark M...");
		BigInteger M = Tools.rndBigInteger(new BigInteger("1000000"), new BigInteger("1000000000000000000000000"));
		M_mark = M.toByteArray();
		VoterHundler.logs("M = " + ByteWorker.Bytes2String(M_mark));
		step8_hide();
	}

	private static void step8_hide()
	{
		//8. M_bl = blind(M, r, C_pubKey)
		VoterHundler.logs("Generating closing multiplier...");
		r_hide = RSA4096.genClosingMultiplier(counterPubKey);
		VoterHundler.logs("Hidding M with closing multiplier...");
		M_bl_mark = RSA4096.blind(M_mark, r_hide, counterPubKey);
		VoterHundler.logs("Hided");
		step9_10_sim_encrypt();
	}

	private static void step9_10_sim_encrypt()
	{
		//9. gen key
		//10. {name_sigV, M_bl}_en = encrypt({name_sigV, M_bl}, key)
		VoterHundler.logs("Generating symmetric key...");
		aesCipher.genKey();
		simKey4step9 = aesCipher.getKey();
		VoterHundler.logs("Generated. Key = " + ByteWorker.Bytes2String(simKey4step9));
		VoterHundler.logs("Encrypting {name_sigV, M_bl}...");
		byte[][] buffBA = new byte[2][];
		buffBA[0] = name_sigV;
		buffBA[1] = M_bl_mark;
		byte[] toEncrypt = ByteWorker.Arrays2Array(buffBA);
		name_sigV_and_M_bl_en = aesCipher.encrypt(toEncrypt);
		VoterHundler.logs("Encrypted.");
		step11_12_en4send();
	}

	private static void step11_12_en4send()
	{
		//11. {name_sigV, M_bl}_en_enC = encrypt({name_sigV, M_bl}_en, C_pubKey)
		
		//byte[] prepare_2_die_edidion_sigV_and_M_bl_and_why_is_it_so_stypid_and_The_quick_brown_fox_jumps_over_the_lazy_dog_bee_movie_scrypt_I_do_not_want_to_programming_this_f4cking_sh1t_en_enC_enV;
		VoterHundler.logs("Encrypting for send to counter...");
		name_sigV_and_M_bl_en_enC = RSA4096.encrypt(name_sigV_and_M_bl_en, counterPubKey);
		VoterHundler.logs("Encrypted.");
		step12_send2Counter();
	}

	private static void step12_send2Counter()
	{
		//12. send to counter {name_sigV, M_bl}_en_enC
		VoterHundler.logs("Sending {name_sigV, M_bl}_en_enC...");
		Message msg = Message.makeMessage().setType(Message.ALGORITHM).setInt(13).setBytes(name_sigV_and_M_bl_en_enC);
		VoterHundler.send(msg);
		VoterHundler.logs("Sended.");
		step14a_requestListOfNames();
	}

	private static void step14a_requestListOfNames()
	{
		int i;
		//Голосующий видит опубликованное {name_sigV, M_bl}_en
		VoterHundler.logs("Receiving answer from server...");
		Message msg = VoterHundler.receive();
		VoterHundler.logs("Message received.");
		if(msg.getType() == Message.ALGORITHM_ERROR)
		{
			VoterHundler.logs("Error. Message from server: " + msg.getString());
			step_end();
		}
		else
		{
			String[][] sArrays = (String[][])ObjectConverter.bytes2obj(msg.getBytes());
			VoterHundler.logs("Trying to find our message is list of names...");
			boolean FINDED = false;
			String toFindString = ByteWorker.Bytes2String(name_sigV_and_M_bl_en);
			for(i = 0; i < sArrays.length; ++i)
				if(sArrays[i][0].equals(toFindString))
				{
					FINDED = true;
					break;
				}
			if(FINDED)
			{
				name_i = i;
				VoterHundler.logs("Finded in line " + name_i + ".");
				step15_16_enKey_and_send();
			}
			else
			{
				VoterHundler.logs("Cannot find. Trying again...");
				step12_send2Counter();
			}
		}
	}

	private static void step15_16_enKey_and_send()
	{
		//15. Шифрует ключ для отправки: key_enC+номерстроки = encrypt(key, C_pubKey)
		//16. Высылает key_enC
		VoterHundler.logs("Encrypting key " + ByteWorker.Bytes2String(simKey4step9) + " and number line " + name_i + "...");
		byte[][] buffBA = new byte[2][];
		buffBA[0] = simKey4step9;
		buffBA[1] = ByteWorker.Int2Bytes(name_i);
		byte[] simKey4step9_and_name_i = ByteWorker.Arrays2Array(buffBA);
		simKey4step9_enC = RSA4096.encrypt(simKey4step9_and_name_i, counterPubKey);
		VoterHundler.logs("Encrypted.");
		VoterHundler.logs("Sending key_enC+numberline to counter...");
		Message msg = Message.makeMessage().setType(Message.ALGORITHM).setInt(17).setBytes(simKey4step9_enC);
		VoterHundler.send(msg);
		VoterHundler.logs("Sended.");
		step22_check_and_unhide();
	}

	private static void step22_check_and_unhide()
	{
		//*22. Видит опубликованное M_bl_sigC и снимает закрывающее число r: M_sigC = unblind(M_bl_sigC, r).
		VoterHundler.logs("Receiving answer from server...");
		Message msg = VoterHundler.receive();
		VoterHundler.logs("Received...");
		if(msg.getType() == Message.ALGORITHM_ERROR)
		{
			VoterHundler.logs("Error. Message from server: " + msg.getString());
			step_end();
		}
		else
		{
			VoterHundler.logs("Trying to check {M_bl_sigC, name_sigV, name} in public list...");
			String[][] sArrays = (String[][])ObjectConverter.bytes2obj(msg.getBytes());
			VoterHundler.logs("Received table. Len is " + sArrays.length);
			String[] neededRow = sArrays[name_i];
			if(neededRow.length == 4)
			{
				String nameInList = neededRow[3];
				VoterHundler.logs("Finded name: \"" + nameInList + "\". ");
				byte[] signedMark_bl = ByteWorker.String2Bytes(neededRow[1]);
				M_sign_mark = RSA4096.unblind(M_mark, signedMark_bl, r_hide, counterPubKey);
				byte[] buffString = RSA4096.unsign(M_sign_mark, counterPubKey);
				VoterHundler.logs("Getting signed by counter mark: " + ByteWorker.Bytes2String(buffString));
				step_end(); //!!!!!CONTINUE!!!!!
			}
			else
			{
				VoterHundler.logs("Cannot find. Retrying...");
				step15_16_enKey_and_send();
			}
		}
	}

	private static void step_end()
	{
		VoterHundler.logs("Ending of working.");
	}

	private static String giveInfoAboutVote()
	{
		VoterHundler.logs("Sending request for information about the vote...");
		Message msg = Message.makeMessage().setType(Message.GET_VOTE_INFO);
		VoterHundler.send(msg);
		VoterHundler.logs("Sended.");
		VoterHundler.logs("Receiving info from server...");
		Message msgAns = VoterHundler.receive();
		if(msgAns.getType() == Message.VOTE_INFO)
		{
			VoterHundler.logs("Received");
			return msgAns.getString();
		}
		else
		{
			VoterHundler.logs("Error. Message from server: " + msgAns.getString());
			return null;
		}
	}

	private static void closeConnection()
	{
		try
		{
			//Thread.sleep(1000);//=(
			clientSocket.shutdownInput();
			VoterHundler.send(Message.makeMessage().setType(Message.OVER_AND_OUT));
			clientSocket.shutdownOutput();
			if(objIn != null)
				objIn.close();
			if(objOut != null)
				objOut.close();
			clientSocket.close();
	        System.out.println("Client was closed...");
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

	private static ObjectOutputStream out()
	{
		if(objOut == null)
		{
			try
			{
				objOut = new ObjectOutputStream(clientSocket.getOutputStream());
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}
		}
		return objOut;
	}

	private static ObjectInputStream in()
	{
		if(objIn == null)
		{
			try
			{
				objIn = new ObjectInputStream(clientSocket.getInputStream());
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}
		}
		return objIn;
	}

	public static void send(Message msg)
	{
		try
		{
	        out().writeObject(msg);
			out().flush();
		}
		catch(IOException e)
		{
			e.printStackTrace();
		}
	}

	public static Message receive()
	{
		Message res = null;
		try
		{
			res = (Message)in().readObject();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		return res;
	}

	@SuppressWarnings( "deprecation" )
	private static void logs(String logStr)
	{
		Date d = new Date();
		String toOut = "[" + (d.getYear()+1900) + ".";
		toOut += (d.getMonth()>9?d.getMonth():"0"+d.getMonth()) + ".";
		toOut += (d.getDate()>9?d.getDate():"0"+d.getDate()) + " ";
		toOut += (d.getHours()>9?d.getHours():"0"+d.getHours()) + ":";
		toOut += (d.getMinutes()>9?d.getMinutes():"0"+d.getMinutes()) + ":";
		toOut += (d.getSeconds()>9?d.getSeconds():"0"+d.getSeconds()) + "] " + logStr;
		System.out.println(toOut);
	}

	private static void init_counters_and_validator_keys(String filePathString)
    {
		File file = new File(filePathString);

		byte[] buffer = null;
		byte[][] buffBA;

		if(file.exists() && !file.isDirectory())
		{
			VoterHundler.logs("Counter and validator keys are found in file \"" + filePathString + "\". Loading...");
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
			counterPubKey = buffBA[0];
			validatorPubKey = buffBA[1];
			VoterHundler.logs("Counter and validator keys are initialized.");
		}
		else
		{
			VoterHundler.logs("File \"" + filePathString + "\" is not found. Counter and validator keys are not found. User input.");
			System.out.println("Input counterPubKey:");
			counterPubKey = ByteWorker.String2Bytes(inCon.nextLine());
			System.out.println("Input validatorPubKey:");
			validatorPubKey = ByteWorker.String2Bytes(inCon.nextLine());
			VoterHundler.logs("Counter and validator keys are initialized. Saving keys in file \"" + filePathString + "\".");

			buffBA = new byte[2][];
			buffBA[0] = counterPubKey;
			buffBA[1] = validatorPubKey;

	        try(FileOutputStream fos = new FileOutputStream(filePathString))
	        {
	            buffer = ByteWorker.Arrays2Array(buffBA);
	            fos.write(buffer, 0, buffer.length);
	        }
	        catch(IOException e)
	        {
	            e.printStackTrace();
	        }
	        VoterHundler.logs("Saved!");
	     }
	     //System.out.println("=====\nPubKey = " + ByteWorker.Bytes2String(counterPubKey) + "\n=====");
    }
}